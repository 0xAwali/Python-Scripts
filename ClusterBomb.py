import concurrent.futures
import sys
import datetime
import traceback
import argparse
from random import randint
from threading import Lock, Semaphore
import requests
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

lock = Lock()
semaphore = None
waf_ips = []
current_ip_index = 0
ip_lock = Lock()

def error(message, **kwargs):
    print('[{}] {}'.format(datetime.datetime.now().time(), message), file=sys.stderr)
    for n, a in kwargs.items():
        print('\t{}={}'.format(n, a), file=sys.stderr)

    exc_type, exc_value, exc_traceback = sys.exc_info()
    print('Exception type:' + str(exc_type), file=sys.stderr)
    print('Exception value:' + str(exc_value), file=sys.stderr)
    print('TRACE:', file=sys.stderr)
    traceback.print_tb(exc_traceback, file=sys.stderr)
    print('\n\n\n', file=sys.stderr)

def normalize_url(base_url, path):
    return urljoin(base_url, path)

def get_next_waf_ip():
    """Get the next IP from the WAF bypass list (round-robin)"""
    global current_ip_index
    if not waf_ips:
        return None
    
    with ip_lock:
        ip = waf_ips[current_ip_index]
        current_ip_index = (current_ip_index + 1) % len(waf_ips)
        return ip

def http_request(url, method='GET', data=None, additional_headers=None, proxy=None, use_waf_bypass=False, path_ip=None):
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/{} Firefox/102.0'.format(randint(1000000,9999999)),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'Te': 'trailers'
    }

    # Add WAF bypass headers if enabled
    if use_waf_bypass and path_ip:
        headers['X-Forwarded-For'] = path_ip
        headers['X-Forwarded-Host'] = path_ip

    if additional_headers:
        headers.update(additional_headers)

    if not proxy:
        proxy = {}

    try:
        resp = requests.request(method, url, data=data, headers=headers, proxies=proxy, 
                              verify=False, timeout=15, allow_redirects=False)
        return resp, path_ip
    except Exception as e:
        return None, path_ip

def check_url(base_url, path, proxy=None, use_waf_bypass=False, path_ip=None):
    url = normalize_url(base_url, path)
    resp, used_ip = http_request(url, proxy=proxy, use_waf_bypass=use_waf_bypass, path_ip=path_ip)
    
    if resp is None:
        return (url, "ERROR", 0, 0, used_ip)
    
    body_size = len(resp.content)
    header_size = len(str(resp.headers))
    
    return (url, resp.status_code, body_size, header_size, used_ip)

def handle_finding(future):
    global semaphore, lock

    semaphore.release()

    if future.done() and not future.exception():
        result = future.result()
        with lock:
            url, status, body_size, header_size, used_ip = result
            if used_ip:
                print(f"{url}\t{status}\t{body_size}\t{header_size}\t{used_ip}")
            else:
                print(f"{url}\t{status}\t{body_size}\t{header_size}")

def parse_args():
    parser = argparse.ArgumentParser(description='Cluster bomb directory brute force tool')
    parser.add_argument('--url-file', required=True, help='File containing base URLs (one per line)')
    parser.add_argument('--wordlist', required=True, help='File with directory paths to test')
    parser.add_argument('--proxy', help='http and https proxy')
    parser.add_argument('--workers', type=int, default=50, help='number of parallel workers')
    parser.add_argument('--waf-bypassed', action='store_true', help='Enable WAF bypass using X-Forwarded-For and X-Forwarded-Host headers')
    parser.add_argument('--ips', help='File containing IP addresses for WAF bypass (one per line) - required if --waf-bypassed is used')
    return parser.parse_args()

def load_urls(url_file):
    with open(url_file, 'r') as f:
        return [url.strip() for url in f if url.strip()]

def load_waf_ips(ips_file):
    ips = []
    try:
        with open(ips_file, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith('#'):
                    ips.append(ip)
        return ips
    except FileNotFoundError:
        print(f"Error: IP file '{ips_file}' not found", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error loading IP file: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    global semaphore, waf_ips
    args = parse_args()

    # Validate arguments
    if args.waf_bypassed and not args.ips:
        print("Error: --ips file is required when using --waf-bypassed", file=sys.stderr)
        sys.exit(1)
    
    if args.ips and not args.waf_bypassed:
        print("Warning: --ips provided without --waf-bypassed. WAF bypass will not be enabled.", file=sys.stderr)
    
    # Load WAF bypass IPs if enabled
    if args.waf_bypassed and args.ips:
        waf_ips = load_waf_ips(args.ips)
        if not waf_ips:
            print("Error: No valid IPs loaded. WAF bypass cannot be enabled.", file=sys.stderr)
            sys.exit(1)

    if args.proxy:
        p = args.proxy
        proxy = {'http': p, 'https': p}
    else:
        proxy = {}
        
    semaphore = Semaphore(args.workers)
    urls = load_urls(args.url_file)
    
    # Load all paths
    with open(args.wordlist, 'r') as f:
        paths = [line.strip() for line in f if line.strip()]

    with concurrent.futures.ThreadPoolExecutor(args.workers) as tpe:
        # Iterate through each path
        for path in paths:
            # Get a new IP for this path (if WAF bypass is enabled)
            path_ip = None
            if args.waf_bypassed and waf_ips:
                path_ip = get_next_waf_ip()
            
            # For this path, iterate through all URLs using the SAME IP
            for base_url in urls:
                # Ensure base URL ends with /
                if not base_url.endswith('/'):
                    base_url += '/'

                semaphore.acquire()
                try:
                    future = tpe.submit(check_url, base_url, path, proxy, args.waf_bypassed, path_ip)
                    future.add_done_callback(handle_finding)
                except Exception as e:
                    semaphore.release()
                    if False:  # Debug disabled
                        error("Error submitting task", base_url=base_url, path=path, error=str(e))

        tpe.shutdown(wait=True)

if __name__ == '__main__':
    main()
