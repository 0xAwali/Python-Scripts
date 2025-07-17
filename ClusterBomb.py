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

def error(message, **kwargs):
    print('[{}] {}'.format(datetime.datetime.now().time(), message), sys.stderr)
    for n, a in kwargs.items():
        print('\t{}={}'.format(n, a), sys.stderr)

    exc_type, exc_value, exc_traceback = sys.exc_info()
    print('Exception type:' + str(exc_type), sys.stderr)
    print('Exception value:' + str(exc_value), sys.stderr)
    print('TRACE:', sys.stderr)
    traceback.print_tb(exc_traceback, file=sys.stderr)
    print('\n\n\n', sys.stderr)

def normalize_url(base_url, path):
    return urljoin(base_url, path)

def http_request(url, method='GET', data=None, additional_headers=None, proxy=None):
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

    if additional_headers:
        headers.update(additional_headers)

    if not proxy:
        proxy = {}

    try:
        resp = requests.request(method, url, data=data, headers=headers, proxies=proxy, 
                              verify=False, timeout=15, allow_redirects=False)
        return resp
    except Exception as e:
        return None

def check_url(base_url, path, proxy=None):
    url = normalize_url(base_url, path)
    resp = http_request(url, proxy=proxy)
    
    if resp is None:
        return (url, "ERROR", 0, 0)
    
    body_size = len(resp.content)
    header_size = len(str(resp.headers))
    
    return (url, resp.status_code, body_size, header_size)

def handle_finding(future):
    global semaphore, lock

    semaphore.release()

    if future.done() and not future.exception():
        result = future.result()
        with lock:
            url, status, body_size, header_size = result
            print(f"{url}\t{status}\t{body_size}\t{header_size}")

def parse_args():
    parser = argparse.ArgumentParser(description='Cluster bomb directory brute force tool')
    parser.add_argument('--url-file', required=True, help='File containing base URLs (one per line)')
    parser.add_argument('--wordlist', required=True, help='File with directory paths to test')
    parser.add_argument('--proxy', help='http and https proxy')
    parser.add_argument('--debug', action='store_true', help='debug output')
    parser.add_argument('--workers', type=int, default=50, help='number of parallel workers')
    return parser.parse_args(sys.argv[1:])

def load_urls(url_file):
    with open(url_file, 'r') as f:
        return [url.strip() for url in f if url.strip()]

def main():
    global semaphore
    args = parse_args()

    if args.proxy:
        p = args.proxy
        proxy = {'http': p, 'https': p}
    else:
        proxy = {}
        
    semaphore = Semaphore(args.workers)
    urls = load_urls(args.url_file)

    with concurrent.futures.ThreadPoolExecutor(args.workers) as tpe, open(args.wordlist, 'r') as wordlist:
        for path in wordlist:
            path = path.strip()
            if not path:
                continue

            for base_url in urls:
                # Ensure base URL ends with /
                if not base_url.endswith('/'):
                    base_url += '/'

                semaphore.acquire()
                try:
                    future = tpe.submit(check_url, base_url, path, proxy)
                    future.add_done_callback(handle_finding)
                except Exception as e:
                    semaphore.release()
                    if args.debug:
                        error("Error submitting task", base_url=base_url, path=path, error=str(e))

        tpe.shutdown(wait=True)

if __name__ == '__main__':
    main()
