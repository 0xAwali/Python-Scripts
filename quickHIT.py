import itertools
import concurrent.futures
import sys
import json
import datetime
import traceback
import argparse
from random import randint
from threading import Lock, Semaphore
import requests

requests.packages.urllib3.disable_warnings()

registered = []
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

def register(f):
    registered.append(f)
    return f

def normalize_url(base_url, path):
    if base_url[-1] == '/' and (path[0] == '/' or path[0] == '\\'):
        url = base_url[:-1] + path
    else:
        url = base_url + path
    return url

def http_request(url, method='GET', data=None, additional_headers=None, proxy=None):
    headers = {'User-Agent':'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/{} Firefox/102.0'.format(randint(1000000,9999999)),
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

    resp = requests.request(method, url, data=data, headers=headers, proxies=proxy, verify=False, timeout=15, allow_redirects=False)
    return resp

def preflight(url, proxy=None):
    try:
        http_request(url, proxy=proxy)
    except:
        return False
    else:
        return True

def content_type(ct):
    return ct.split(';')[0].lower().strip()

@register
def gitFile(base_url, debug, proxy=None):
    GIT = '/.git/config'
    url = normalize_url(base_url, GIT)

    try:
        resp = http_request(url, proxy=proxy)
        body_lower = resp.text.lower()
        if (resp.status_code == 200 and 
            '[credentials]' in body_lower and 
            '[core]' in body_lower and
            not ('<html' in body_lower and '<body' in body_lower)):
            return {'url': url, 'function': 'gitFile'}
            
    except Exception as e:
        if debug:
            error(f'Exception: {str(e)}', method='GIT', url=url)
    
    return None

def check_url(base_url, debug, proxy=None):
    if not preflight(base_url, proxy):
        return None

    for method in registered:
        result = method(base_url, debug, proxy)
        if result:
            return {'base_url': base_url, 'match': result}
    return None

def handle_finding(future):
    global semaphore, lock

    semaphore.release()

    if future.done():
        if not future.exception():
            result = future.result()

            with lock:
                if result:
                    print(json.dumps(result))

def parse_args():
    parser = argparse.ArgumentParser(description='It\'s just quickHIT tool to match specific responses')

    parser.add_argument('--file', help='file with urls')
    parser.add_argument('--proxy', help='http and https proxy')
    parser.add_argument('--debug', action='store_true', help='debug output')
    parser.add_argument('--workers', type=int, default=50, help='number of parallel workers')

    return parser.parse_args(sys.argv[1:])

def main():
    global semaphore

    args = parse_args()

    if args.proxy:
        p = args.proxy
        proxy = {'http': p, 'https': p}
    else:
        proxy = {}

    if not args.file:
        print('You must specify the --file parameter, bye.')
        sys.exit(1337)

    semaphore = Semaphore(args.workers)

    with concurrent.futures.ThreadPoolExecutor(args.workers) as tpe, open(args.file, 'r') as input:
        while True:
            line = input.readline()
            if not line:
                break

            url = line.strip()

            semaphore.acquire()
            try:
                future = tpe.submit(check_url, url, args.debug, proxy)
                future.add_done_callback(handle_finding)
            except:
                semaphore.release()

        tpe.shutdown(wait=True)

if __name__ == '__main__':
    main()
