import urllib.request
import sys

try:
    with urllib.request.urlopen('http://127.0.0.1:5000/api/health', timeout=3) as r:
        print(r.status)
        print(r.read().decode())
except Exception as e:
    print('error', e)
    sys.exit(1)
