import time
import requests
import sys

url = "http://127.0.0.1:5000/api/health"
for i in range(10):
    try:
        r = requests.get(url, timeout=2)
        print(r.json())
        sys.exit(0)
    except Exception as e:
        print(f"Attempt {i+1}/10 failed: {e}")
        time.sleep(1)
print("Health check failed after retries")
sys.exit(1)
