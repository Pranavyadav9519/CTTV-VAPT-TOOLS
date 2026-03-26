#!/usr/bin/env python
import requests
import json

print('Testing API Endpoints:')
print('=' * 50)

# Test health
r = requests.get('http://127.0.0.1:5000/api/health')
print(f'Health: {r.status_code}')

# Test reports
r = requests.get('http://127.0.0.1:5000/api/reports')
print(f'Reports: {r.status_code}')
data = r.json()
print(f'Total reports: {data.get("total", 0)}')

# Test analytics
r = requests.get('http://127.0.0.1:5000/api/analytics/summary')
print(f'\nAnalytics: {r.status_code}')
print('Data:', json.dumps(r.json()['data'], indent=2))

# Test scans
r = requests.get('http://127.0.0.1:5000/api/scans')
print(f'\nScans: {r.status_code} - {len(r.json().get("data", []))} scans')
