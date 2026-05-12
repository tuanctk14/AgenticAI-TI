#!/usr/bin/env python3
"""Check raw NVD response"""
import requests
import json

url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
params = {'cveId': 'CVE-2021-44228'}

resp = requests.get(url, params=params, timeout=10)
data = resp.json()

if data.get('vulnerabilities'):
    item = data['vulnerabilities'][0]
    cve = item['cve']

    print("=" * 80)
    print("CVE-2021-44228 Full Structure")
    print("=" * 80)

    print(f"\nCVE keys: {list(cve.keys())}")

    if 'weaknesses' in cve:
        print(f"\nWeaknesses: {len(cve['weaknesses'])} items")
        if cve['weaknesses']:
            print(json.dumps(cve['weaknesses'][0], indent=2))
    else:
        print("\nNo weaknesses key")
