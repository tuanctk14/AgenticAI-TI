#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test NVD API behavior with date filtering.

According to NVD API docs:
- pubStartDate and pubEndDate filter by "last modified" date
- NOT by "published" date
- CVE-2021-47973 might have been recently updated (modified), so it appears in recent date ranges
"""

import requests
from datetime import datetime

# Test 1: Check CVE-2021-47973 directly
print("=" * 60)
print("TEST 1: Fetch CVE-2021-47973 directly")
print("=" * 60)
resp = requests.get(
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
    params={"cveId": "CVE-2021-47973"},
    timeout=15
)
data = resp.json()
if data.get("vulnerabilities"):
    cve = data["vulnerabilities"][0]["cve"]
    print(f"CVE ID: {cve['id']}")
    print(f"Published: {cve.get('published')}")
    print(f"Last Modified: {cve.get('lastModified')}")
else:
    print("CVE not found")

# Test 2: Query for CVEs with May 15-16, 2026 date range
print("\n" + "=" * 60)
print("TEST 2: Query for CVEs in May 15-16, 2026 range")
print("=" * 60)
resp = requests.get(
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
    params={
        "pubStartDate": "2026-05-15T00:00:00.000",
        "pubEndDate": "2026-05-16T23:59:59.000",
        "resultsPerPage": 100,
    },
    timeout=30
)
data = resp.json()
total = data.get("totalResults", 0)
print(f"Total results: {total}")
print(f"CVEs in response: {len(data.get('vulnerabilities', []))}")

if data.get("vulnerabilities"):
    print("\nFirst 5 CVEs:")
    for item in data["vulnerabilities"][:5]:
        cve = item["cve"]
        print(f"  {cve['id']}")
        print(f"    Published: {cve.get('published')}")
        print(f"    Last Modified: {cve.get('lastModified')}")
