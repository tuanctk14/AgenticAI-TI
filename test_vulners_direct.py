#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test Vulners API directly"""
import requests

api_key = "H727HV96YPZ6XKQUE2XSMGRNA3SZGFTJYTD72WR6CYKS0S8SA0AX4JCFQ92UBAJJ"
cve_id = "CVE-2021-44228"

print("Testing Vulners API directly...")
print(f"CVE: {cve_id}")
print(f"API Key: {api_key[:20]}...")
print()

# Test 1: With apiKey as query param
print("Test 1: apiKey as query parameter")
try:
    url = "https://vulners.com/api/v3/search/id/"
    params = {
        "id": cve_id,
        "apiKey": api_key
    }
    resp = requests.get(url, params=params, timeout=10)
    print(f"  Status: {resp.status_code}")
    print(f"  Response: {resp.text[:200]}")
except Exception as e:
    print(f"  Error: {e}")

print()

# Test 2: With apiKey as header
print("Test 2: apiKey as HTTP header")
try:
    url = "https://vulners.com/api/v3/search/id/"
    params = {"id": cve_id}
    headers = {"X-API-Key": api_key}
    resp = requests.get(url, params=params, headers=headers, timeout=10)
    print(f"  Status: {resp.status_code}")
    print(f"  Response: {resp.text[:200]}")
except Exception as e:
    print(f"  Error: {e}")

print()

# Test 3: Check if API key itself works
print("Test 3: Test API key validity")
try:
    url = "https://vulners.com/api/v3/user/profile/"
    params = {"apiKey": api_key}
    resp = requests.get(url, params=params, timeout=10)
    print(f"  Status: {resp.status_code}")
    print(f"  Response: {resp.text[:300]}")
except Exception as e:
    print(f"  Error: {e}")
