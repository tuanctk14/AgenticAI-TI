#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test CVE date range filtering"""
from tools.nvd_client import fetch_nvd_cves

# Test with specific date range (May 15-16, 2026)
result = fetch_nvd_cves(start_date='2026-05-15T00:00:00.000', end_date='2026-05-16T23:59:59.000')
print(f'Total CVEs returned: {result["total"]}')
print(f'CVEs in result: {len(result["context"])}')

if result['context']:
    print('All CVEs:')
    for cve in result['context']:
        print(f"  {cve['id']} - Published: {cve['published']}")
else:
    print("No CVEs returned for the date range!")
