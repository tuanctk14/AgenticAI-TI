#!/usr/bin/env python3
"""Test pattern fix for false positives"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from tools.cve_parser import DescriptionParser

print("=" * 80)
print("PATTERN MATCHING TEST - FALSE POSITIVE FIX")
print("=" * 80)

# Test descriptions
tests = [
    ("Apache Log4j2 versions less than 2.15.0 are vulnerable to RCE", "apache:log4j", True),
    ("Apache HTTP Server path traversal vulnerability", "apache:http_server", True),
    ("Apache Log4j2 2.14.1 RCE", "apache:log4j", True),
    ("Apache Tomcat server vulnerability", "apache:tomcat", True),
    ("Apache ActiveMQ broker RCE", "apache:activemq", True),
]

print("\nTesting DescriptionParser.extract_product_info():")
print("-" * 80)

for description, expected_id, should_match in tests:
    result = DescriptionParser.extract_product_info(description)
    detected_id = result.get("normalized_id")
    status = "[PASS]" if detected_id == expected_id else "[FAIL]"
    print(f"\n{status} Description: {description[:60]}...")
    print(f"   Expected: {expected_id}")
    print(f"   Detected: {detected_id}")

# Test false positive scenario
print("\n" + "=" * 80)
print("FALSE POSITIVE TEST: CVE-2021-44228 (Log4j) should NOT match Apache HTTP")
print("=" * 80)

fp_test = "Apache Log4j2 versions less than 2.15.0 are vulnerable to remote code execution"
result = DescriptionParser.extract_product_info(fp_test)

print(f"\nDescription: {fp_test}")
print(f"Detected product: {result.get('normalized_id')}")
print(f"Expected: apache:log4j (NOT apache:http_server)")

if result.get('normalized_id') == 'apache:log4j':
    print(f"Status: [PASS] - Correctly identified as log4j, not HTTP server")
else:
    print(f"Status: [FAIL] - Incorrectly identified")

# Verify Apache HTTP still matches
print("\n" + "-" * 80)
http_test = "Apache HTTP Server path traversal vulnerability"
result_http = DescriptionParser.extract_product_info(http_test)

print(f"\nDescription: {http_test}")
print(f"Detected product: {result_http.get('normalized_id')}")
print(f"Expected: apache:http_server")

if result_http.get('normalized_id') == 'apache:http_server':
    print(f"Status: [PASS] - Correctly identified as HTTP server")
else:
    print(f"Status: [FAIL] - Not identified")

print("\n" + "=" * 80)
