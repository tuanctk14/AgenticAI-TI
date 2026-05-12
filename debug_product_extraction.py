"""Debug product extraction for WordPress MStore API"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from tools.cve_parser import parse_cve_metadata
from tools.product_extractor import extract_product_metadata

cve = {
    "id": "CVE-2021-47933",
    "description": "WordPress MStore API plugin before 2.0.7 allows arbitrary file upload. The mstore-api plugin is vulnerable to unauthenticated file upload attacks.",
    "cwe_ids": ["306", "434"],
    "configurations": []
}

print("=" * 70)
print("DEBUGGING: CVE-2021-47933 Product Extraction")
print("=" * 70)

# Test product extraction
extracted = extract_product_metadata(cve)
print("\n[EXTRACTED]")
for key, value in extracted.items():
    print(f"  {key}: {value}")

# Test parse_cve_metadata
print("\n[CVE METADATA]")
metadata = parse_cve_metadata(cve)
for key, value in metadata.items():
    print(f"  {key}: {value}")
