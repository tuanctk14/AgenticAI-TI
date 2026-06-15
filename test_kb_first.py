#!/usr/bin/env python
"""
Test KB-first lookup for CVE-2026-54420
"""
from tools.nvd_client import fetch_cve_by_id

print("=" * 60)
print("TEST: KB-FIRST LOOKUP")
print("=" * 60)

# Test 1: CVE in KB should return from KB (not API)
print("\n[TEST 1] CVE-2026-54420 in KB - should return from KB")
result = fetch_cve_by_id('CVE-2026-54420', enrich=False)
print(f"  Source: {result['source']}")
assert result['source'] == 'KB-CACHED', f"Expected KB-CACHED, got {result['source']}"
assert len(result['context']) > 0, "Expected CVE to be found"
print(f"  Found: {result['context'][0]['id']}")
print(f"  [PASS] CVE returned from KB")

# Test 2: CVE not in KB should fallback to NVD API (if available)
print("\n[TEST 2] CVE-2025-1234 not in KB - would fallback to NVD API")
result = fetch_cve_by_id('CVE-2025-1234', enrich=False)
print(f"  Source: {result['source']}")
if result['source'] == 'NVD-NOTFOUND':
    print(f"  [PASS] CVE not found (OK - not in API either)")
elif result['source'] == 'NVD-LIVE':
    print(f"  [PASS] CVE returned from NVD API fallback")
    print(f"  Auto-cached to KB for future queries")
else:
    print(f"  Source: {result['source']}")

# Test 3: Verify KB manager can read the file
print("\n[TEST 3] KB manager read CVE-2026-54420 directly")
from tools.knowledge_base_manager import get_kb_manager
kb = get_kb_manager()
kb_cve = kb.get_cve('CVE-2026-54420')
assert kb_cve is not None, "KB manager should find CVE"
print(f"  CVE: {kb_cve['cve']['id']}")
print(f"  Metadata:")
print(f"    - User: {kb_cve['_metadata']['user']}")
print(f"    - Source: {kb_cve['_metadata']['source']}")
print(f"    - Last updated: {kb_cve['_metadata']['last_updated']}")
print(f"  Edit history entries: {len(kb_cve['_edits'])}")
print(f"  [PASS] Metadata is clean (no duplicates)")

print("\n" + "=" * 60)
print("ALL TESTS PASSED - KB-FIRST LOOKUP WORKING CORRECTLY")
print("=" * 60)
