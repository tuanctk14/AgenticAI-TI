"""
tests/test_opencti_hash_search.py - Test OpenCTI hash search capability
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.opencti_client import _is_file_hash, fetch_opencti_indicators

def test_hash_detection():
    """Test hash detection for MD5, SHA-1, SHA-256"""
    # MD5 (32 hex)
    assert _is_file_hash("5d41402abc4b2a76b9719d911017c592") == True  # 32 hex = MD5

    # SHA-1 (40 hex)
    assert _is_file_hash("32a21398869e2e221552da49fe1d4beba11ad2ca") == True  # 40 hex = SHA-1

    # SHA-256 (64 hex)
    assert _is_file_hash("fe624698a9736f0975d20550d6fccc9c83536710d5cd1abc86e17e2624f01450") == True

    # Non-hash
    assert _is_file_hash("emotet") == False
    assert _is_file_hash("192.168.1.1") == False
    assert _is_file_hash("") == False

    print("[PASS] All hash detection tests passed")

def test_opencti_hash_search():
    """Test OpenCTI hash search (requires OPENCTI_TOKEN to be set)"""
    # Test with a known hash (if OpenCTI is available)
    test_hash = "fe624698a9736f0975d20550d6fccc9c83536710d5cd1abc86e17e2624f01450"

    result = fetch_opencti_indicators(search_term=test_hash, indicator_type="all")

    # Basic validation
    assert isinstance(result, dict)
    assert "source" in result
    assert "context" in result

    print(f"OpenCTI hash search result: {result['source']}")
    if result.get("error"):
        print(f"  Error: {result['error']}")
    else:
        print(f"  Results: {len(result['context'])} indicators found")
        for item in result['context']:
            print(f"    - {item.get('entity_type')}: {item.get('name')} (pattern: {item.get('pattern', 'N/A')[:50]})")

if __name__ == "__main__":
    test_hash_detection()
    test_opencti_hash_search()
    print("\n[PASS] All tests completed")
