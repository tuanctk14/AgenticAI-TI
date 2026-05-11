#!/usr/bin/env python3
"""Test Menu 3: Document Upload"""
import sys
import os
import json

if sys.platform == "win32":
    import codecs
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(__file__))

from tools.doc_store import upload_document, get_knowledge_base_stats

def test():
    print("\n╔════════════════════════════════════════════════════════╗")
    print("║           MENU 3: DOCUMENT UPLOAD TEST                 ║")
    print("╚════════════════════════════════════════════════════════╝\n")

    # Create a sample CVE JSON file for testing
    sample_data = {
        "cves": [
            {
                "id": "CVE-2024-12345",
                "description": "Test vulnerability from Menu 3 test",
                "cvss_score": 8.5,
                "severity": "HIGH"
            },
            {
                "id": "CVE-2024-54321",
                "description": "Another test vulnerability",
                "cvss_score": 7.2,
                "severity": "HIGH"
            }
        ],
        "indicators": [
            {
                "value": "menu3test.example.com",
                "type": "domain",
                "malware_family": "TestMalware"
            }
        ]
    }

    test_file = "test_menu3_upload.json"
    with open(test_file, 'w', encoding='utf-8') as f:
        json.dump(sample_data, f, indent=2, ensure_ascii=False)

    print(f"Uploading test file: {test_file}\n")

    try:
        # Upload the document
        result = upload_document(test_file)

        if "error" in result:
            print(f" ❌ Error: {result['error']}")
        else:
            saved = result.get("context", {})
            print(f" ✓ Successfully uploaded:")
            print(f"   CVEs: {saved.get('cves', 0)}")
            print(f"   IOCs: {saved.get('iocs', 0)}")
            print(f"   Malwares: {saved.get('malwares', 0)}")

        # Display KB stats
        print(f"\n[Knowledge Base Stats]")
        stats = get_knowledge_base_stats()
        s = stats.get("context", {})

        for cat in ["cves", "iocs", "malwares"]:
            info = s.get(cat, {})
            count = info.get("count", 0) if isinstance(info, dict) else info
            latest = info.get("latest_upload") if isinstance(info, dict) else None
            cat_name = {"cves": "CVEs", "iocs": "IOCs", "malwares": "Malwares"}.get(cat)
            if latest:
                print(f"   {cat_name:10s}: {count:3d} records | Last upload: {latest}")
            else:
                print(f"   {cat_name:10s}: {count:3d} records")

        return result
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
            print(f"\n ✓ Cleanup completed")

if __name__ == "__main__":
    test()
