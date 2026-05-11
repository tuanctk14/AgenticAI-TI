#!/usr/bin/env python3
"""Comprehensive test for all menu functionalities"""
import sys
import os
import json
from datetime import datetime, timedelta

if sys.platform == "win32":
    import codecs
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(__file__))

from main import run_query, _print_chat_response, _print_summary
from tools.doc_store import upload_document, get_knowledge_base_stats

def print_test_header(menu_num, title):
    print(f"\n{'='*70}")
    print(f" MENU {menu_num}: {title}")
    print(f"{'='*70}\n")

def test_menu_1():
    """Menu 1: CVE Scan"""
    print_test_header(1, "CVE Scan và tìm thiết bị ảnh hưởng")

    query = "Hãy quét lỗ hổng (keyword: log4j) từ NVD, so khớp với thiết bị nội bộ và cho biết thiết bị nào bị ảnh hưởng."
    print(f"Query: {query}\n")

    result = run_query(query, verbose=True, chat_mode=False)
    return result

def test_menu_2():
    """Menu 2: Report generation"""
    print_test_header(2, "Tạo báo cáo")

    # Calculate date range (last 7 days)
    end_date = datetime.now()
    start_date = end_date - timedelta(days=7)

    start_iso = start_date.strftime("%Y-%m-%dT00:00:00.000")
    end_iso = end_date.strftime("%Y-%m-%dT23:59:59.999")

    print(f"Date Range: {start_iso} to {end_iso}\n")

    # Create a query that will generate report
    query = f"Thực hiện đánh giá CVE: lấy CVE severity HIGH từ NVD, so khớp với hệ thống nội bộ, tạo báo cáo executive_summary."
    print(f"Query: {query}\n")

    result = run_query(query, verbose=True, chat_mode=False)
    return result

def test_menu_3():
    """Menu 3: Document upload"""
    print_test_header(3, "Upload / xử lý tài liệu nội bộ")

    # Create a sample CVE JSON file for testing
    sample_data = {
        "cves": [
            {
                "id": "CVE-2023-12345",
                "description": "Test vulnerability",
                "cvss_score": 8.5,
                "severity": "HIGH"
            },
            {
                "id": "CVE-2023-54321",
                "description": "Another test vulnerability",
                "cvss_score": 7.2,
                "severity": "HIGH"
            }
        ],
        "indicators": [
            {
                "value": "malware.example.com",
                "type": "domain",
                "malware_family": "Emotet"
            }
        ]
    }

    test_file = "test_upload.json"
    with open(test_file, 'w', encoding='utf-8') as f:
        json.dump(sample_data, f, indent=2)

    print(f"Uploading test file: {test_file}\n")

    try:
        result = upload_document(test_file)

        if "error" in result:
            print(f" Error: {result['error']}")
        else:
            saved = result.get("context", {})
            print(f" Successfully uploaded:")
            print(f"   CVEs: {saved.get('cves', 0)}")
            print(f"   IOCs: {saved.get('iocs', 0)}")
            print(f"   Malwares: {saved.get('malwares', 0)}")

        # Display KB stats
        stats = get_knowledge_base_stats()
        s = stats.get("context", {})
        print(f"\n[Knowledge Base Stats]")
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

def test_menu_4():
    """Menu 4: Chat mode with multiple queries"""
    print_test_header(4, "Chat với ATI BOT")

    conversation_history = []
    test_queries = [
        "SRV-001",  # Device query
        "CVE-2021-44228",  # CVE query
        "thiet bi ip 192.168.1.10",  # IP query
        "các thiết bị nội bộ",  # General device query
        "ca sĩ IU bạn biết không",  # Off-topic query
    ]

    for i, query in enumerate(test_queries, 1):
        print(f"\n--- Query {i} ---")
        print(f"Bạn: {query}\n")

        conversation_history.append({"role": "user", "content": query})

        result = run_query(query, verbose=False, chat_mode=True, conversation_history=conversation_history)
        _print_chat_response(result)

        # Add response to history
        last_response = result.get("last_agent_response", "")
        if "ANSWER:" in last_response:
            answer_text = last_response.split("ANSWER:")[1].strip()
        else:
            answer_text = last_response

        conversation_history.append({"role": "assistant", "content": answer_text})

        print("\n" + "-"*70)

def main():
    print("\n╔════════════════════════════════════════════════════════╗")
    print("║           FULL MENU FUNCTIONALITY TEST                ║")
    print("╚════════════════════════════════════════════════════════╝\n")

    # Check Ollama connection first
    from core.ollama_llm import check_ollama_connection
    ok, msg = check_ollama_connection()
    if not ok:
        print(f" Error: {msg}")
        sys.exit(1)

    print(f" ✓ Ollama connection OK\n")

    # Test each menu
    try:
        print("\n[Menu 1] Testing CVE Scan...")
        test_menu_1()
        input("\n[Enter để tiếp tục]")
    except Exception as e:
        print(f"Menu 1 Error: {e}")

    try:
        print("\n[Menu 2] Testing Report Generation...")
        test_menu_2()
        input("\n[Enter để tiếp tục]")
    except Exception as e:
        print(f"Menu 2 Error: {e}")

    try:
        print("\n[Menu 3] Testing Document Upload...")
        test_menu_3()
        input("\n[Enter để tiếp tục]")
    except Exception as e:
        print(f"Menu 3 Error: {e}")

    try:
        print("\n[Menu 4] Testing Chat Mode...")
        test_menu_4()
        input("\n[Enter để tiếp tục]")
    except Exception as e:
        print(f"Menu 4 Error: {e}")

    print("\n╔════════════════════════════════════════════════════════╗")
    print("║           ALL TESTS COMPLETED                         ║")
    print("╚════════════════════════════════════════════════════════╝\n")

if __name__ == "__main__":
    main()
