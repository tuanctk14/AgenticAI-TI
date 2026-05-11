#!/usr/bin/env python3
"""Comprehensive system functionality test"""
import sys
import os
import json
from datetime import datetime, timedelta

if sys.platform == "win32":
    import codecs
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(__file__))

from main import run_query, _print_chat_response
from tools.doc_store import get_knowledge_base_stats
from core.ollama_llm import check_ollama_connection

def print_section(title):
    print(f"\n{'='*70}")
    print(f" {title}")
    print(f"{'='*70}\n")

def test_connection():
    """Test 1: Ollama Connection"""
    print_section("TEST 1: Kết Nối Ollama")
    ok, msg = check_ollama_connection()
    if ok:
        print(f"✅ Ollama sẵn sàng: {msg}")
        return True
    else:
        print(f"❌ Lỗi kết nối: {msg}")
        return False

def test_menu1_cve_scan():
    """Test 2: Menu 1 - CVE Scan"""
    print_section("TEST 2: Menu 1 - Quét CVE và Tìm Thiết Bị Ảnh Hưởng")

    tests = [
        ("CVE cụ thể", "CVE-2021-44228"),
        ("Từ khóa CVE", "log4j vulnerability"),
        ("CVE + Device", "Hãy quét log4j từ NVD, so khớp với thiết bị nội bộ"),
    ]

    results = []
    for desc, query in tests:
        try:
            print(f"📌 Test: {desc}")
            print(f"   Query: {query[:50]}...")
            result = run_query(query, verbose=False, chat_mode=False)

            agent_history = result.get("agent_history", [])
            cves = result.get("collected_cves", [])

            status = "✅" if (agent_history and len(cves) > 0) else "⚠️"
            results.append({
                "desc": desc,
                "status": status,
                "agents": " → ".join(agent_history),
                "cves_found": len(cves)
            })
            print(f"   {status} Agents: {' → '.join(agent_history)}")
            print(f"   📊 CVEs found: {len(cves)}\n")
        except Exception as e:
            results.append({
                "desc": desc,
                "status": "❌",
                "agents": "ERROR",
                "cves_found": 0
            })
            print(f"   ❌ Error: {str(e)[:100]}\n")

    return results

def test_menu2_report():
    """Test 3: Menu 2 - Report Generation"""
    print_section("TEST 3: Menu 2 - Tạo Báo Cáo")

    try:
        # Test report generation
        query = "Tạo báo cáo bảo mật cho 7 ngày gần nhất"
        print(f"📌 Generating report...")
        print(f"   Query: {query}")

        result = run_query(query, verbose=False, chat_mode=False)
        agent_history = result.get("agent_history", [])

        status = "✅" if "agent_reporter" in agent_history else "⚠️"
        print(f"   {status} Agents: {' → '.join(agent_history)}")
        print(f"   📋 Report generated")

        return {
            "status": status,
            "agents": " → ".join(agent_history),
            "success": "agent_reporter" in agent_history
        }
    except Exception as e:
        print(f"   ❌ Error: {str(e)[:100]}")
        return {"status": "❌", "agents": "ERROR", "success": False}

def test_menu3_kb():
    """Test 4: Menu 3 - Knowledge Base Stats"""
    print_section("TEST 4: Menu 3 - Trạng Thái Knowledge Base")

    try:
        stats = get_knowledge_base_stats()
        kb_data = stats.get("context", {})

        print(f"✅ Knowledge Base Statistics:")
        for category in ["cves", "iocs", "malwares"]:
            info = kb_data.get(category, {})
            count = info.get("count", 0) if isinstance(info, dict) else info
            latest = info.get("latest_upload") if isinstance(info, dict) else None

            cat_name = {"cves": "CVEs", "iocs": "IOCs", "malwares": "Malwares"}.get(category)
            if latest:
                print(f"   📊 {cat_name:10s}: {count:3d} records | Last upload: {latest}")
            else:
                print(f"   📊 {cat_name:10s}: {count:3d} records")

        return {"status": "✅", "kb_stats": kb_data}
    except Exception as e:
        print(f"   ❌ Error: {str(e)[:100]}")
        return {"status": "❌", "kb_stats": {}}

def test_menu4_chat():
    """Test 5: Menu 4 - Chat Mode"""
    print_section("TEST 5: Menu 4 - Chat Mode Interaktif")

    chat_tests = [
        ("Device by ID", "SRV-001"),
        ("Device by IP", "thiet bi ip 192.168.1.10"),
        ("Device by Hostname", "thiet bi workstation-finance-01"),
        ("General Devices", "các thiết bị nội bộ"),
        ("CVE Lookup", "CVE-2021-44228"),
        ("Keyword Search", "log4j"),
        ("Off-Topic", "xin chào"),
    ]

    conversation_history = []
    results = []

    for desc, query in chat_tests:
        try:
            print(f"📌 {desc}")
            print(f"   Query: {query[:40]}...")

            conversation_history.append({"role": "user", "content": query})
            result = run_query(query, verbose=False, chat_mode=True, conversation_history=conversation_history)

            agent_history = result.get("agent_history", [])
            response = result.get("last_agent_response", "")

            has_answer = "ANSWER:" in response or "HANDOFF:" in response
            status = "✅" if (has_answer and len(agent_history) > 0) else "❌"

            results.append({
                "desc": desc,
                "status": status,
                "agents": " → ".join(agent_history)
            })

            print(f"   {status} Agents: {' → '.join(agent_history)}")

            # Add response to history
            if "ANSWER:" in response:
                answer_text = response.split("ANSWER:")[1].strip()[:50]
            else:
                answer_text = response[:50]
            conversation_history.append({"role": "assistant", "content": answer_text})

        except Exception as e:
            results.append({
                "desc": desc,
                "status": "❌",
                "agents": "ERROR"
            })
            print(f"   ❌ Error: {str(e)[:80]}")

        print()

    return results

def test_device_filtering():
    """Test 6: Device Filtering Features"""
    print_section("TEST 6: Tính Năng Lọc Thiết Bị")

    filter_tests = [
        ("Device ID", "SRV-001", "SRV-001"),
        ("Device IP", "192.168.1.10", "SRV-001"),
        ("Device Hostname", "workstation-finance-01", "PC-001"),
        ("IP khác", "192.168.1.20", "SRV-002"),
    ]

    results = []

    for desc, query, expected_device in filter_tests:
        try:
            print(f"📌 {desc}: {query}")

            result = run_query(f"thiet bi {query}", verbose=False, chat_mode=False)
            response = result.get("last_agent_response", "")

            # Check if expected device is in response
            found = expected_device in response
            status = "✅" if found else "❌"

            results.append({
                "desc": desc,
                "query": query,
                "status": status,
                "expected": expected_device,
                "found": found
            })

            print(f"   {status} Expected: {expected_device}, Found: {found}\n")
        except Exception as e:
            results.append({
                "desc": desc,
                "query": query,
                "status": "❌",
                "expected": expected_device,
                "found": False
            })
            print(f"   ❌ Error: {str(e)[:80]}\n")

    return results

def test_conversation_memory():
    """Test 7: Conversation Memory"""
    print_section("TEST 7: Bộ Nhớ Hội Thoại Đa Lần")

    try:
        conversation_history = []

        # Turn 1
        print("📌 Turn 1: Hỏi về một nhân vật")
        query1 = "bạn biết về ca sĩ IU không"
        print(f"   Query: {query1}")

        conversation_history.append({"role": "user", "content": query1})
        result1 = run_query(query1, verbose=False, chat_mode=True, conversation_history=conversation_history)
        response1 = result1.get("last_agent_response", "")

        if "ANSWER:" in response1:
            answer_text = response1.split("ANSWER:")[1].strip()[:50]
        else:
            answer_text = response1[:50]

        conversation_history.append({"role": "assistant", "content": answer_text})
        print(f"   ✅ Response received\n")

        # Turn 2
        print("📌 Turn 2: Hỏi về 'cô ấy' (should refer to IU)")
        query2 = "cô ấy có những bài hát nào nổi tiếng"
        print(f"   Query: {query2}")

        conversation_history.append({"role": "user", "content": query2})
        result2 = run_query(query2, verbose=False, chat_mode=True, conversation_history=conversation_history)
        response2 = result2.get("last_agent_response", "")

        # Check if conversation is understood (simplified check)
        understood = len(response2) > 50  # If LLM responded with meaningful text
        status = "✅" if understood else "❌"

        print(f"   {status} Conversation context understood: {understood}\n")

        return {
            "status": "✅" if understood else "⚠️",
            "turns": 2,
            "context_understood": understood
        }
    except Exception as e:
        print(f"   ❌ Error: {str(e)[:100]}")
        return {"status": "❌", "turns": 0, "context_understood": False}

def test_agent_routing():
    """Test 8: Agent Routing Logic"""
    print_section("TEST 8: Logic Định Tuyến Agent")

    routing_tests = [
        ("CVE Pattern", "CVE-2021-44228", ["agent_supervisor", "agent_ti"]),
        ("CVE + Device", "log4j affecting devices", ["agent_supervisor", "agent_ti", "agent_matcher"]),
        ("Device Only", "SRV-001", ["agent_supervisor", "agent_device"]),
        ("Off-Topic", "hello world", ["agent_supervisor"]),
    ]

    results = []

    for desc, query, expected_agents in routing_tests:
        try:
            print(f"📌 {desc}: {query[:30]}...")

            result = run_query(query, verbose=False, chat_mode=False)
            agent_history = result.get("agent_history", [])

            # Check if expected agents are in history
            all_match = all(agent in agent_history for agent in expected_agents)
            status = "✅" if all_match else "⚠️"

            results.append({
                "desc": desc,
                "status": status,
                "expected": expected_agents,
                "actual": agent_history
            })

            print(f"   {status} Expected: {expected_agents}")
            print(f"        Actual:   {agent_history}\n")
        except Exception as e:
            results.append({
                "desc": desc,
                "status": "❌",
                "expected": expected_agents,
                "actual": ["ERROR"]
            })
            print(f"   ❌ Error: {str(e)[:80]}\n")

    return results

def main():
    print("\n╔════════════════════════════════════════════════════════════╗")
    print("║   KIỂM TRA TOÀN BỘ CHỨC NĂNG HỆ THỐNG ATI                 ║")
    print("║   COMPREHENSIVE SYSTEM FUNCTIONALITY CHECK                  ║")
    print("╚════════════════════════════════════════════════════════════╝\n")

    all_results = {}

    # Test 1: Connection
    if not test_connection():
        print("\n❌ Không thể kết nối Ollama. Hủy test.")
        return

    # Test 2: Menu 1
    all_results["Menu 1 (CVE Scan)"] = test_menu1_cve_scan()

    # Test 3: Menu 2
    all_results["Menu 2 (Report)"] = test_menu2_report()

    # Test 4: Menu 3
    all_results["Menu 3 (KB Stats)"] = test_menu3_kb()

    # Test 5: Menu 4
    all_results["Menu 4 (Chat)"] = test_menu4_chat()

    # Test 6: Device Filtering
    all_results["Device Filtering"] = test_device_filtering()

    # Test 7: Conversation Memory
    all_results["Conversation Memory"] = test_conversation_memory()

    # Test 8: Agent Routing
    all_results["Agent Routing"] = test_agent_routing()

    # Summary
    print_section("TỔNG KẾT / SUMMARY")

    print("✅ Tất Cả Tests Hoàn Thành\n")

    print("📊 Chi Tiết Kết Quả:")
    for test_name, result in all_results.items():
        if isinstance(result, list):
            passed = sum(1 for r in result if r.get("status") == "✅")
            total = len(result)
            print(f"   {test_name:25s}: {passed}/{total} passed")
        elif isinstance(result, dict):
            status = result.get("status", "⚠️")
            print(f"   {test_name:25s}: {status}")

    print("\n╔════════════════════════════════════════════════════════════╗")
    print("║           KIỂM TRA HOÀN THÀNH / CHECK COMPLETE             ║")
    print("╚════════════════════════════════════════════════════════════╝\n")

if __name__ == "__main__":
    main()
