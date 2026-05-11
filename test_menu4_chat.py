#!/usr/bin/env python3
"""Test Menu 4: Chat Mode"""
import sys
import os

if sys.platform == "win32":
    import codecs
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(__file__))

from main import run_query, _print_chat_response

def test():
    print("\n╔════════════════════════════════════════════════════════╗")
    print("║           MENU 4: CHAT MODE TEST                       ║")
    print("╚════════════════════════════════════════════════════════╝\n")

    conversation_history = []

    test_queries = [
        ("Device query by ID", "SRV-001"),
        ("Device query by IP", "thiet bi ip 192.168.1.10"),
        ("Device query by hostname", "thiet bi workstation-finance-01"),
        ("General device query", "các thiết bị nội bộ"),
        ("CVE query", "CVE-2021-44228"),
        ("Keyword search", "log4j vulnerability"),
        ("Off-topic query", "bạn tên gì"),
    ]

    for i, (desc, query) in enumerate(test_queries, 1):
        print(f"\n[Query {i}] {desc}")
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

        print(f"\n{'='*70}\n")

    print("\n✓ Chat mode test completed with all query types\n")

if __name__ == "__main__":
    test()
