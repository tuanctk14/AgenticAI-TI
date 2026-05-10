#!/usr/bin/env python3
"""Test device query in chat mode"""
import sys
import os

if sys.platform == "win32":
    import codecs
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(__file__))

from main import run_query, _print_chat_response

def test_device_query():
    """Test device query"""
    print("\n╔════════════════════════════════════════════════════════╗")
    print("║           DEVICE QUERY TEST                            ║")
    print("╚════════════════════════════════════════════════════════╝\n")

    conversation_history = []

    # Query 1
    print("Bạn: SRV-001\n")
    result1 = run_query("SRV-001", verbose=False, chat_mode=True, conversation_history=conversation_history)
    _print_chat_response(result1)

    print("\n" + "="*70 + "\n")

    # Add to history
    conversation_history.append({"role": "user", "content": "SRV-001"})
    last_response = result1.get("last_agent_response", "")
    if "ANSWER:" in last_response:
        answer_text = last_response.split("ANSWER:")[1].strip()
    else:
        answer_text = last_response
    conversation_history.append({"role": "assistant", "content": answer_text})

    # Query 2
    print("Bạn: các thiết bị nội bộ\n")
    result2 = run_query("các thiết bị nội bộ", verbose=False, chat_mode=True, conversation_history=conversation_history)
    _print_chat_response(result2)

if __name__ == "__main__":
    test_device_query()
