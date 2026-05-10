#!/usr/bin/env python3
"""Test conversation history in chat mode"""
import sys
import os

if sys.platform == "win32":
    import codecs
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(__file__))

from main import run_query, _print_chat_response

def test_conversation():
    """Test multi-turn conversation"""
    print("\n╔════════════════════════════════════════════════════════╗")
    print("║           CONVERSATION MEMORY TEST                     ║")
    print("╚════════════════════════════════════════════════════════╝\n")

    conversation_history = []

    # Turn 1
    query1 = "ca sĩ IU bạn biết không"
    print(f"Bạn: {query1}\n")

    result1 = run_query(query1, verbose=False, chat_mode=True, conversation_history=conversation_history)
    _print_chat_response(result1)

    # Add to history
    conversation_history.append({"role": "user", "content": query1})
    last_response = result1.get("last_agent_response", "")
    if "ANSWER:" in last_response:
        answer_text = last_response.split("ANSWER:")[1].strip()
    else:
        answer_text = last_response
    conversation_history.append({"role": "assistant", "content": answer_text})

    print("\n" + "="*70 + "\n")

    # Turn 2
    query2 = "cô ấy có những bài hát nào nổi tiếng"
    print(f"Bạn: {query2}\n")

    result2 = run_query(query2, verbose=False, chat_mode=True, conversation_history=conversation_history)
    _print_chat_response(result2)

    print("\nNỘI DUNG CONVERSATION HISTORY:")
    print(f"Turn 1 (user): {query1[:50]}...")
    print(f"Turn 2 (user): {query2[:50]}...")
    print("✓ Supervisor should understand 'cô ấy' refers to IU from conversation context")

if __name__ == "__main__":
    test_conversation()
