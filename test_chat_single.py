#!/usr/bin/env python3
"""Test single CVE query in chat mode simulation"""
import sys
import os

# Fix encoding
if sys.platform == "win32":
    import codecs
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(__file__))

from core.state import init_state
from core.graph import get_graph
from main import _print_chat_response

def test_cve_chat():
    """Test CVE query in chat mode"""
    query = "CVE-2026-42569"

    print("\n╔════════════════════════════════════════════════════════╗")
    print("║           CHAT MODE - ATI THREAT INTELLIGENCE          ║")
    print("║  (Gõ 'exit' hoặc 'quit' để quay lại menu chính)       ║")
    print("╚════════════════════════════════════════════════════════╝\n")

    print(f"Bạn: {query}\n")

    graph = get_graph()
    state = init_state(query)

    try:
        result = graph.invoke(state, config={"recursion_limit": 30})
        _print_chat_response(result)
    except Exception as e:
        print(f"Lỗi: {e}")

if __name__ == "__main__":
    test_cve_chat()
