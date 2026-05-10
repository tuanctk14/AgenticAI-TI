#!/usr/bin/env python3
"""Test full output in chat mode"""
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
    print("║           FULL OUTPUT TEST                             ║")
    print("╚════════════════════════════════════════════════════════╝\n")

    print("Bạn: SRV-001\n")
    result = run_query("SRV-001", verbose=False, chat_mode=True)
    _print_chat_response(result)

if __name__ == "__main__":
    test()
