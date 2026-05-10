#!/usr/bin/env python3
"""Test IP and hostname device queries"""
import sys
import os

if sys.platform == "win32":
    import codecs
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(__file__))

from main import run_query, _print_chat_response

def test_ip_query():
    """Test IP address device query"""
    print("\n╔════════════════════════════════════════════════════════╗")
    print("║           IP ADDRESS DEVICE QUERY TEST                 ║")
    print("╚════════════════════════════════════════════════════════╝\n")

    # Test 1: IP address query
    print("Bạn: thiet bi ip 192.168.1.10\n")
    result1 = run_query("thiet bi ip 192.168.1.10", verbose=False, chat_mode=True)
    _print_chat_response(result1)

    print("\n" + "="*70 + "\n")

    # Test 2: Hostname query
    print("Bạn: thiet bi workstation-finance-01\n")
    result2 = run_query("thiet bi workstation-finance-01", verbose=False, chat_mode=True)
    _print_chat_response(result2)

if __name__ == "__main__":
    test_ip_query()
