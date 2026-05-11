#!/usr/bin/env python3
"""Test MITRE ATT&CK and NIST SP 800-53 Integration"""
import sys
import os

if sys.platform == "win32":
    import codecs
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(__file__))

from main import run_query, _print_summary

def test():
    print("\n╔════════════════════════════════════════════════════════╗")
    print("║    MITRE ATT&CK & NIST SP 800-53 INTEGRATION TEST      ║")
    print("╚════════════════════════════════════════════════════════╝\n")

    # Test 1: CVE with device matching (should trigger analyst)
    print("Test 1: CVE Scan with Device Impact (trigger analyst)\n")
    query1 = "Hãy quét lỗ hổng (keyword: log4j) từ NVD, so khớp với thiết bị nội bộ"
    print(f"Query: {query1}\n")

    result1 = run_query(query1, verbose=True, chat_mode=False)

    agent_history = result1.get("agent_history", [])
    print(f"\n✓ Agent Flow: {' → '.join(agent_history)}")

    # Check if agent_analyst was called
    if "agent_analyst" in agent_history:
        print("✅ MITRE/NIST analysis EXECUTED")
    else:
        print("⚠️  MITRE/NIST analysis NOT called")
        print("   (Analyst may only be called if matcher provides info)")

    print("\n" + "="*70 + "\n")

    # Test 2: Direct CVE query for analysis
    print("Test 2: Direct CVE Analysis (CVE-2021-44228)\n")
    query2 = "CVE-2021-44228 analysis with MITRE ATT&CK and NIST controls"
    print(f"Query: {query2}\n")

    result2 = run_query(query2, verbose=True, chat_mode=False)

    agent_history2 = result2.get("agent_history", [])
    print(f"\n✓ Agent Flow: {' → '.join(agent_history2)}")

    if "agent_analyst" in agent_history2:
        print("✅ MITRE/NIST analysis EXECUTED")
    else:
        print("⚠️  MITRE/NIST analysis NOT called (analyst may need different routing)")

if __name__ == "__main__":
    test()
