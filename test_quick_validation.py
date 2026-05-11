#!/usr/bin/env python3
"""Quick validation of all major features"""
import sys
import os

if sys.platform == "win32":
    import codecs
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(__file__))

from main import run_query, _print_chat_response

def test_quick():
    print("\n╔════════════════════════════════════════════════════════╗")
    print("║           QUICK VALIDATION TEST                        ║")
    print("║   Kiểm tra nhanh tất cả tính năng chính               ║")
    print("╚════════════════════════════════════════════════════════╝\n")

    conversation_history = []

    tests = [
        ("Menu 4 - Device by ID", "SRV-001"),
        ("Menu 4 - Device by IP", "thiet bi ip 192.168.1.10"),
        ("Menu 4 - Device by Hostname", "thiet bi workstation-finance-01"),
        ("Menu 4 - CVE Query", "CVE-2021-44228"),
        ("Menu 4 - Keyword Search", "log4j"),
        ("Menu 4 - Off-Topic", "xin chào"),
    ]

    results = []

    for desc, query in tests:
        try:
            conversation_history.append({"role": "user", "content": query})
            result = run_query(query, verbose=False, chat_mode=True, conversation_history=conversation_history)

            agent_history = result.get("agent_history", [])
            response = result.get("last_agent_response", "")

            # Determine if test passed
            has_answer = "ANSWER:" in response or "HANDOFF:" in response
            passed = has_answer and len(agent_history) > 0

            status = "✅" if passed else "❌"
            results.append({
                "desc": desc,
                "status": status,
                "agents": " → ".join(agent_history),
                "response_type": "ANSWER" if "ANSWER:" in response else "HANDOFF"
            })

            # Add response to history
            if "ANSWER:" in response:
                answer_text = response.split("ANSWER:")[1].strip()[:50]
            else:
                answer_text = response[:50]
            conversation_history.append({"role": "assistant", "content": answer_text})

            print(f"{status} {desc}")
            print(f"   Agents: {results[-1]['agents']}")

        except Exception as e:
            results.append({
                "desc": desc,
                "status": "❌",
                "agents": "ERROR",
                "response_type": str(e)[:50]
            })
            print(f"❌ {desc}")
            print(f"   Error: {str(e)[:100]}")

    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)

    passed = sum(1 for r in results if "✅" in r["status"])
    total = len(results)

    print(f"\nPassed: {passed}/{total}")

    print("\nDetailed Results:")
    for r in results:
        print(f"{r['status']} {r['desc']:30s} | {r['agents']:40s} | {r['response_type']}")

    if passed == total:
        print("\n✅ ALL TESTS PASSED!\n")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed\n")

if __name__ == "__main__":
    test_quick()
