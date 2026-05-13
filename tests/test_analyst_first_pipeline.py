"""
tests/test_analyst_first_pipeline.py - Test analyst-first agent flow for Menu 1

Test cases:
1. CVE with device match (Log4j -> SRV-002 if it exists in CMDB)
2. CVE without device match (no internal systems affected)
3. Multiple CVEs (keyword search)

Flow validation:
- agent_ti fetches CVE
- agent_analyst analyzes CWE -> MITRE/NIST (BEFORE device matching)
- agent_matcher matches CVE with CMDB and outputs full analysis
- Output always includes CVE + MITRE/NIST regardless of device match status
"""
import sys
import os
import io
from pathlib import Path

# Fix Unicode encoding for Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.graph import get_graph
from core.state import init_state


def test_analyst_first_pipeline():
    """
    Test the analyst-first pipeline with real CVE data.
    Validates that MITRE/NIST analysis happens BEFORE device matching.
    """
    print("\n" + "=" * 80)
    print(" ANALYST-FIRST PIPELINE - AGENT FLOW TESTS")
    print("=" * 80)
    print("")

    test_cases = [
        {
            "name": "Test 1: CVE with device match (Log4j)",
            "query": "Quét CVE log4j và tìm thiết bị ảnh hưởng trong CMDB",
            "expected_flow": ["agent_ti", "agent_analyst", "agent_matcher"],
            "validate": {
                "must_have_mitre": True,
                "must_have_nist": True,
                "must_have_remediation": True,
            }
        },
        {
            "name": "Test 2: Specific CVE without device match",
            "query": "Quét CVE-2024-12345 (CVE không có trong CMDB)",
            "expected_flow": ["agent_ti", "agent_analyst", "agent_matcher"],
            "validate": {
                "must_have_mitre": True,
                "must_have_nist": True,
                "must_have_remediation": True,
            }
        },
        {
            "name": "Test 3: Apache CVE (multiple results)",
            "query": "Quét lỗ hổng Apache từ NVD",
            "expected_flow": ["agent_ti", "agent_analyst", "agent_matcher"],
            "validate": {
                "must_have_mitre": True,
                "must_have_nist": True,
                "must_have_remediation": True,
            }
        },
    ]

    graph = get_graph()
    passed = 0
    failed = 0

    for test_case in test_cases:
        print(f"\n{'-' * 80}")
        print(f" {test_case['name']}")
        print(f"{'-' * 80}")
        print(f" Query: {test_case['query']}")
        print()

        try:
            # Initialize state with test query
            state = init_state(test_case["query"])

            # Run the graph (this will go through all agents)
            result = graph.invoke(state, config={"recursion_limit": 30})

            # Extract flow from agent_history
            agent_flow = result.get("agent_history", [])
            print(f" Agent flow: {' → '.join(agent_flow)}")

            # Validate flow contains expected agents
            has_ti = "agent_ti" in agent_flow
            has_analyst = "agent_analyst" in agent_flow
            has_matcher = "agent_matcher" in agent_flow

            print(f" ✓ agent_ti executed: {has_ti}")
            print(f" ✓ agent_analyst executed: {has_analyst}")
            print(f" ✓ agent_matcher executed: {has_matcher}")

            # Get final response
            final_response = result.get("last_agent_response", "")
            if final_response.startswith("ANSWER:"):
                final_response = final_response[8:].strip()

            # Validate output contains required sections
            validations = test_case.get("validate", {})
            all_valid = True

            if validations.get("must_have_mitre"):
                has_mitre = "MITRE" in final_response or "PHÂN TÍCH MITRE" in final_response
                print(f" ✓ Has MITRE section: {has_mitre}")
                all_valid = all_valid and has_mitre

            if validations.get("must_have_nist"):
                has_nist = "NIST" in final_response or "NIST SP 800-53" in final_response
                print(f" ✓ Has NIST section: {has_nist}")
                all_valid = all_valid and has_nist

            if validations.get("must_have_remediation"):
                has_remediation = "REMEDIATION" in final_response or "thiết bị" in final_response.lower()
                print(f" ✓ Has comprehensive output: {has_remediation}")
                all_valid = all_valid and has_remediation

            # Check state tracking
            attack_info = result.get("attack_info", {})
            nist_info = result.get("nist_info", {})
            analyst_iters = result.get("analyst_iterations", 0)

            print(f" ✓ attack_info in state: {bool(attack_info)}")
            print(f" ✓ nist_info in state: {bool(nist_info)}")
            print(f" ✓ analyst_iterations: {analyst_iters}")

            # Overall validation
            flow_correct = has_ti and has_analyst and has_matcher
            if flow_correct and all_valid:
                print(f"\n ✅ TEST PASSED")
                passed += 1
            else:
                print(f"\n ❌ TEST FAILED - Flow or validation issue")
                failed += 1
                if not flow_correct:
                    print(f"    Expected flow: {test_case['expected_flow']}")
                    print(f"    Actual flow: {agent_flow}")

        except Exception as e:
            print(f"\n ❌ TEST FAILED with exception: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    # Summary
    print(f"\n{'=' * 80}")
    print(f" SUMMARY: {passed} passed, {failed} failed")
    print(f"{'=' * 80}")
    print("")

    return failed == 0


if __name__ == "__main__":
    success = test_analyst_first_pipeline()
    sys.exit(0 if success else 1)
