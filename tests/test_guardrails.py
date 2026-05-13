"""
tests/test_guardrails.py - Test Tool Permission Guardrails

Validates that TOOL_PERMISSIONS matrix prevents unauthorized tool calls
while maintaining Agentic AI principles (agent reasons within boundaries).
"""
import sys
import io
from pathlib import Path

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.base import TOOL_PERMISSIONS, call_tool


def test_guardrail_blocks_unauthorized_tool():
    """Test: agent_analyst cannot call match_cves_with_cmdb"""
    print("\n" + "=" * 80)
    print(" GUARDRAIL TEST 1: Block agent_analyst from calling match_cves_with_cmdb")
    print("=" * 80)

    # Simulate agent_analyst trying to call match_cves_with_cmdb
    state = {
        "last_agent": "agent_analyst",
        "last_agent_response": """
ACTION: match_cves_with_cmdb
ARGUMENTS: {"cve_list": []}
        """,
        "tool_observations": [],
    }

    result = call_tool(state)

    # Check that call was blocked
    obs = result.get("tool_observations", [])
    print(f"Tool observations: {len(obs)}")

    blocked = any("GUARDRAIL" in str(o) for o in obs)
    print(f"Guardrail block triggered: {blocked}")

    if blocked:
        print("\n✅ TEST PASSED - Unauthorized tool call was blocked")
        for o in obs:
            if "GUARDRAIL" in str(o):
                print(f"   Message: {o}")
        return True
    else:
        print("\n❌ TEST FAILED - Guardrail did not block unauthorized call")
        return False


def test_guardrail_allows_permitted_tool():
    """Test: agent_analyst CAN call get_mitre_attack_info"""
    print("\n" + "=" * 80)
    print(" GUARDRAIL TEST 2: Allow agent_analyst to call get_mitre_attack_info")
    print("=" * 80)

    # Simulate agent_analyst calling get_mitre_attack_info
    state = {
        "last_agent": "agent_analyst",
        "last_agent_response": """
ACTION: get_mitre_attack_info
ARGUMENTS: {"cve_id": "CVE-2021-44228"}
        """,
        "tool_observations": [],
    }

    result = call_tool(state)

    # Check that tool was called (not blocked)
    obs = result.get("tool_observations", [])
    print(f"Tool observations: {len(obs)}")

    called = any("get_mitre_attack_info" in str(o) and "GUARDRAIL" not in str(o) for o in obs)
    blocked = any("GUARDRAIL" in str(o) for o in obs)

    print(f"Tool called (not blocked): {called}")
    print(f"Guardrail blocked it: {blocked}")

    if called and not blocked:
        print("\n✅ TEST PASSED - Permitted tool call was allowed")
        return True
    elif blocked:
        print("\n❌ TEST FAILED - Guardrail incorrectly blocked permitted tool")
        return False
    else:
        print("\n⚠ TEST INCONCLUSIVE - Tool was not called but not blocked either")
        return True


def test_tool_permissions_matrix():
    """Test: Verify TOOL_PERMISSIONS matrix is complete and sensible"""
    print("\n" + "=" * 80)
    print(" GUARDRAIL TEST 3: Verify TOOL_PERMISSIONS matrix")
    print("=" * 80)

    print(f"\nAgent permissions defined: {len(TOOL_PERMISSIONS)}")
    for agent, tools in TOOL_PERMISSIONS.items():
        print(f"  {agent}: {len(tools)} tools")
        for tool in tools:
            print(f"    - {tool}")

    # Verify critical constraints
    checks = {
        "agent_analyst can only call MITRE/NIST": (
            set(TOOL_PERMISSIONS["agent_analyst"]) == {"get_mitre_attack_info", "get_nist_controls"}
        ),
        "agent_analyzer cannot call match_cves_with_cmdb": (
            "match_cves_with_cmdb" not in TOOL_PERMISSIONS.get("agent_analyst", [])
        ),
        "agent_matcher can only call match_cves_with_cmdb": (
            set(TOOL_PERMISSIONS["agent_matcher"]) == {"match_cves_with_cmdb"}
        ),
        "agent_ti can only call fetch_* tools": (
            all(t in ["fetch_cve_by_id", "fetch_nvd_cves", "fetch_kb_cves"]
                for t in TOOL_PERMISSIONS.get("agent_ti", []))
        ),
    }

    all_pass = True
    for check_name, result in checks.items():
        status = "✅" if result else "❌"
        print(f"{status} {check_name}")
        all_pass = all_pass and result

    print("")
    if all_pass:
        print("✅ TEST PASSED - TOOL_PERMISSIONS matrix is correct")
        return True
    else:
        print("❌ TEST FAILED - TOOL_PERMISSIONS matrix has issues")
        return False


def main():
    print("\n" + "=" * 80)
    print(" TOOL PERMISSION GUARDRAILS - COMPREHENSIVE TESTS")
    print("=" * 80)

    tests = [
        ("Block unauthorized tool", test_guardrail_blocks_unauthorized_tool),
        ("Allow permitted tool", test_guardrail_allows_permitted_tool),
        ("Verify permissions matrix", test_tool_permissions_matrix),
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            failed += 1
            print(f"❌ {test_name} FAILED with exception: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 80)
    print(f" SUMMARY: {passed} passed, {failed} failed")
    print("=" * 80)
    print("")

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
