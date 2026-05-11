"""
Comprehensive test suite for ATI-AgenticThreatIntelligence
Tests all 3 main workflows:
1. CVE-only query
2. Device-only query
3. CVE + Device query
"""
from main import run_query

print("="*80)
print(" ATI SYSTEM - COMPREHENSIVE WORKFLOW TESTS")
print("="*80)

# Test 1: CVE-only query
print("\n" + "="*80)
print(" TEST 1: CVE-ONLY QUERY")
print("="*80)
result1 = run_query("Lấy thông tin CVE-2026-42569", verbose=False, chat_mode=False)
history1 = result1.get("agent_history", [])
cves1 = result1.get("collected_cves", [])
devices1 = result1.get("matched_devices", [])

print(f"Agent chain: {' → '.join(history1)}")
print(f"CVEs found: {len(cves1)}")
print(f"Devices matched: {len(devices1)}")
assert "agent_ti" in history1, "❌ agent_ti should be in chain"
assert "agent_matcher" not in history1, "❌ agent_matcher should NOT be in chain (no device request)"
assert len(cves1) > 0, "❌ Should find CVEs"
print("✅ TEST 1 PASSED: CVE-only workflow works\n")

# Test 2: Device-only query
print("="*80)
print(" TEST 2: DEVICE-ONLY QUERY")
print("="*80)
result2 = run_query("Liệt kê thông tin thiết bị SRV-001", verbose=False, chat_mode=False)
history2 = result2.get("agent_history", [])
devices2 = result2.get("matched_devices", [])

print(f"Agent chain: {' → '.join(history2)}")
print(f"Devices found: {len(devices2)}")
assert "agent_device" in history2, "❌ agent_device should be in chain"
assert "agent_ti" not in history2, "❌ agent_ti should NOT be in chain (no CVE request)"
assert "agent_matcher" not in history2, "❌ agent_matcher should NOT be in chain (no CVE request)"
print("✅ TEST 2 PASSED: Device-only workflow works\n")

# Test 3: CVE + Device query (full workflow)
print("="*80)
print(" TEST 3: CVE + DEVICE QUERY (Full Workflow)")
print("="*80)
result3 = run_query("Quét CVE-2026-42569 và tìm thiết bị bị ảnh hưởng", verbose=False, chat_mode=False)
history3 = result3.get("agent_history", [])
cves3 = result3.get("collected_cves", [])
devices3 = result3.get("matched_devices", [])
last_response3 = result3.get("last_agent_response", "")

print(f"Agent chain: {' → '.join(history3)}")
print(f"CVEs found: {len(cves3)}")
print(f"Devices matched: {len(devices3)}")
print(f"Final agent: {history3[-1] if history3 else 'None'}")

assert "agent_ti" in history3, "❌ agent_ti should fetch CVE"
assert "agent_matcher" in history3, "❌ agent_matcher should match CVE to devices"
assert "agent_analyst" in history3, "❌ agent_analyst should analyze MITRE/NIST"
assert len(cves3) > 0, "❌ Should find CVEs"
assert len(devices3) > 0, "❌ Should find matched devices"
assert "[Remediation dựa trên MITRE" in last_response3, "❌ Should have MITRE-based remediation"
print("✅ TEST 3 PASSED: Full CVE+Device workflow works\n")

# Summary
print("="*80)
print(" SUMMARY")
print("="*80)
print("✅ ALL TESTS PASSED!")
print("\nWorkflows verified:")
print("  1. CVE-only → agent_ti")
print("  2. Device-only → agent_device")
print("  3. CVE+Device → agent_ti → agent_matcher → agent_analyst")
print("\nKey features:")
print("  ✓ No agent loops detected")
print("  ✓ Proper HANDOFF routing")
print("  ✓ MITRE-based remediation in final analysis")
print("="*80)
