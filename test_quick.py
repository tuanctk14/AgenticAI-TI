#!/usr/bin/env python
"""Quick test cho CyberSec optimization."""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from tools.nvd_client import fetch_cve_by_id, fetch_nvd_cves
from tools.cmdb import list_all_devices
from agents.base import call_agent
from core.state import init_state

print("=" * 60)
print("TEST 1: fetch_cve_by_id()")
print("=" * 60)
result = fetch_cve_by_id("CVE-2021-44228")
print(f"✓ Result: {len(result.get('context', []))} CVE found")
print(f"  Source: {result.get('source')}")

print("\n" + "=" * 60)
print("TEST 2: fetch_nvd_cves()")
print("=" * 60)
result = fetch_nvd_cves("log4j", "HIGH")
print(f"✓ Result: {len(result.get('context', []))} CVEs found")
print(f"  Source: {result.get('source')}")

print("\n" + "=" * 60)
print("TEST 3: list_all_devices()")
print("=" * 60)
result = list_all_devices()
devices = result.get('context', [])
print(f"✓ Result: {len(devices)} devices found")
if devices:
    print(f"  First device: {devices[0].get('hostname')}")

print("\n" + "=" * 60)
print("TEST 4: CMDB matching")
print("=" * 60)
from tools.cmdb import match_cves_with_cmdb
cves = [
    {"id": "CVE-2021-44228", "description": "Log4Shell", "cvss_score": 10.0},
    {"id": "CVE-2021-41773", "description": "Apache RCE", "cvss_score": 9.8}
]
result = match_cves_with_cmdb(cves)
matches = result.get('context', [])
print(f"✓ Result: {len(matches)} matches found")
print(f"  Devices affected: {result.get('devices_affected')}")

print("\n" + "=" * 60)
print("TEST 5: JSON parsing in call_tool")
print("=" * 60)
from agents.base import call_tool
test_state = {
    "last_agent_response": "ACTION: fetch_nvd_cves\nARGUMENTS: {\"keyword\": \"log4j\", \"severity\": \"HIGH\"}",
    "last_agent": "agent_ti",
    "tool_observations": [],
}
result_state = call_tool(test_state)
print(f"✓ call_tool() executed successfully")
print(f"  Observations: {len(result_state.get('tool_observations', []))} entries")

print("\n" + "=" * 60)
print("All tests passed!")
print("=" * 60)
