#!/usr/bin/env python
"""Test agent_matcher specifically."""
import sys, os

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except:
        pass

sys.path.insert(0, os.path.dirname(__file__))

from agents.base import call_agent
from core.state import init_state

print("=" * 70)
print("TEST: Agent Matcher with proper tool parsing")
print("=" * 70)

# Create initial state with CVEs
state = init_state("Tim thiet bi trong CMDB bi anh huong boi log4j")
state["collected_cves"] = [
    {"id": "CVE-2021-44228", "description": "Log4Shell", "cvss_score": 10.0},
    {"id": "CVE-2021-4104", "description": "Log4j RCE", "cvss_score": 8.5}
]

print("\n[Initial State]")
print(f"  Query: {state['query']}")
print(f"  CVEs: {len(state.get('collected_cves', []))} CVEs")

# Call matcher agent
print("\n[Calling agent_matcher...]")
state = call_agent(state, "agent_matcher")

print("\n[State After Matcher]")
print(f"  Last agent: {state.get('last_agent')}")
print(f"  Tool observations: {len(state.get('tool_observations', []))}")
if state.get('matched_devices'):
    print(f"  Matched devices: {len(state.get('matched_devices'))} matches")
    for d in state.get('matched_devices', [])[:3]:
        print(f"    - {d.get('hostname')} ({d.get('cve_id')})")

print("\n" + "=" * 70)
print("Agent matcher test completed")
print("=" * 70)
