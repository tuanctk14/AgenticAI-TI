#!/usr/bin/env python
"""Test full agent flow through graph."""
import sys, os

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except:
        pass

sys.path.insert(0, os.path.dirname(__file__))

from core.state import init_state
from core.graph import get_graph
from config import OLLAMA_MODEL

print("=" * 70)
print("TEST: Full agent flow through graph")
print("=" * 70)

# Initialize state
query = "Tim thiet bi trong CMDB bi anh huong boi CVE-2021-44228"
print(f"\nQuery: {query}")
print(f"Model: {OLLAMA_MODEL}")

state = init_state(query)

# Build and invoke graph
graph = get_graph()

print("\n[Invoking graph...]")
result = graph.invoke(state, config={"recursion_limit": 10})

print(f"\n[Results]")
print(f"  Steps: {result.get('num_steps')}")
print(f"  Agents: {' -> '.join(result.get('agent_history', []))}")
print(f"  Collected CVEs: {len(result.get('collected_cves', []))}")
print(f"  Matched devices: {len(result.get('matched_devices', []))}")
print(f"  Tool observations: {len(result.get('tool_observations', []))}")

if result.get('matched_devices'):
    print("\n[Matched Devices:]")
    for d in result.get('matched_devices', [])[:3]:
        print(f"  - {d.get('hostname')} | {d.get('cve_id')} | {d.get('risk_level')}")

if result.get('last_agent_response'):
    print("\n[Final Response (first 300 chars):]")
    print(result.get('last_agent_response')[:300])

print("\n" + "=" * 70)
print("Full flow test completed")
print("=" * 70)
