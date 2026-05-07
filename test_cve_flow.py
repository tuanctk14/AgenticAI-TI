#!/usr/bin/env python
"""Test CVE scanning flow."""
import sys, os

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except:
        pass

sys.path.insert(0, os.path.dirname(__file__))

from core.state import init_state
from core.graph import get_graph

print("=" * 70)
print("CVE SCANNING FLOW TEST")
print("=" * 70)

query = "Quet CVE log4j va tim thiet bi bi anh huong"
print(f"\nQuery: {query}")

state = init_state(query)
graph = get_graph()

print("\n[Starting graph invoke...]")
result = graph.invoke(state, config={"recursion_limit": 20})

print(f"\n✓ COMPLETED")
print(f"  Total steps: {result.get('num_steps')}")
print(f"  Agents: {' -> '.join(result.get('agent_history', []))}")
cves = result.get('collected_cves') or []
devices = result.get('matched_devices') or []
print(f"  CVEs collected: {len(cves)}")
print(f"  Devices affected: {len(devices)}")

if result.get('collected_cves'):
    print("\n[CVEs found:]")
    for cve in result.get('collected_cves', [])[:3]:
        print(f"  - {cve['id']} (CVSS: {cve['cvss_score']})")

if result.get('matched_devices'):
    print("\n[Affected devices:]")
    for dev in result.get('matched_devices', [])[:3]:
        print(f"  - {dev['hostname']} | {dev['cve_id']}")

response = result.get('last_agent_response', '')[:300]
if response:
    print(f"\n[Final response (first 300 chars):]")
    print(f"  {response}...")

print("\n" + "=" * 70)
