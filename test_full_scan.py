#!/usr/bin/env python
"""Test full CVE scan with device matching."""
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
print("FULL CVE SCAN WITH DEVICE MATCHING")
print("=" * 70)

query = "Quet CVE log4j va tim thiet bi bi anh huong sau do tao bao cao executive summary"
print(f"\nQuery: {query}")

state = init_state(query)
graph = get_graph()

print("\n[Starting full scan...]")
result = graph.invoke(state, config={"recursion_limit": 30})

print(f"\n✓ COMPLETED")
print(f"  Total steps: {result.get('num_steps')}")
print(f"  Agent flow: {' → '.join(result.get('agent_history', []))}")

cves = result.get('collected_cves') or []
devices = result.get('matched_devices') or []
report = result.get('final_report') or ""

print(f"\n[Results Summary]")
print(f"  CVEs collected: {len(cves)}")
if cves:
    critical = len([c for c in cves if c.get('severity') == 'CRITICAL'])
    print(f"    - CRITICAL: {critical}")
    print(f"    - Highest CVSS: {max([c.get('cvss_score', 0) for c in cves])}")

print(f"  Devices affected: {len(devices)}")
if devices:
    unique_devices = len({d['device_id'] for d in devices})
    print(f"    - Unique devices: {unique_devices}")
    for d in devices[:5]:
        print(f"      • {d['hostname']} | {d['cve_id']} | {d['risk_level']}")

if report:
    report_name = report.split('\\')[-1] if '\\' in report else report
    print(f"  Report: {report_name}")

print("\n" + "=" * 70)
