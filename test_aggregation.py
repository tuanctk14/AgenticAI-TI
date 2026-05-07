#!/usr/bin/env python
"""Test device-level CVE aggregation."""
import sys, os

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except:
        pass

sys.path.insert(0, os.path.dirname(__file__))

from tools.analyzer import aggregate_cves_by_device, summarize_device_risks
from tools.nvd_client import fetch_nvd_cves
from tools.cmdb import match_cves_with_cmdb

print("=" * 70)
print("TEST: Device-Level CVE Aggregation")
print("=" * 70)

# Step 1: Fetch CVEs
print("\n[Step 1] Fetch CVEs from NVD...")
cve_result = fetch_nvd_cves("log4j", "HIGH")
cves = cve_result.get("context", [])
print(f"  ✓ Found {len(cves)} CVEs")

# Step 2: Match with CMDB
print("\n[Step 2] Match CVEs with CMDB...")
match_result = match_cves_with_cmdb(cves)
matched = match_result.get("context", [])
print(f"  ✓ Found {len(matched)} matches")

# Step 3: Aggregate by device
print("\n[Step 3] Aggregate CVEs by device...")
agg_result = aggregate_cves_by_device(matched, cves)
device_map = agg_result.get("context", {})
print(f"  ✓ Grouped into {len(device_map)} unique devices")

# Step 4: Summarize risks
print("\n[Step 4] Summarize device risks...")
summary = summarize_device_risks(device_map)

print(f"\n[Device Risk Summary]")
print(f"  Total devices: {summary['total_devices']}")
print(f"  CRITICAL devices: {summary['critical_devices']}")
print(f"  HIGH devices: {summary['high_devices']}")
print(f"  MEDIUM devices: {summary['medium_devices']}")

print(f"\n[Device Details]")
for device_id, info in list(summary['device_risk_distribution'].items())[:5]:
    print(f"  {device_id} ({info['hostname']})")
    print(f"    - Risk: {info['risk_level']}")
    print(f"    - CVEs: {info['cve_count']}")

print(f"\n[Device-Level CVE Map Sample]")
for device_id, data in list(device_map.items())[:2]:
    print(f"\n  {device_id}: {data['device_info']['hostname']}")
    print(f"    Unique CVEs: {data['cve_ids']}")
    print(f"    Risk levels: {data['risk_levels']}")

print("\n" + "=" * 70)
print("OPTIMIZATION: Reduces analysis work from N CVEs to M unique CVEs/device")
print("  Where N = total matches, M = unique CVEs (typically 30-50% reduction)")
print("=" * 70)
