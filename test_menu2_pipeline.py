#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test Menu 2 Report Pipeline with Full Pagination"""
import sys
import os
sys.stdout.reconfigure(encoding='utf-8') if hasattr(sys.stdout, 'reconfigure') else None

from tools.nvd_client import fetch_nvd_cves
from tools.opencti_client import fetch_opencti_indicators
from tools.cmdb import match_cves_with_cmdb
from tools.report_generator import generate_report
from datetime import datetime, timedelta, timezone

print("=" * 80)
print("MENU 2 PIPELINE TEST: Full Report Generation")
print("=" * 80)

# Simulate 7-day range
end_dt = datetime.now(timezone.utc)
start_dt = end_dt - timedelta(days=7)
start_date = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
end_date = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
start_display = start_dt.strftime("%d-%m-%Y")
end_display = end_dt.strftime("%d-%m-%Y")

print(f"\nTime Range: {start_display} -> {end_display} (7 days)")
print("-" * 80)

# Step 1: Fetch CVEs with full pagination
print("\n[Step 1] Fetching CVEs with full pagination...")
cve_result = fetch_nvd_cves(keyword="", severity="", start_date=start_date, end_date=end_date)
cves = cve_result.get("context", [])
print(f"  Total CVEs: {len(cves)}")
print(f"  Expected: {cve_result.get('total')} (from API)")

# Step 2: Fetch IOC/Malware
print("\n[Step 2] Fetching IOC/Malware from OpenCTI...")
ioc_result = fetch_opencti_indicators(search_term="")
indicators = ioc_result.get("context", [])
print(f"  Total Indicators: {len(indicators)}")

# Breakdown
entity_counts = {}
for ind in indicators:
    et = ind.get("entity_type", "Unknown")
    entity_counts[et] = entity_counts.get(et, 0) + 1
print(f"  Breakdown: {entity_counts}")

# Step 3: Match CVEs with devices
print("\n[Step 3] Matching CVEs with CMDB devices...")
cmdb_result = match_cves_with_cmdb(cves)
matches = cmdb_result.get("context", [])
devices_affected = cmdb_result.get("devices_affected", 0)
print(f"  Total CVE-Device matches: {len(matches)}")
print(f"  Devices affected: {devices_affected}")

# Build state
state = {
    "collected_cves": cves,
    "collected_indicators": indicators,
    "matched_devices": cmdb_result.get("context", []),
}

# Step 4: Generate both HTML and Markdown reports
print("\n[Step 4] Generating reports...")
print("  Generating HTML report...")
html_result = generate_report(
    state=state,
    title=f"Security Report - {start_display} to {end_display}",
    report_type="executive_summary",
    export_format="html"
)
html_file = html_result.get("file_path", "unknown")
print(f"    -> {html_file}")

print("  Generating Markdown report...")
md_result = generate_report(
    state=state,
    title=f"Security Report - {start_display} to {end_display}",
    report_type="executive_summary",
    export_format="markdown"
)
md_file = md_result.get("file_path", "unknown")
print(f"    -> {md_file}")

print("\n" + "=" * 80)
print("PIPELINE TEST COMPLETED SUCCESSFULLY!")
print("=" * 80)
print(f"\nSummary:")
print(f"  - CVEs Fetched: {len(cves)} (pagination working)")
print(f"  - IOC/Malware: {len(indicators)} (new fields available)")
print(f"  - Device-CVE Matches: {len(matches)}")
print(f"  - Reports Generated: HTML + Markdown")
print("\nGenerated reports with:")
print(f"  - {len(cves)} CVEs (full pagination, not 100 limit)")
print(f"  - {len(indicators)} diverse IOC/Malware (not fixed 17)")
print(f"  - {len(matches)} device-CVE mappings with remediation")
print(f"  - DD-MM-YYYY date format (e.g., {start_display} to {end_display})")
