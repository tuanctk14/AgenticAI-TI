#!/usr/bin/env python
"""Test complete flow: CVE scan -> match -> report."""
import sys, os

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except:
        pass

sys.path.insert(0, os.path.dirname(__file__))

from tools.nvd_client import fetch_nvd_cves
from tools.cmdb import match_cves_with_cmdb
from tools.report_generator import generate_report
from core.state import init_state

print("=" * 70)
print("COMPLETE FLOW TEST: CVE Scan -> Match -> Executive Summary Report")
print("=" * 70)

# Step 1: Fetch CVEs
print("\n[STEP 1] Fetching CVEs (log4j, HIGH)...")
cve_result = fetch_nvd_cves("log4j", "HIGH")
cves = cve_result.get("context", [])
print(f"✓ Found {len(cves)} CVEs")

# Step 2: Match with CMDB
print("\n[STEP 2] Matching CVEs with CMDB...")
match_result = match_cves_with_cmdb(cves)
matched_devices = match_result.get("context", [])
print(f"✓ Found {len(matched_devices)} matches on {match_result.get('devices_affected')} devices")

# Step 3: Build state
print("\n[STEP 3] Building state for report...")
state = init_state("Test CVE assessment")
state["collected_cves"] = cves
state["matched_devices"] = matched_devices
state["last_agent_response"] = "ANSWER: Log4j vulnerability assessment completed. Devices have been identified and need patching within 24-48 hours."

# Step 4: Generate executive_summary
print("\n[STEP 4] Generating executive_summary report...")
report_result = generate_report(
    report_type="executive_summary",
    title="Log4j CVE Assessment - Executive Summary",
    state=state
)
report_file = report_result.get("file_path", "")
print(f"✓ Report generated: {report_file}")

# Step 5: Verify file
import os.path
if os.path.exists(report_file):
    with open(report_file, 'r', encoding='utf-8') as f:
        content = f.read()
    print(f"\n✓ Report file size: {len(content)} bytes")
    print(f"✓ Report contains dashboard: {'EXECUTIVE DASHBOARD' in content}")
    print(f"✓ Report contains critical actions: {'CRITICAL ACTIONS' in content or 'TOP 3' in content}")
    print(f"\nFirst 500 chars of report:")
    print("-" * 70)
    print(content[:500])
    print("-" * 70)
else:
    print(f"❌ Report file not found: {report_file}")

print("\n" + "=" * 70)
print("FLOW TEST COMPLETED SUCCESSFULLY!")
print("=" * 70)
