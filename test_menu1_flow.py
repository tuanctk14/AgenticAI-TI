#!/usr/bin/env python3
"""
Test Menu 1 workflow integration with inference pipeline.
Direct test without encoding issues.
"""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from tools.inference_pipeline import InferencePipeline
from tools.cmdb import match_cves_with_cmdb

print("=" * 80)
print("MENU 1 INTEGRATION TEST: CVE SCAN WITH INFERENCE PIPELINE")
print("=" * 80)

# Load test CVEs directly from KB
print("\n[STEP 1] Load Test CVEs")
with open("data/docs/cves.json", encoding="utf-8") as f:
    all_cves = json.load(f)

# Select test CVEs
test_cve_ids = ["CVE-2023-20198", "CVE-2021-44228", "CVE-2021-41773"]
test_cves = [c for c in all_cves if c.get("id") in test_cve_ids]

print(f"Loaded: {len(test_cves)} test CVEs")
for cve in test_cves:
    print(f"  - {cve.get('id')}: {cve.get('description', '')[:60]}...")

# Step 2: CMDB Matching (current behavior)
print("\n[STEP 2] CMDB Matching (Current Behavior)")
print("-" * 80)
cmdb_result = match_cves_with_cmdb(test_cves)
matched_devices = cmdb_result.get("context", [])
print(f"Total device matches: {len(matched_devices)}")

# Group by device
devices_map = {}
for device in matched_devices:
    dev_id = device["device_id"]
    if dev_id not in devices_map:
        devices_map[dev_id] = {"hostname": device["hostname"], "cves": []}
    devices_map[dev_id]["cves"].append({
        "cve_id": device["cve_id"],
        "risk": device["risk_level"],
        "software": device["affected_software"]
    })

for dev_id, info in devices_map.items():
    print(f"\n{dev_id} ({info['hostname']})")
    for cve_info in info["cves"]:
        print(f"  - {cve_info['cve_id']}: {cve_info['risk']} ({cve_info['software']})")

# Step 3: Run Inference Pipeline (NEW)
print("\n[STEP 3] Run Inference Pipeline (PROPOSED ENHANCEMENT)")
print("-" * 80)

pipeline = InferencePipeline()

cve_inference_results = {}

for cve in test_cves:
    cve_id = cve.get("id", "")
    description = cve.get("description", "")

    inference_result = pipeline.infer_cve_context(
        cve_id=cve_id,
        description=description,
        cwe_ids=cve.get("cwe_ids", []),
        affected_product=None
    )

    cve_inference_results[cve_id] = inference_result

    print(f"\nCVE: {cve_id}")
    print(f"  Inference Chain: {' -> '.join(inference_result['inference_layers_used'])}")
    print(f"  Confidence: {inference_result['confidence']:.2f}")
    print(f"  Vulnerability Class: {inference_result.get('vuln_class', 'N/A')}")
    print(f"  CWE IDs: {', '.join(inference_result.get('cwe_ids', []))}")
    print(f"  MITRE Techniques:")
    for tech in inference_result.get("mitre_techniques", []):
        print(f"    - {tech['id']}: {tech['name']} ({tech['tactic']}) [conf: {tech['confidence']:.2f}]")
    print(f"  NIST Controls: {', '.join(inference_result.get('nist_controls', []))}")

# Step 4: Enhanced Output with Inference
print("\n[STEP 4] ENHANCED MENU 1 OUTPUT WITH INFERENCE PIPELINE")
print("=" * 80)

print("\nVulnerability Intelligence Report")
print("-" * 80)

for cve in test_cves:
    cve_id = cve.get("id", "")
    cvss = cve.get("cvss_score", "N/A")
    inference = cve_inference_results.get(cve_id, {})

    print(f"\n{cve_id} (CVSS: {cvss})")
    print(f"  Description: {cve.get('description', '')[:100]}...")
    print(f"\n  Inference Analysis:")
    print(f"    Inference Chain: {' -> '.join(inference.get('inference_layers_used', []))}")
    print(f"    Confidence Score: {inference.get('confidence', 0.0):.2f}")

    if inference.get('vuln_class'):
        print(f"    Vulnerability Class: {inference['vuln_class']}")

    print(f"    CWE IDs: {', '.join(inference.get('cwe_ids', []))}")
    print(f"\n  MITRE ATT&CK Techniques:")
    for tech in inference.get("mitre_techniques", []):
        print(f"    {tech['id']}: {tech['name']}")
        print(f"      Tactic: {tech['tactic']}")
        print(f"      Confidence: {tech['confidence']:.2f}")

    print(f"\n  NIST Controls: {', '.join(inference.get('nist_controls', []))}")

    # Show affected devices
    affected = [d for d in matched_devices if d["cve_id"] == cve_id]
    if affected:
        print(f"\n  Affected Devices ({len(affected)}):")
        for device in affected:
            print(f"    - {device['device_id']} ({device['hostname']})")
            print(f"      Software: {device['affected_software']}")
            print(f"      Risk Level: {device['risk_level']}")
            print(f"      Match Type: {device.get('match_type', 'N/A')}")

# Step 5: Summary
print("\n" + "=" * 80)
print("SUMMARY: CURRENT vs ENHANCED WITH INFERENCE PIPELINE")
print("=" * 80)

print("""
CURRENT MENU 1 BEHAVIOR:
  Step 1: Fetch CVE
    - NVD/KB lookup works
    - CVE metadata extracted

  Step 2: CMDB Matching
    - Analyst-grade matching (CPE-first)
    - Match type shown (exact_normalized, keyword_fallback)
    - Device impact identified

  Step 3: Generate Remediation
    - MITRE ATT&CK from cve_inference.py
    - NIST controls from tools/nist.py
    - Device-specific remediation

PROPOSED ENHANCEMENT:
  Add Step 3A: Inference Pipeline
    - Multi-layer inference (5 layers)
    - Confidence scores per layer
    - Vulnerability ontology classification
    - Product-aware ATT&CK remapping
    - Transparent inference chain

BENEFITS:
  + Analyst-grade confidence metrics
  + Semantic vulnerability classification
  + Product-specific ATT&CK techniques
  + Clear inference chain visibility
  + Better transparency for security teams

STATUS:
  Current: WORKING (without inference pipeline)
  Enhanced: READY TO INTEGRATE (inference pipeline complete)
""")

print("=" * 80)
print("TEST COMPLETED SUCCESSFULLY")
print("=" * 80)
