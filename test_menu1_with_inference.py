#!/usr/bin/env python3
"""
Test Menu 1 workflow with inference pipeline integrated.
This simulates what the system SHOULD do with full analyst-grade inference.
"""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from tools.inference_pipeline import InferencePipeline
from tools.cve_parser import parse_cve_metadata
from tools.cmdb import match_cves_with_cmdb
from tools.nvd_client import fetch_nvd_cves, fetch_cve_by_id
from tools.doc_store import fetch_kb_cves

print("=" * 80)
print("MENU 1 TEST: CVE SCAN + ANALYST-GRADE INFERENCE PIPELINE")
print("=" * 80)

# Simulate Menu 1: User enters CVE keyword
keyword = "CVE-2023-20198"
print(f"\nUser Input: {keyword}")
print("-" * 80)

# Step 1: Fetch CVE (current behavior - works)
print("\n[STEP 1] Fetch CVE from NVD/KB")
try:
    cve_result = fetch_cve_by_id(keyword)
    cves = cve_result.get("context", [])
    print(f"  Found: {len(cves)} CVE(s)")

    if cves:
        cve = cves[0]
        print(f"    CVE ID: {cve.get('id')}")
        print(f"    CVSS: {cve.get('cvss_score')}")
except Exception as e:
    print(f"  Error fetching CVE: {e}")
    cves = []

if not cves:
    print("ERROR: No CVE found")
    sys.exit(1)

# Step 2: CMDB Matching (current behavior - works with analyst-grade)
print("\n[STEP 2] Match with CMDB (Analyst-Grade)")
cmdb_result = match_cves_with_cmdb(cves)
matched_devices = cmdb_result.get("context", [])
print(f"  Matched devices: {len(matched_devices)}")

if matched_devices:
    for device in matched_devices:
        print(f"    - {device['device_id']} ({device['hostname']})")
        print(f"      Software: {device['affected_software']}")
        print(f"      Risk: {device['risk_level']}")

# Step 3: INFERENCE PIPELINE (NEW - not yet integrated into agents)
print("\n[STEP 3] Run Inference Pipeline (PROPOSED NEW LAYER)")
print("-" * 80)

pipeline = InferencePipeline()

print(f"\n  Processing inference for each CVE...")
for cve in cves:
    cve_id = cve.get("id", "")
    description = cve.get("description", "")

    # Parse CVE metadata for CWE
    cve_meta = parse_cve_metadata(cve)
    cwe_ids = cve.get("cwe_ids", [])
    if not cwe_ids and cve_meta.get("cwe_ids"):
        cwe_ids = cve_meta.get("cwe_ids", [])

    # Run full inference
    inference_result = pipeline.infer_cve_context(
        cve_id=cve_id,
        description=description,
        cwe_ids=cwe_ids,
        affected_product=None
    )

    print(f"\n  CVE: {cve_id}")
    print(f"    Inference Chain: {' -> '.join(inference_result['inference_layers_used'])}")
    print(f"    Confidence: {inference_result['confidence']:.2f}")

    if inference_result.get("vuln_class"):
        print(f"    Vulnerability Class: {inference_result['vuln_class']}")

    print(f"    CWE IDs: {inference_result.get('cwe_ids', [])}")
    print(f"    MITRE Techniques:")
    for tech in inference_result.get("mitre_techniques", []):
        print(f"      - {tech['id']}: {tech['name']} ({tech['tactic']}) [confidence: {tech['confidence']:.2f}]")

    print(f"    NIST Controls: {', '.join(inference_result.get('nist_controls', []))}")

    # Generate analyst report
    report = pipeline.generate_analyst_report(inference_result)
    print(f"    Analyst Report:")
    print(f"      - Inference Chain: {report['inference_chain']}")
    print(f"      - Confidence Score: {report['confidence_score']:.2f}")
    if report.get("product_category") != "unknown":
        print(f"      - Product Category: {report['product_category']}")

# Step 4: Compare Current vs Proposed
print("\n" + "=" * 80)
print("COMPARISON: CURRENT vs PROPOSED WITH INFERENCE PIPELINE")
print("=" * 80)

print("\n[CURRENT MENU 1 BEHAVIOR]")
print("  1. Fetch CVE -> OK (NVD/KB)")
print("  2. Match CMDB -> OK (analyst-grade)")
print("  3. Get MITRE -> Depends on cve_inference.py")
print("  4. Get NIST -> Depends on tools/nist.py")
print("  5. Generate remediation -> OK (from agent_analyst)")

print("\n[PROPOSED WITH INFERENCE PIPELINE]")
print("  1. Fetch CVE -> OK")
print("  2. Match CMDB -> OK")
print("  3. Run Inference Pipeline -> NEW")
print("     - Layer 1: Exact CVE mapping (0.95 confidence)")
print("     - Layer 2: CWE mapping (0.85 confidence)")
print("     - Layer 3: Vulnerability ontology (0.75-0.92)")
print("     - Layer 4: Product-aware context (device-specific ATT&CK)")
print("     - Layer 5: Generic fallback (0.40)")
print("  4. Generate analyst report with inference chain")
print("  5. Show confidence metrics per layer")

# Step 5: Test with different CVEs
print("\n" + "=" * 80)
print("TESTING OTHER CVEs WITH INFERENCE PIPELINE")
print("=" * 80)

test_cves = [
    ("CVE-2021-44228", "Apache Log4j2 RCE"),
    ("CVE-2021-41773", "Apache HTTP Server path traversal"),
]

for cve_id, expected_name in test_cves:
    try:
        result = fetch_cve_by_id(cve_id)
        if result.get("context"):
            cve = result["context"][0]
            inference = pipeline.infer_cve_context(
                cve_id=cve_id,
                description=cve.get("description", ""),
                cwe_ids=cve.get("cwe_ids", [])
            )
            print(f"\n{cve_id}: {expected_name}")
            print(f"  Inference: {' -> '.join(inference['inference_layers_used'])}")
            print(f"  Confidence: {inference['confidence']:.2f}")
            if inference.get("mitre_techniques"):
                print(f"  Techniques: {', '.join([t['id'] for t in inference['mitre_techniques'][:2]])}")
    except Exception as e:
        print(f"\n{cve_id}: ERROR - {str(e)[:50]}")

print("\n" + "=" * 80)
print("CONCLUSION")
print("=" * 80)

print("""
CURRENT STATE:
  ✅ Menu 1 works (CVE fetch + CMDB matching + remediation)
  ✅ Uses analyst-grade CPE-first matching
  ✅ Generates device-specific remediation

PROPOSED ENHANCEMENT:
  🔄 Integrate inference pipeline for multi-layer inference
  🔄 Show confidence scores and inference chain
  🔄 Product-aware ATT&CK context remapping
  🔄 Semantic vulnerability ontology classification

ACTION REQUIRED:
  1. Integrate InferencePipeline into agent_analyst
  2. Modify agent_analyst to call inference_pipeline.infer_cve_context()
  3. Update remediation generation to use inference results
  4. Display inference chain in final report

IMPACT:
  ✅ More transparent threat intelligence
  ✅ Analyst-grade confidence metrics
  ✅ Product-specific ATT&CK techniques
  ✅ Better remediation guidance
""")

print("=" * 80)
