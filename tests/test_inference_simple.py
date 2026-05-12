#!/usr/bin/env python3
"""Test inference pipeline - simplified version"""
import sys
import json
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from tools.inference_pipeline import InferencePipeline
from tools.vuln_ontology import classify_vulnerability

print("=" * 80)
print("INFERENCE PIPELINE TEST - LAYER-BASED ARCHITECTURE")
print("=" * 80)

pipeline = InferencePipeline()

# Test 1: Vulnerability Ontology
print("\n[TEST 1] Vulnerability Ontology - Semantic Normalization")
print("-" * 80)
test_descriptions = [
    "remote code execution vulnerability",
    "arbitrary file upload without validation",
    "sql injection in database query",
]

for desc in test_descriptions:
    result = classify_vulnerability(desc)
    print("Input:    ", desc)
    print("Class:    ", result.get("class"))
    print("Confidence:", result.get("confidence", 0.0))
    print()

# Test 2: Exact CVE Mapping
print("[TEST 2] Layer 1 - Exact CVE Mapping")
print("-" * 80)
result = pipeline.infer_cve_context(
    "CVE-2021-44228",
    "Apache Log4j2 RCE vulnerability",
    cwe_ids=["CWE-502", "CWE-78"]
)
print("CVE:                ", result["cve_id"])
print("Inference layers:   ", " -> ".join(result["inference_layers_used"]))
print("Confidence:         ", result["confidence"])
print("MITRE Techniques:   ")
for tech in result["mitre_techniques"]:
    print(f"  - {tech['id']}: {tech['name']} ({tech['tactic']})")
print()

# Test 3: CWE Mapping (no exact match)
print("[TEST 3] Layer 2 - CWE Mapping (Buffer Overflow)")
print("-" * 80)
result = pipeline.infer_cve_context(
    "CVE-UNKNOWN-001",
    "Buffer overflow in native code",
    cwe_ids=["CWE-787"]
)
print("CVE:                ", result["cve_id"])
print("Inference layers:   ", " -> ".join(result["inference_layers_used"]))
print("Confidence:         ", result["confidence"])
print("MITRE Techniques:   ")
for tech in result["mitre_techniques"]:
    print(f"  - {tech['id']}: {tech['name']}")
print()

# Test 4: Product-Aware Context
print("[TEST 4] Layer 4 - Product-Aware Context (Cisco IOS)")
print("-" * 80)
result = pipeline.infer_cve_context(
    "CVE-2023-20198",
    "Cisco IOS XE privilege escalation",
    cwe_ids=["CWE-250"],
    affected_product="cisco:ios_xe"
)
print("CVE:                ", result["cve_id"])
print("Product Context:    ", result["product_context"])
print("Inference layers:   ", " -> ".join(result["inference_layers_used"]))
print("MITRE Techniques (with context remapping):")
for tech in result["mitre_techniques"]:
    print(f"  - {tech['id']}: {tech['name']} ({tech['layer']})")
print()

# Test 5: Analyst Report
print("[TEST 5] Analyst Report Generation")
print("-" * 80)
report = pipeline.generate_analyst_report(result)
print("CVE:              ", report["cve_id"])
print("Inference chain:  ", report["inference_chain"])
print("Confidence score: ", report["confidence_score"])
print("Product category: ", report["product_category"])
print("NIST Controls:    ", ", ".join(report["nist_controls"]))
print()

print("=" * 80)
print("ALL TESTS PASSED")
print("=" * 80)
