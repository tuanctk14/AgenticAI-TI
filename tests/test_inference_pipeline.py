#!/usr/bin/env python3
"""Test inference pipeline with multi-layer architecture"""
import sys
import json
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from tools.inference_pipeline import InferencePipeline
from tools.vuln_ontology import classify_vulnerability, VULN_CLASSES
from tools.product_context import get_product_category, remap_technique_for_context


def test_vulnerability_ontology():
    """Test semantic normalization of vulnerabilities."""
    print("=" * 80)
    print("TEST 1: VULNERABILITY ONTOLOGY (Semantic Normalization)")
    print("=" * 80)

    test_cases = [
        ("remote code execution vulnerability", "RCE"),
        ("command injection in user input", "RCE"),
        ("arbitrary file upload without validation", "FILE_UPLOAD"),
        ("sql injection in database query", "SQLI"),
        ("cross-site scripting vulnerability", "XSS"),
        ("path traversal directory access", "LFI"),
        ("authentication bypass in login", "AUTH_BYPASS"),
        ("privilege escalation vulnerability", "PRIVILEGE_ESCALATION"),
    ]

    for description, expected_class in test_cases:
        result = classify_vulnerability(description)
        actual_class = result.get("class", "None")
        status = "[PASS]" if actual_class == expected_class else "[FAIL]"
        print(f"\n{status} '{description}'")
        print(f"   Expected: {expected_class}, Got: {actual_class}")
        print(f"   Matched keywords: {result.get('matched_keywords', [])}")
        print(f"   Confidence: {result.get('confidence', 0.0):.2f}")
        print(f"   Source: {result.get('source', 'none')}")


def test_product_context():
    """Test product-aware context mapping."""
    print("\n" + "=" * 80)
    print("TEST 2: PRODUCT-AWARE CONTEXT (Device-Specific ATT&CK)")
    print("=" * 80)

    test_cases = [
        ("cisco:ios", "network_device"),
        ("apache:http_server", "web_server"),
        ("wordpress:wordpress", "web_application"),
        ("microsoft:windows", "operating_system_windows"),
        ("linux", None),  # Not in mapping
    ]

    for product_id, expected_context in test_cases:
        actual_context = get_product_category(product_id)
        if expected_context is None:
            expected_context = "unknown"

        status = "[PASS]" if actual_context == expected_context else "[FAIL]"
        print(f"\n{status} Product: {product_id}")
        print(f"   Expected context: {expected_context}, Got: {actual_context}")

    # Test technique remapping
    print("\n--- Technique Remapping per Product Context ---")
    remapping_tests = [
        ("T1059", "network_device", "T1059.008"),
        ("T1059", "web_server", "T1059.004"),
        ("T1059", "operating_system_windows", "T1059.001"),
        ("T1059", "operating_system_linux", "T1059.004"),
    ]

    for technique, context, expected_remapped in remapping_tests:
        remapped = remap_technique_for_context(technique, context)
        status = "[PASS]" if remapped == expected_remapped else "[FAIL]"
        print(f"{status} {technique} + {context} -> {remapped} (expected {expected_remapped})")


def test_inference_pipeline():
    """Test multi-layer inference pipeline."""
    print("\n" + "=" * 80)
    print("TEST 3: MULTI-LAYER INFERENCE PIPELINE")
    print("=" * 80)

    pipeline = InferencePipeline()

    # Test Case 1: Exact mapping
    print("\n--- Layer 1: Exact Mapping ---")
    result = pipeline.infer_cve_context(
        "CVE-2021-44228",
        "Apache Log4j2 RCE vulnerability",
        cwe_ids=["CWE-502", "CWE-78"]
    )
    print(f"CVE: {result['cve_id']}")
    print(f"Layers used: {' → '.join(result['inference_layers_used'])}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"MITRE Techniques:")
    for tech in result['mitre_techniques']:
        print(f"  - {tech['id']}: {tech['name']} ({tech['layer']})")

    # Test Case 2: CWE mapping (no exact match)
    print("\n--- Layer 2: CWE Mapping ---")
    result = pipeline.infer_cve_context(
        "CVE-UNKNOWN-001",
        "Buffer overflow in native code",
        cwe_ids=["CWE-787"]
    )
    print(f"CVE: {result['cve_id']}")
    print(f"Layers used: {' → '.join(result['inference_layers_used'])}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"MITRE Techniques:")
    for tech in result['mitre_techniques']:
        print(f"  - {tech['id']}: {tech['name']} (confidence: {tech['confidence']:.2f})")

    # Test Case 3: Vulnerability ontology (keyword-based)
    print("\n--- Layer 3: Vulnerability Ontology ---")
    result = pipeline.infer_cve_context(
        "CVE-UNKNOWN-002",
        "Arbitrary file upload vulnerability allows RCE",
        cwe_ids=None
    )
    print(f"CVE: {result['cve_id']}")
    print(f"Vuln Class: {result['vuln_class']}")
    print(f"Layers used: {' → '.join(result['inference_layers_used'])}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"MITRE Techniques:")
    for tech in result['mitre_techniques']:
        print(f"  - {tech['id']}: {tech['name']}")

    # Test Case 4: Product-aware context (Cisco)
    print("\n--- Layer 4: Product-Aware Context (Cisco IOS) ---")
    result = pipeline.infer_cve_context(
        "CVE-2023-20198",
        "Cisco IOS XE privilege escalation",
        cwe_ids=["CWE-250"],
        affected_product="cisco:ios_xe"
    )
    print(f"CVE: {result['cve_id']}")
    print(f"Product Context: {result['product_context']}")
    print(f"Layers used: {' → '.join(result['inference_layers_used'])}")
    print(f"MITRE Techniques (with context remapping):")
    for tech in result['mitre_techniques']:
        print(f"  - {tech['id']}: {tech['name']} ({tech['layer']})")


def test_analyst_report():
    """Test analyst report generation."""
    print("\n" + "=" * 80)
    print("TEST 4: ANALYST REPORT GENERATION")
    print("=" * 80)

    pipeline = InferencePipeline()

    result = pipeline.infer_cve_context(
        "CVE-2023-20198",
        "Cisco IOS XE privilege escalation",
        cwe_ids=["CWE-250"],
        affected_product="cisco:ios_xe"
    )

    report = pipeline.generate_analyst_report(result)

    print(f"\nCVE: {report['cve_id']}")
    print(f"Inference Chain: {report['inference_chain']}")
    print(f"Vulnerability Class: {report['vulnerability_class']}")
    print(f"Affected Product: {report['affected_product']}")
    print(f"Product Category: {report['product_category']}")
    print(f"Confidence Score: {report['confidence_score']:.2f}")
    print(f"\nCWE IDs: {report['cwe_ids']}")
    print(f"\nMITRE ATT&CK Techniques:")
    for tech in report['mitre_techniques']:
        print(f"  - {tech['id']}: {tech['name']} ({tech['tactic']}) [confidence: {tech['confidence']:.2f}]")
    print(f"\nNIST Controls: {', '.join(report['nist_controls'])}")


if __name__ == "__main__":
    test_vulnerability_ontology()
    test_product_context()
    test_inference_pipeline()
    test_analyst_report()

    print("\n" + "=" * 80)
    print("ALL TESTS COMPLETED")
    print("=" * 80)
