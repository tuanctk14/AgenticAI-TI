#!/usr/bin/env python3
"""
Test Menu 2 enhancement with enrichment data
"""
import sys
import io

# Fix UTF-8 encoding on Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from tools.nvd_client import fetch_cve_by_id

print("=" * 70)
print("Testing Menu 2 with Enrichment Data")
print("=" * 70)

# Test with known CVE that has enrichment
test_cves = [
    "CVE-2021-44228",  # Log4j RCE
    "CVE-2021-3129",   # Laravel
    "CVE-2017-9822",   # WordPress
]

print(f"\n[INFO] Testing enrichment with known CVEs...")

cves = []
for cve_id in test_cves:
    result = fetch_cve_by_id(cve_id, enrich=True)
    if result.get("context"):
        cves.extend(result.get("context", []))
        print(f"  ✓ Fetched {cve_id}")
print(f"[INFO] Found {len(cves)} CVEs")

if cves:
    print(f"\n[INFO] Sample CVEs with enrichment data:\n")

    # Show first 3 CVEs with enrichment
    for i, cve in enumerate(cves[:3], 1):
        cve_id = cve.get("id", "N/A")
        cvss = cve.get("cvss_score", "N/A")
        severity = cve.get("severity", "N/A")

        enrichment = cve.get("enrichment", {})

        print(f"{i}. {cve_id}")
        print(f"   CVSS: {cvss} | Severity: {severity}")

        if enrichment:
            print(f"   [ENRICHMENT DATA]")

            # EPSS
            epss = enrichment.get("epss_score")
            if epss:
                print(f"     - EPSS: {epss:.4f}")

            # KEV
            if enrichment.get("kev_listed"):
                print(f"     - KEV: ✓ Listed (via {enrichment.get('kev_source')})")

            # Exploit
            exploit_flags = []
            if enrichment.get("public_exploit"):
                exploit_flags.append("POC")
            if enrichment.get("metasploit"):
                exploit_flags.append("MSF")
            if enrichment.get("ransomware_activity"):
                exploit_flags.append("⚠ Ransomware")

            if exploit_flags:
                print(f"     - Exploit: {', '.join(exploit_flags)}")

            # Risk score
            risk_score = enrichment.get("unified_risk_score")
            if risk_score:
                print(f"     - Risk Score: {risk_score:.2f}/100")

            summary = enrichment.get("enrichment_summary")
            if summary:
                print(f"     - Summary: {summary}")
        else:
            print(f"   [No enrichment data available]")

        print()

    # Calculate average risk score
    risk_scores = []
    for cve in cves:
        enrichment = cve.get("enrichment", {})
        if enrichment and enrichment.get("unified_risk_score"):
            risk_scores.append(enrichment.get("unified_risk_score"))
        else:
            # Fallback to CVSS
            cvss = cve.get("cvss_score", 0)
            if cvss and cvss != "N/A":
                try:
                    cvss_val = float(cvss)
                    risk_scores.append(min(100, cvss_val * 10))
                except (ValueError, TypeError):
                    pass

    if risk_scores:
        avg_risk = sum(risk_scores) / len(risk_scores)
        print(f"[SUMMARY] Average Risk Score: {avg_risk:.2f}/100")
        print(f"[SUMMARY] Total CVEs with risk data: {len(risk_scores)}/{len(cves)}")

        risk_level = (
            "CRITICAL (9-10)" if avg_risk >= 90 else
            "HIGH (7-9)" if avg_risk >= 70 else
            "MEDIUM (4-7)" if avg_risk >= 40 else
            "LOW (0-4)"
        )
        print(f"[SUMMARY] Risk Level: {risk_level}")

print("\n" + "=" * 70)
print("Test complete!")
print("=" * 70)
