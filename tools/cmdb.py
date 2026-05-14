"""
tools/cmdb.py - So khớp CVE với inventory thiết bị nội bộ (CMDB)

Analyst-grade asset vulnerability correlation using:
1. Multi-CPE matching with version range support (gold source)
2. Software normalization (handle aliases)
3. Normalized ID matching (avoid false positives from keyword matching)
4. Description parsing fallback (when CPE unavailable)
5. Version range comparison for precise matching
"""
import json
import os
from tools.cve_parser import parse_cve_metadata, match_app_in_device, compare_versions
from tools.cwe_mapper import get_cwe_analysis

# Load CMDB từ file JSON
_DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cmdb_devices.json")
with open(_DATA_PATH, encoding="utf-8") as f:
    CMDB_DEVICES = json.load(f)

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def match_cves_with_cmdb(cve_list: list) -> dict:
    """
    ANALYST-GRADE CVE-to-device matching using multi-CPE architecture with version ranges.

    Process:
    1. Parse CVE with parse_cve_metadata (CPE-first → normalized software ID + all CPE entries)
    2. For CPE entries: check version range against device software
    3. For non-CPE: Match normalized ID against device software
    4. Return structured matches with confidence metrics

    Returns: {
        context: [
            {cve_id, cvss_score, risk_level, device_id, hostname, ip,
             affected_software, match_type, match_source, ...}
        ],
        source: "CMDB-Matcher",
        total_matches: int,
        devices_affected: int
    }
    """
    print(f"  [CMDB] Matching {len(cve_list)} CVEs with {len(CMDB_DEVICES)} devices (analyst-grade, multi-CPE)")

    matches: list[dict] = []

    for cve in cve_list:
        # PHASE 1: Parse CVE metadata (CPE-first architecture with multi-CPE support)
        cve_metadata = parse_cve_metadata(cve)

        cve_id = cve.get("id", "").upper()
        cve_source = cve_metadata.get("source")
        date_valid = cve_metadata.get("date_valid", True)
        date_warnings = cve_metadata.get("date_warnings", [])
        cpe_entries = cve_metadata.get("cpe_entries", [])  # NEW: multi-CPE support

        # Handle CVSS score
        cvss_raw = cve.get("cvss_score", 0)
        try:
            cve_score = float(cvss_raw) if cvss_raw and cvss_raw != "N/A" else 0.0
        except (ValueError, TypeError):
            cve_score = 0.0

        # Flag if date validation found issues
        if not date_valid:
            print(f"  [WARN] {cve_id}: Date validation failed - {date_warnings}")

        # PHASE 1.5: Extract CWE and map to MITRE/NIST
        cwe_analysis = get_cwe_analysis(cve)

        # PHASE 2: Multi-CPE Matching (NEW: iterate through all CPE entries)
        if cpe_entries:
            # Match using CPE entries with version ranges
            for cpe_entry in cpe_entries:
                matches.extend(_match_cpe_entry_with_devices(
                    cve_id, cve_score, cpe_entry, cve_metadata, cve_source,
                    date_valid, date_warnings, cwe_analysis
                ))
        else:
            # Fallback: use primary software ID from parse_cve_metadata
            normalized_sw_id = cve_metadata.get("normalized_software_id")
            if not normalized_sw_id:
                continue

            # Match against device inventory using normalized ID
            for device in CMDB_DEVICES:
                device_software = device.get("software", [])
                match_result = match_app_in_device(cve_metadata, device_software, device)

                if match_result.get("matched"):
                    risk = _calculate_risk(cve_score)
                    # Blend match confidence: structural match (60%) + MSI confidence (40%)
                    base_match_conf = match_result.get("confidence", 0)
                    if cve_source == "multi_source_intel" and cve_metadata.get("extraction_confidence"):
                        blended_conf = int(
                            base_match_conf * 0.6 +
                            cve_metadata.get("extraction_confidence", 0) * 100 * 0.4
                        )
                        match_confidence = min(blended_conf, 100)
                    else:
                        match_confidence = base_match_conf

                    matches.append({
                        "cve_id":              cve_id,
                        "cvss_score":          cve_score,
                        "risk_level":          risk,
                        "device_id":           device["device_id"],
                        "hostname":            device["hostname"],
                        "ip":                  device["ip"],
                        "department":          device["department"],
                        "criticality":         device["criticality"],
                        "affected_software":   match_result.get("software_name", "Unknown"),
                        "device_version":      match_result.get("device_version", "Unknown"),
                        "os":                  f"{device['os']} {device['os_version']}",
                        "location":            device["location"],
                        "match_type":          match_result.get("match_type", "unknown"),
                        "match_confidence":    match_confidence,
                        "match_source":        "normalized_id",  # NEW: track match source
                        "component":           match_result.get("component"),
                        "component_type":      match_result.get("component_type"),
                        "cve_source":          cve_source,
                        "date_valid":          date_valid,
                        "date_warnings":       date_warnings,
                        "cwe_ids":             cwe_analysis.get("cwe_ids", []),
                        "mitre_techniques":    cwe_analysis.get("mitre_techniques", []),
                        "nist_controls":       cwe_analysis.get("nist_controls", []),
                        "msi_confidence":      cve_metadata.get("extraction_confidence", 1.0),
                        "msi_source_breakdown": cve_metadata.get("msi_source_breakdown", {}),
                        "msi_sources_agreeing": cve_metadata.get("msi_sources_agreeing", []),
                    })

    # Sắp xếp theo nguy cơ
    matches.sort(key=lambda x: (
        RISK_ORDER.get(x["risk_level"], 4),
        RISK_ORDER.get(x["criticality"], 4),
    ))

    devices_affected = len({m["device_id"] for m in matches})
    print(f"  [CMDB]  {len(matches)} matches on {devices_affected} devices")
    return {
        "context":          matches,
        "source":           "CMDB-Matcher",
        "total_matches":    len(matches),
        "devices_affected": devices_affected,
    }


def _calculate_risk(cvss_score: float) -> str:
    """Calculate risk level from CVSS score"""
    return (
        "CRITICAL" if cvss_score >= 9.0 else
        "HIGH"     if cvss_score >= 7.0 else
        "MEDIUM"   if cvss_score >= 4.0 else
        "LOW"
    )


def _match_cpe_entry_with_devices(
    cve_id: str,
    cve_score: float,
    cpe_entry: dict,
    cve_metadata: dict,
    cve_source: str,
    date_valid: bool,
    date_warnings: list,
    cwe_analysis: dict
) -> list:
    """
    Match a single CPE entry against all devices using version range.
    Returns list of matches for this CPE entry.
    """
    matches = []
    cpe_vendor = cpe_entry.get("vendor", "").lower()
    cpe_product = cpe_entry.get("product", "").lower()
    normalized_cpe_id = cpe_entry.get("normalized_id", "").lower()

    # Version range from CPE
    version_end_excluding = cpe_entry.get("version_end_excluding")
    version_end_including = cpe_entry.get("version_end_including")
    version_start_including = cpe_entry.get("version_start_including")
    version_start_excluding = cpe_entry.get("version_start_excluding")

    for device in CMDB_DEVICES:
        device_software = device.get("software", [])

        # Try to match CPE vendor/product against device software
        for sw in device_software:
            sw_name = sw.get("name", "").lower()
            sw_version = sw.get("version", "")
            sw_normalized = sw.get("normalized_id", "").lower()

            # Check if this software matches the CPE
            matches_vendor = (cpe_vendor in sw_name or cpe_vendor in sw_normalized)
            matches_product = (cpe_product in sw_name or cpe_product in sw_normalized)
            matches_normalized = (normalized_cpe_id == sw_normalized) if normalized_cpe_id else False

            if (matches_vendor and matches_product) or matches_normalized:
                # Check version range
                if sw_version and (version_end_excluding or version_end_including or
                                   version_start_including or version_start_excluding):
                    is_vulnerable = compare_versions(
                        sw_version,
                        vulnerable_max=version_end_including,
                        version_end_excluding=version_end_excluding,
                        version_end_including=version_end_including,
                        version_start_including=version_start_including,
                        version_start_excluding=version_start_excluding,
                    )

                    if not is_vulnerable:
                        continue

                # Match found!
                risk = _calculate_risk(cve_score)
                matches.append({
                    "cve_id":              cve_id,
                    "cvss_score":          cve_score,
                    "risk_level":          risk,
                    "device_id":           device["device_id"],
                    "hostname":            device["hostname"],
                    "ip":                  device["ip"],
                    "department":          device["department"],
                    "criticality":         device["criticality"],
                    "affected_software":   sw_name,
                    "device_version":      sw_version,
                    "os":                  f"{device['os']} {device['os_version']}",
                    "location":            device["location"],
                    "match_type":          "version_range_match",
                    "match_confidence":    0.95,  # CPE + version range = high confidence
                    "match_source":        "cpe_version_range",  # NEW: track CPE-based match
                    "cpe_uri":             cpe_entry.get("cpe_uri"),
                    "version_range":       {
                        "start_including": version_start_including,
                        "start_excluding": version_start_excluding,
                        "end_including":   version_end_including,
                        "end_excluding":   version_end_excluding,
                    },
                    "component":           cve_metadata.get("component"),
                    "component_type":      cve_metadata.get("component_type"),
                    "cve_source":          cve_source,
                    "date_valid":          date_valid,
                    "date_warnings":       date_warnings,
                    "cwe_ids":             cwe_analysis.get("cwe_ids", []),
                    "mitre_techniques":    cwe_analysis.get("mitre_techniques", []),
                    "nist_controls":       cwe_analysis.get("nist_controls", []),
                })

    return matches


def list_all_devices() -> dict:
    """Liệt kê toàn bộ thiết bị trong CMDB."""
    summary = []
    for d in CMDB_DEVICES:
        sw_list = ", ".join(f"{s['name']} {s['version']}" for s in d["software"])
        summary.append({
            "device_id":   d["device_id"],
            "hostname":    d["hostname"],
            "ip":          d["ip"],
            "type":        d["type"],
            "os":          f"{d['os']} {d['os_version']}",
            "criticality": d["criticality"],
            "department":  d["department"],
            "software":    sw_list,
        })
    return {"context": summary, "source": "CMDB", "total": len(summary)}


def _load_kb_keywords():
    """Load KB keywords to enrich CMDB matching. Runs at import time."""
    try:
        from tools.doc_store import enrich_cmdb_keywords
        result = enrich_cmdb_keywords()
        kb_kw = result.get("context", {})
        VULN_KEYWORDS.update(kb_kw)
    except Exception:
        pass


_load_kb_keywords()
