"""
tools/cmdb.py - So khớp CVE với inventory thiết bị nội bộ (CMDB)

Analyst-grade asset vulnerability correlation using:
1. CPE-first architecture (gold source)
2. Software normalization (handle aliases)
3. Normalized ID matching (avoid false positives from keyword matching)
4. Description parsing fallback (when CPE unavailable)
"""
import json
import os
from tools.cve_parser import parse_cve_metadata, match_app_in_device
from tools.cwe_mapper import get_cwe_analysis

# Load CMDB từ file JSON
_DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cmdb_devices.json")
with open(_DATA_PATH, encoding="utf-8") as f:
    CMDB_DEVICES = json.load(f)

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def match_cves_with_cmdb(cve_list: list) -> dict:
    """
    ANALYST-GRADE CVE-to-device matching using CPE-first architecture.

    Process:
    1. Parse CVE with parse_cve_metadata (CPE-first → normalized software ID)
    2. Match normalized ID against device software (via match_app_in_device)
    3. Return structured matches with confidence metrics

    Returns: {
        context: [
            {cve_id, cvss_score, risk_level, device_id, hostname, ip,
             affected_software, match_type, ...}
        ],
        source: "CMDB-Matcher",
        total_matches: int,
        devices_affected: int
    }
    """
    print(f"  [CMDB] Matching {len(cve_list)} CVEs with {len(CMDB_DEVICES)} devices (analyst-grade)")

    matches: list[dict] = []

    for cve in cve_list:
        # PHASE 1: Parse CVE metadata (CPE-first architecture)
        cve_metadata = parse_cve_metadata(cve)

        cve_id = cve.get("id", "").upper()
        normalized_sw_id = cve_metadata.get("normalized_software_id")
        cve_source = cve_metadata.get("source")

        # Skip if no software identified
        if not normalized_sw_id:
            continue

        # Handle CVSS score
        cvss_raw = cve.get("cvss_score", 0)
        try:
            cve_score = float(cvss_raw) if cvss_raw and cvss_raw != "N/A" else 0.0
        except (ValueError, TypeError):
            cve_score = 0.0

        # PHASE 1.5: Extract CWE and map to MITRE/NIST
        cwe_analysis = get_cwe_analysis(cve)

        # PHASE 2: Match against device inventory
        for device in CMDB_DEVICES:
            device_software = device.get("software", [])

            # Use analyst-grade matching function with full device context
            match_result = match_app_in_device(cve_metadata, device_software, device)

            if match_result.get("matched"):
                risk = (
                    "CRITICAL" if cve_score >= 9.0 else
                    "HIGH"     if cve_score >= 7.0 else
                    "MEDIUM"   if cve_score >= 4.0 else
                    "LOW"
                )

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
                    "match_confidence":    match_result.get("confidence", 0),
                    "component":           match_result.get("component"),
                    "component_type":      match_result.get("component_type"),
                    "cve_source":          cve_source,
                    "cwe_ids":             cwe_analysis.get("cwe_ids", []),
                    "mitre_techniques":    cwe_analysis.get("mitre_techniques", []),
                    "nist_controls":       cwe_analysis.get("nist_controls", []),
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
