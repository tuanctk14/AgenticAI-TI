"""
tools/cmdb.py - So khớp CVE với inventory thiết bị nội bộ (CMDB)
"""
import json
import os
from tools.cve_parser import parse_cve_metadata, compare_versions, match_app_in_device

# Load CMDB từ file JSON
_DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cmdb_devices.json")
with open(_DATA_PATH, encoding="utf-8") as f:
    CMDB_DEVICES = json.load(f)

# ── Keyword mapping: CVE / sản phẩm → tên phần mềm ───────────────────────
VULN_KEYWORDS: dict[str, list[str]] = {
    "CVE-2021-44228": ["log4j", "log4j2"],
    "CVE-2021-41773": ["apache", "apache http", "httpd"],
    "CVE-2022-22965": ["spring", "springframework"],
    "CVE-2014-0160":  ["openssl"],
    "CVE-2021-26855": ["exchange", "microsoft exchange"],
    "CVE-2023-44487": ["apache", "nginx", "tomcat", "http"],
    "CVE-2021-47940": ["wordpress", "download from files"],
    "log4j":          ["log4j", "log4j2"],
    "apache":         ["apache", "httpd"],
    "openssl":        ["openssl"],
    "mysql":          ["mysql"],
    "ssh":            ["openssh"],
    "spring":         ["spring", "springframework"],
    "tomcat":         ["tomcat"],
    "cisco":          ["cisco"],
    "wordpress":      ["wordpress"],
    "php":            ["php"],
    "chrome":         ["chrome"],
    "adobe":          ["adobe"],
}

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def match_cves_with_cmdb(cve_list: list) -> dict:
    """
    So khớp danh sách CVE với CMDB dựa trên:
    1. Parse CVE description để extract app name + version range
    2. Match app name với device software
    3. Compare version: device_version <= vulnerable_max_version?

    Trả về các thiết bị có nguy cơ bị ảnh hưởng, sắp xếp theo mức độ nguy hiểm.
    """
    print(f"  [CMDB] So khớp {len(cve_list)} CVEs với {len(CMDB_DEVICES)} thiết bị")

    matches: list[dict] = []

    for cve in cve_list:
        # Parse CVE metadata (app name, version, keywords)
        cve_metadata = parse_cve_metadata(cve)

        cve_id = cve.get("id", "").upper()
        cve_keywords = cve_metadata.get("keywords", [])
        affected_app = cve_metadata.get("affected_app", "Unknown")
        max_version = cve_metadata.get("max_version")
        min_version = cve_metadata.get("min_version")

        # Handle N/A or None cvss_score
        cvss_raw = cve.get("cvss_score", 0)
        try:
            cve_score = float(cvss_raw) if cvss_raw and cvss_raw != "N/A" else 0.0
        except (ValueError, TypeError):
            cve_score = 0.0

        # Nếu không tìm được keywords → skip
        if not cve_keywords and not affected_app:
            continue

        # Duyệt qua các thiết bị để matching
        for device in CMDB_DEVICES:
            matched_software = None

            # Kiểm tra mỗi phần mềm trên device
            for sw in device["software"]:
                sw_name = sw.get("name", "")
                sw_version = sw.get("version", "")
                sw_lower = sw_name.lower()

                # Check 1: Có trong keywords không?
                keyword_match = any(kw.lower() in sw_lower for kw in cve_keywords)

                # Check 2: App name match không?
                app_match = affected_app.lower() in sw_lower if affected_app else False

                # Nếu match theo keyword hoặc app name
                if keyword_match or app_match:
                    # Check 3: Version comparison (nếu có max_version)
                    if max_version:
                        if compare_versions(sw_version, max_version, min_version):
                            # Device version <= vulnerable version → MATCH!
                            matched_software = {
                                "name": sw_name,
                                "version": sw_version,
                                "vulnerable": True
                            }
                            break
                    else:
                        # Nếu không có version info từ CVE, match theo app name/keyword
                        matched_software = {
                            "name": sw_name,
                            "version": sw_version,
                            "vulnerable": True
                        }
                        break

            # Nếu tìm được phần mềm bị ảnh hưởng
            if matched_software:
                risk = (
                    "CRITICAL" if cve_score >= 9.0 else
                    "HIGH"     if cve_score >= 7.0 else
                    "MEDIUM"
                )
                matches.append({
                    "cve_id":            cve_id,
                    "cvss_score":        cve_score,
                    "risk_level":        risk,
                    "device_id":         device["device_id"],
                    "hostname":          device["hostname"],
                    "ip":                device["ip"],
                    "department":        device["department"],
                    "criticality":       device["criticality"],
                    "affected_software": f"{matched_software['name']} {matched_software['version']}",
                    "os":                f"{device['os']} {device['os_version']}",
                    "location":          device["location"],
                    "vulnerable_version": max_version,  # Vulnerable up to this version
                })

    # Sắp xếp theo nguy cơ
    matches.sort(key=lambda x: (
        RISK_ORDER.get(x["risk_level"], 4),
        RISK_ORDER.get(x["criticality"], 4),
    ))

    devices_affected = len({m["device_id"] for m in matches})
    print(f"  [CMDB]  {len(matches)} matches trên {devices_affected} thiết bị")
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
