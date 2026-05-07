"""
tools/cmdb.py - So khớp CVE với inventory thiết bị nội bộ (CMDB)
"""
import json
import os

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
    "log4j":          ["log4j", "log4j2"],
    "apache":         ["apache", "httpd"],
    "openssl":        ["openssl"],
    "mysql":          ["mysql"],
    "ssh":            ["openssh"],
    "spring":         ["spring", "springframework"],
    "tomcat":         ["tomcat"],
    "cisco":          ["cisco"],
    "php":            ["php"],
    "chrome":         ["chrome"],
    "adobe":          ["adobe"],
}

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def match_cves_with_cmdb(cve_list: list) -> dict:
    """
    So khớp danh sách CVE với CMDB.
    Trả về các thiết bị có nguy cơ bị ảnh hưởng, sắp xếp theo mức độ nguy hiểm.
    """
    print(f"  [CMDB] So khớp {len(cve_list)} CVEs với {len(CMDB_DEVICES)} thiết bị")

    matches: list[dict] = []

    for cve in cve_list:
        cve_id   = str(cve.get("id",          "")).lower()
        cve_desc = str(cve.get("description", "")).lower()
        # Handle N/A or None cvss_score
        cvss_raw = cve.get("cvss_score", 0)
        try:
            cve_score = float(cvss_raw) if cvss_raw and cvss_raw != "N/A" else 0.0
        except (ValueError, TypeError):
            cve_score = 0.0

        # Thu thập keywords liên quan đến CVE này
        relevant: set[str] = set()
        for key, kws in VULN_KEYWORDS.items():
            if key in cve_id or key in cve_desc:
                relevant.update(kws)
        # Thêm keyword tự trích từ description
        for sw in ["apache", "log4j", "openssl", "mysql", "openssh",
                   "spring", "cisco", "php", "chrome", "adobe", "tomcat"]:
            if sw in cve_desc:
                relevant.add(sw)

        if not relevant:
            continue

        for device in CMDB_DEVICES:
            for sw in device["software"]:
                sw_lower = sw["name"].lower()
                if any(kw in sw_lower for kw in relevant):
                    risk = (
                        "CRITICAL" if cve_score >= 9.0 else
                        "HIGH"     if cve_score >= 7.0 else
                        "MEDIUM"
                    )
                    matches.append({
                        "cve_id":           cve.get("id"),
                        "cvss_score":       cve_score,
                        "risk_level":       risk,
                        "device_id":        device["device_id"],
                        "hostname":         device["hostname"],
                        "ip":               device["ip"],
                        "department":       device["department"],
                        "criticality":      device["criticality"],
                        "affected_software": f"{sw['name']} {sw['version']}",
                        "os":               f"{device['os']} {device['os_version']}",
                        "location":         device["location"],
                    })
                    break  # tránh duplicate per device

    # Sắp xếp theo nguy cơ
    matches.sort(key=lambda x: (
        RISK_ORDER.get(x["risk_level"], 4),
        RISK_ORDER.get(x["criticality"], 4),
    ))

    devices_affected = len({m["device_id"] for m in matches})
    print(f"  [CMDB] ✅ {len(matches)} matches trên {devices_affected} thiết bị")
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
