"""
tools/nist.py - Ánh xạ CVE/lỗ hổng → NIST SP 800-53 controls và remediation steps
"""

NIST_PROFILES: dict[str, dict] = {
    "remote_code_execution": {
        "controls": [
            {"id": "SI-2",  "name": "Flaw Remediation",
             "action": "Áp dụng bản vá ngay lập tức; ưu tiên CVE CRITICAL."},
            {"id": "SI-3",  "name": "Malicious Code Protection",
             "action": "Triển khai EDR/AV trên tất cả hệ thống bị ảnh hưởng."},
            {"id": "SC-7",  "name": "Boundary Protection",
             "action": "Chặn kết nối JNDI/LDAP outbound tại firewall."},
            {"id": "CM-6",  "name": "Configuration Settings",
             "action": "Áp dụng workaround configuration trước khi có bản vá."},
            {"id": "RA-5",  "name": "Vulnerability Scanning",
             "action": "Quét authenticated để xác định toàn bộ instances bị ảnh hưởng."},
            {"id": "IR-4",  "name": "Incident Handling",
             "action": "Kích hoạt IR plan nếu nghi ngờ đã bị khai thác; isolate systems."},
        ],
        "priority":  "IMMEDIATE",
        "timeframe": "24-48 giờ",
    },
    "path_traversal": {
        "controls": [
            {"id": "SI-2",  "name": "Flaw Remediation",
             "action": "Cập nhật lên phiên bản đã vá ngay."},
            {"id": "SC-7",  "name": "Boundary Protection",
             "action": "Cấu hình WAF để chặn path traversal patterns."},
            {"id": "AC-3",  "name": "Access Enforcement",
             "action": "Hạn chế quyền truy cập file system của web server process."},
            {"id": "AU-2",  "name": "Event Logging",
             "action": "Bật logging chi tiết cho HTTP requests; monitor bất thường."},
        ],
        "priority":  "HIGH",
        "timeframe": "72 giờ",
    },
    "information_disclosure": {
        "controls": [
            {"id": "SI-2",  "name": "Flaw Remediation",
             "action": "Cập nhật và thay đổi tất cả credentials có thể bị lộ."},
            {"id": "SC-8",  "name": "Transmission Confidentiality",
             "action": "Tái tạo certificates; rotate private keys."},
            {"id": "IA-5",  "name": "Authenticator Management",
             "action": "Reset tất cả passwords và API keys trên hệ thống bị ảnh hưởng."},
        ],
        "priority":  "HIGH",
        "timeframe": "48 giờ",
    },
    "denial_of_service": {
        "controls": [
            {"id": "SI-2",  "name": "Flaw Remediation",
             "action": "Cập nhật phần mềm lên phiên bản đã vá."},
            {"id": "SC-5",  "name": "Denial of Service Protection",
             "action": "Cấu hình rate limiting và DDoS protection."},
            {"id": "CP-2",  "name": "Contingency Plan",
             "action": "Kích hoạt kế hoạch continuity nếu service bị gián đoạn."},
        ],
        "priority":  "MEDIUM",
        "timeframe": "7 ngày",
    },
    "generic": {
        "controls": [
            {"id": "SI-2",  "name": "Flaw Remediation",
             "action": "Áp dụng bản vá theo thứ tự ưu tiên."},
            {"id": "RA-5",  "name": "Vulnerability Scanning",
             "action": "Quét để xác định hệ thống bị ảnh hưởng."},
            {"id": "CM-8",  "name": "System Component Inventory",
             "action": "Cập nhật CMDB sau khi vá."},
        ],
        "priority":  "MEDIUM",
        "timeframe": "7 ngày",
    },
}

# Phân loại CVE → profile
CVE_PROFILE_MAP: dict[str, str] = {
    "CVE-2021-44228": "remote_code_execution",
    "CVE-2021-41773": "path_traversal",
    "CVE-2022-22965": "remote_code_execution",
    "CVE-2014-0160":  "information_disclosure",
    "CVE-2023-44487": "denial_of_service",
}


def get_nist_controls(cve_id: str = "", keyword: str = "") -> dict:
    """Ánh xạ CVE → NIST SP 800-53 controls và hành động khắc phục."""
    print(f"  [NIST] Lookup: cve='{cve_id}', keyword='{keyword}'")

    # Tìm profile phù hợp
    profile_key = CVE_PROFILE_MAP.get(cve_id.upper() if cve_id else "")
    if not profile_key and keyword:
        kw = keyword.lower()
        if any(w in kw for w in ("rce", "execute", "injection", "code execution")):
            profile_key = "remote_code_execution"
        elif any(w in kw for w in ("traversal", "path", "directory")):
            profile_key = "path_traversal"
        elif any(w in kw for w in ("disclosure", "leak", "heartbleed", "memory")):
            profile_key = "information_disclosure"
        elif any(w in kw for w in ("dos", "denial", "ddos", "reset")):
            profile_key = "denial_of_service"

    profile = NIST_PROFILES.get(profile_key or "generic")
    print(f"  [NIST]  Profile: {profile_key or 'generic'}, "
          f"priority: {profile['priority']}")
    return {"context": profile, "source": "NIST-SP800-53"}
