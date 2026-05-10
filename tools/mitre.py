"""
tools/mitre.py - Tra cứu MITRE ATT&CK mapping cho CVE
"""

# ── Mapping CVE → ATT&CK Techniques ──────────────────────────────────────
CVE_TO_ATTACK: dict[str, dict] = {
    "CVE-2021-44228": {
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application",
             "tactic": "Initial Access",
             "description": "Khai thác Log4Shell để có initial access qua JNDI injection."},
            {"id": "T1059", "name": "Command and Scripting Interpreter",
             "tactic": "Execution",
             "description": "Thực thi shell sau khi khai thác thành công Log4Shell RCE."},
            {"id": "T1071", "name": "Application Layer Protocol (C2)",
             "tactic": "Command and Control",
             "description": "LDAP/LDAPS dùng cho JNDI callback về server của attacker."},
        ],
        "threat_actors": ["APT41", "Lazarus Group", "Hafnium"],
        "kill_chain_phase": "Exploitation",
        "mitigations": ["M1051 - Update Software", "M1048 - Application Isolation"],
    },
    "CVE-2021-41773": {
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application",
             "tactic": "Initial Access",
             "description": "Path traversal trong Apache 2.4.49 cho phép đọc file nhạy cảm."},
            {"id": "T1083", "name": "File and Directory Discovery",
             "tactic": "Discovery",
             "description": "Duyệt hệ thống file qua HTTP request độc hại."},
        ],
        "threat_actors": ["Various Cybercriminals"],
        "kill_chain_phase": "Exploitation",
        "mitigations": ["M1051 - Update Software", "M1042 - Disable or Remove Feature"],
    },
    "CVE-2022-22965": {
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application",
             "tactic": "Initial Access",
             "description": "Spring4Shell cho phép RCE qua class manipulation trên JDK 9+."},
            {"id": "T1505.003", "name": "Web Shell",
             "tactic": "Persistence",
             "description": "Attacker deploy web shell sau khi khai thác Spring4Shell."},
        ],
        "threat_actors": ["Unknown / Cybercriminals"],
        "kill_chain_phase": "Exploitation",
        "mitigations": ["M1051 - Update Software", "M1018 - User Account Management"],
    },
    "CVE-2014-0160": {
        "techniques": [
            {"id": "T1040", "name": "Network Sniffing",
             "tactic": "Credential Access",
             "description": "Heartbleed cho phép đọc bộ nhớ server, lộ private keys và passwords."},
        ],
        "threat_actors": ["Various Nation-State Actors"],
        "kill_chain_phase": "Reconnaissance",
        "mitigations": ["M1051 - Update Software", "M1041 - Encrypt Sensitive Information"],
    },
    "CVE-2023-44487": {
        "techniques": [
            {"id": "T1498", "name": "Network Denial of Service",
             "tactic": "Impact",
             "description": "HTTP/2 Rapid Reset tạo DoS bằng cách reset stream liên tục."},
        ],
        "threat_actors": ["Unknown DDoS Groups"],
        "kill_chain_phase": "Impact",
        "mitigations": ["M1037 - Filter Network Traffic", "M1051 - Update Software"],
    },
}

# Generic fallback
GENERIC_ATTACK = {
    "techniques": [
        {"id": "T1190", "name": "Exploit Public-Facing Application",
         "tactic": "Initial Access",
         "description": "Khai thác lỗ hổng đã biết trên ứng dụng công khai."},
    ],
    "threat_actors": ["Unknown"],
    "kill_chain_phase": "Exploitation",
    "mitigations": ["M1051 - Update Software", "M1016 - Vulnerability Scanning"],
    "note": "Generic mapping - chưa có ATT&CK mapping cụ thể cho CVE này",
}


def get_mitre_attack_info(cve_id: str = "", technique: str = "", keyword: str = "") -> dict:
    """Truy xuất thông tin MITRE ATT&CK cho CVE hoặc kỹ thuật tấn công."""
    print(f"  [MITRE] Lookup: cve='{cve_id}', keyword='{keyword}'")

    # Tra cứu theo CVE ID
    result = CVE_TO_ATTACK.get(cve_id.upper() if cve_id else "")

    # Fallback: tra theo keyword
    if not result and keyword:
        for data in CVE_TO_ATTACK.values():
            if keyword.lower() in str(data).lower():
                result = data
                break

    if not result:
        result = GENERIC_ATTACK

    print(f"  [MITRE]  {len(result.get('techniques', []))} techniques, "
          f"actors: {result.get('threat_actors', [])}")
    return {"context": result, "source": "MITRE-ATT&CK"}
