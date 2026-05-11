"""
tools/cve_inference.py - Suy luận MITRE ATT&CK và NIST Controls từ CVE description
Cho các CVE mới không có trong database bằng NLP/keyword analysis + CWE mapping
"""
import re
from typing import Dict, List, Tuple, Optional


class CVEInference:
    """Suy luận MITRE techniques và NIST controls từ CVE description"""

    # CWE → MITRE ATT&CK mapping (analyst-grade, official CWE-ATT&CK correlations)
    CWE_MITRE_MAP = {
        # Input Validation & Injection
        "CWE-79": {
            "techniques": [("T1189", 0.95, "Drive-by Compromise")],
            "tactics": ["Initial Access"],
        },
        "CWE-89": {
            "techniques": [("T1190", 0.95, "Exploit Public-Facing Application")],
            "tactics": ["Initial Access"],
        },
        "CWE-434": {
            "techniques": [("T1190", 0.90, "Exploit Public-Facing Application"), ("T1505.003", 0.85, "Web Shell")],
            "tactics": ["Initial Access", "Persistence"],
        },
        "CWE-22": {
            "techniques": [("T1190", 0.85, "Exploit Public-Facing Application"), ("T1083", 0.80, "File and Directory Discovery")],
            "tactics": ["Initial Access"],
        },
        # Authentication & Credentials
        "CWE-287": {
            "techniques": [("T1110", 0.90, "Brute Force"), ("T1078", 0.85, "Valid Accounts")],
            "tactics": ["Credential Access"],
        },
        "CWE-347": {
            "techniques": [("T1187", 0.85, "Forced Authentication"), ("T1078", 0.80, "Valid Accounts")],
            "tactics": ["Credential Access"],
        },
        # Command Execution
        "CWE-78": {
            "techniques": [("T1190", 0.95, "Exploit Public-Facing Application"), ("T1059", 0.90, "Command and Scripting Interpreter")],
            "tactics": ["Initial Access", "Execution"],
        },
        "CWE-94": {
            "techniques": [("T1059", 0.95, "Command and Scripting Interpreter"), ("T1203", 0.80, "Exploitation for Client Execution")],
            "tactics": ["Execution"],
        },
        # Privilege Escalation
        "CWE-269": {
            "techniques": [("T1548", 0.90, "Abuse Elevation Control Mechanism")],
            "tactics": ["Privilege Escalation"],
        },
        "CWE-250": {
            "techniques": [("T1548", 0.85, "Abuse Elevation Control Mechanism")],
            "tactics": ["Privilege Escalation"],
        },
        # Information Disclosure
        "CWE-200": {
            "techniques": [("T1005", 0.85, "Data from Local System"), ("T1040", 0.75, "Traffic Sniffing")],
            "tactics": ["Discovery"],
        },
        "CWE-319": {
            "techniques": [("T1040", 0.90, "Traffic Sniffing"), ("T1557", 0.85, "On-Path Attack")],
            "tactics": ["Discovery"],
        },
        # Deserialization
        "CWE-502": {
            "techniques": [("T1190", 0.95, "Exploit Public-Facing Application"), ("T1059", 0.85, "Command and Scripting Interpreter")],
            "tactics": ["Initial Access", "Execution"],
        },
    }

    # CWE → NIST SP 800-53 mapping (analyst-grade controls for each CWE)
    CWE_NIST_MAP = {
        "CWE-79": ["SI-10", "SI-3", "SC-7"],  # Input validation, malware protection
        "CWE-89": ["SI-10", "SI-2", "RA-5"],  # SQL injection patches, vulnerability scanning
        "CWE-434": ["CM-6", "AC-3", "SI-7"],  # File upload restrictions, access control
        "CWE-22": ["AC-3", "AC-6", "SI-7"],  # Directory traversal - access control
        "CWE-287": ["IA-2", "IA-5", "IA-8"],  # Authentication failures - identity/access
        "CWE-347": ["IA-2", "SC-8", "AC-3"],  # Signature verification - authentication
        "CWE-78": ["SI-10", "AC-3", "SC-7"],  # Command injection - input validation
        "CWE-94": ["SI-10", "SI-3", "CM-6"],  # Code injection - malware protection
        "CWE-269": ["AC-3", "AC-6", "SC-7"],  # Improper permissions - least privilege
        "CWE-250": ["AC-3", "AC-6", "IA-5"],  # Execution with privileges - access control
        "CWE-200": ["AC-3", "AC-6", "SC-8"],  # Information disclosure - confidentiality
        "CWE-319": ["SC-8", "SC-13", "SC-7"],  # Unencrypted transmission - encryption
        "CWE-502": ["SI-10", "SI-3", "CM-6"],  # Deserialization - input validation
    }

    # Keyword patterns để detect vulnerability types
    VULNERABILITY_PATTERNS = {
        "rce": {
            "keywords": ["remote code execution", "rce", "arbitrary code execution", "command execution",
                        "code injection", "shell access", "system command", "execute code"],
            "cwe": ["CWE-78", "CWE-502"],
            "mitre_techniques": ["T1190", "T1059"],
            "nist_controls": ["SI-10", "AC-3", "SC-7"],
        },
        "file_upload": {
            "keywords": ["file upload", "arbitrary file upload", "unrestricted file", "upload vulnerable",
                        "file write"],
            "cwe": ["CWE-434"],
            "mitre_techniques": ["T1190", "T1505.003"],
            "nist_controls": ["CM-6", "AC-3", "SI-7"],
        },
        "web_shell": {
            "keywords": ["web shell", "backdoor", "webshell", "persistent shell", "shell upload"],
            "mitre_techniques": ["T1505.003", "T1190"],
            "nist_controls": ["AC-3", "AC-6", "CM-6", "SI-7", "SC-7"],
        },
        "auth_bypass": {
            "keywords": ["authentication bypass", "bypass authentication", "auth bypass", "unauthorized access",
                        "bypass login", "skip authentication", "authentication weakness"],
            "cwe": ["CWE-287"],
            "mitre_techniques": ["T1078"],
            "nist_controls": ["IA-2", "IA-5"],
        },
        "sqli": {
            "keywords": ["sql injection", "sqli", "database injection"],
            "cwe": ["CWE-89"],
            "mitre_techniques": ["T1190"],
            "nist_controls": ["SI-10", "SI-2", "RA-5"],
        },
        "xss": {
            "keywords": ["cross-site scripting", "xss", "dom-based xss", "stored xss", "reflected xss"],
            "cwe": ["CWE-79"],
            "mitre_techniques": ["T1189"],
            "nist_controls": ["SI-10", "SI-3", "SC-7"],
        },
        "lfi": {
            "keywords": ["local file inclusion", "lfi", "file inclusion", "arbitrary file read",
                        "path traversal", "directory traversal"],
            "cwe": ["CWE-22"],
            "mitre_techniques": ["T1190"],
            "nist_controls": ["AC-3", "AC-6", "SI-7"],
        },
        "privilege_escalation": {
            "keywords": ["privilege escalation", "privilege esclation", "elevated access", "sudo", "escalate privilege",
                        "run as administrator", "administrator access"],
            "cwe": ["CWE-269", "CWE-250"],
            "mitre_techniques": ["T1548"],
            "nist_controls": ["AC-3", "AC-6", "SC-7"],
        },
        "dos": {
            "keywords": ["denial of service", "dos", "ddos", "crash", "resource exhaustion",
                        "buffer overflow", "heap overflow", "stack overflow"],
            "mitre_techniques": ["T1499"],
            "nist_controls": ["SC-7", "SI-4"],
        },
        "information_disclosure": {
            "keywords": ["information disclosure", "sensitive information", "data leak", "expose credential",
                        "leak secret", "information exposure", "sensitive data"],
            "cwe": ["CWE-200"],
            "mitre_techniques": ["T1005"],
            "nist_controls": ["AC-3", "AC-6", "SC-8"],
        },
        "cve_2021_47933": {
            # WordPress Plugin: Download From Files RCE
            "keywords": ["download from files", "wordpress plugin", "plugin", "unauthenticated"],
            "cwe": ["CWE-78"],
            "mitre_techniques": ["T1190", "T1505.003", "T1059"],
            "nist_controls": ["SI-10", "AC-3", "SC-7"],
        },
    }

    @staticmethod
    def extract_cwe_from_description(description: str) -> List[str]:
        """Extract CWE IDs from CVE description (e.g., 'CWE-79', 'CWE-89')"""
        cwe_pattern = r'CWE-(\d+)'
        matches = re.findall(cwe_pattern, description, re.IGNORECASE)
        return [f"CWE-{m}" for m in matches]

    @staticmethod
    def infer_cwe_from_vulnerability_type(description: str) -> List[str]:
        """Suy luận CWE từ loại vulnerability được phát hiện"""
        desc_lower = description.lower()
        detected_cwes = set()

        for vuln_type, patterns in CVEInference.VULNERABILITY_PATTERNS.items():
            if "cwe" in patterns:
                for keyword in patterns["keywords"]:
                    if keyword in desc_lower:
                        detected_cwes.update(patterns["cwe"])
                        break

        return sorted(list(detected_cwes))

    @staticmethod
    def infer_mitre_from_cwe(cwe_ids: List[str], description: str = "") -> Tuple[List[Tuple[str, float, str]], List[str]]:
        """
        Suy luận MITRE techniques từ CWE IDs
        Returns: ([(technique_id, confidence, tactic), ...], tactics_list)
        """
        techniques = {}
        tactics_set = set()

        for cwe_id in cwe_ids:
            if cwe_id in CVEInference.CWE_MITRE_MAP:
                mapping = CVEInference.CWE_MITRE_MAP[cwe_id]
                for tech_id, confidence, tactic_name in mapping["techniques"]:
                    if tech_id not in techniques:
                        techniques[tech_id] = (confidence, tactic_name)
                    else:
                        old_conf = techniques[tech_id][0]
                        techniques[tech_id] = (max(old_conf, confidence), tactic_name)
                tactics_set.update(mapping["tactics"])

        tech_list = [(tid, conf, tactic) for tid, (conf, tactic) in techniques.items()]
        tech_list.sort(key=lambda x: x[1], reverse=True)

        return tech_list[:5], sorted(list(tactics_set))

    @staticmethod
    def infer_nist_from_cwe(cwe_ids: List[str]) -> List[str]:
        """Suy luận NIST controls từ CWE IDs"""
        controls = set()
        for cwe_id in cwe_ids:
            if cwe_id in CVEInference.CWE_NIST_MAP:
                controls.update(CVEInference.CWE_NIST_MAP[cwe_id])

        ctrl_list = sorted(list(controls))
        main_controls = ["AC-3", "CM-6", "SI-7", "SI-3", "SC-7"]
        priority_ordered = []
        for ctrl in main_controls:
            if ctrl in ctrl_list:
                priority_ordered.append(ctrl)
        for ctrl in ctrl_list:
            if ctrl not in priority_ordered:
                priority_ordered.append(ctrl)
        return priority_ordered[:5]

    @staticmethod
    def infer_vulnerability_type(description: str) -> List[str]:
        """
        Suy luận loại vulnerability từ description
        Returns: list of detected vulnerability types
        """
        desc_lower = description.lower()
        detected_types = []

        for vuln_type, patterns in CVEInference.VULNERABILITY_PATTERNS.items():
            for keyword in patterns["keywords"]:
                if keyword in desc_lower:
                    detected_types.append(vuln_type)
                    break

        return detected_types if detected_types else ["unknown"]

    @staticmethod
    def infer_mitre_techniques(description: str) -> Tuple[List[str], List[str]]:
        """
        Suy luận MITRE ATT&CK techniques từ CVE description
        Sử dụng CWE làm primary source, fallback to vulnerability type patterns

        Returns: (techniques_list, vulnerability_types)
        """
        cwe_ids = CVEInference.extract_cwe_from_description(description)

        if not cwe_ids:
            cwe_ids = CVEInference.infer_cwe_from_vulnerability_type(description)

        if cwe_ids:
            tech_tuples, _ = CVEInference.infer_mitre_from_cwe(cwe_ids, description)
            techniques = [t[0] for t in tech_tuples]
        else:
            techniques = []

        if not techniques:
            vuln_types = CVEInference.infer_vulnerability_type(description)
            for vuln_type in vuln_types:
                if vuln_type in CVEInference.VULNERABILITY_PATTERNS:
                    patterns = CVEInference.VULNERABILITY_PATTERNS[vuln_type]
                    techniques.extend(patterns["mitre_techniques"])
            techniques = list(set(techniques))

        if not techniques:
            techniques = ["T1190", "T1059"]

        return techniques[:5], CVEInference.infer_vulnerability_type(description)

    @staticmethod
    def infer_nist_controls(description: str) -> Tuple[List[str], List[str]]:
        """
        Suy luận NIST SP 800-53 controls từ CVE description
        Sử dụng CWE làm primary source, fallback to vulnerability type patterns

        Returns: (controls_list, vulnerability_types)
        """
        cwe_ids = CVEInference.extract_cwe_from_description(description)

        if not cwe_ids:
            cwe_ids = CVEInference.infer_cwe_from_vulnerability_type(description)

        if cwe_ids:
            controls = CVEInference.infer_nist_from_cwe(cwe_ids)
        else:
            controls = []

        if not controls:
            vuln_types = CVEInference.infer_vulnerability_type(description)
            controls_set = set()
            for vuln_type in vuln_types:
                if vuln_type in CVEInference.VULNERABILITY_PATTERNS:
                    patterns = CVEInference.VULNERABILITY_PATTERNS[vuln_type]
                    controls_set.update(patterns["nist_controls"])
            controls = sorted(list(controls_set))[:5]

        if not controls:
            controls = ["SI-2", "SC-7"]

        return controls[:5], CVEInference.infer_vulnerability_type(description)

    @staticmethod
    def infer_mitre_and_nist(cve_dict: dict) -> dict:
        """
        Suy luận MITRE techniques và NIST controls từ CVE dict

        Args:
            cve_dict: dict with 'id', 'description', etc.

        Returns:
            dict with inferred techniques and controls
        """
        cve_id = cve_dict.get("id", "UNKNOWN")
        description = cve_dict.get("description", "")

        # Try to get from description if available
        techniques, vuln_types = CVEInference.infer_mitre_techniques(description)
        controls, _ = CVEInference.infer_nist_controls(description)

        return {
            "cve_id": cve_id,
            "vulnerability_types": vuln_types,
            "mitre_techniques": techniques,
            "nist_controls": controls,
            "source": "inference",
        }


def infer_mitre_attack_info(cve_id: str, description: str = "") -> dict:
    """
    Suy luận MITRE techniques từ CVE ID và description
    Sử dụng CWE mapping cho analyst-grade quality

    Được gọi như một fallback khi database không có CVE này
    """
    cwe_ids = CVEInference.extract_cwe_from_description(description)

    if not cwe_ids:
        cwe_ids = CVEInference.infer_cwe_from_vulnerability_type(description)

    vuln_types = CVEInference.infer_vulnerability_type(description)

    # Technique name mapping
    technique_names = {
        "T1190": "Exploit Public-Facing Application",
        "T1505.003": "Web Shell",
        "T1059": "Command and Scripting Interpreter",
        "T1078": "Valid Accounts",
        "T1005": "Data from Local System",
        "T1083": "File and Directory Discovery",
        "T1548": "Abuse Elevation Control Mechanism",
        "T1499": "Endpoint Denial of Service",
        "T1040": "Traffic Sniffing",
        "T1557": "On-Path Attack",
        "T1203": "Exploitation for Client Execution",
        "T1189": "Drive-by Compromise",
        "T1187": "Forced Authentication",
    }

    # Tactic mapping per technique
    tactic_map = {
        "T1190": "Initial Access",
        "T1505.003": "Persistence",
        "T1059": "Execution",
        "T1078": "Credential Access",
        "T1005": "Discovery",
        "T1083": "Discovery",
        "T1548": "Privilege Escalation",
        "T1499": "Impact",
        "T1040": "Discovery",
        "T1557": "Discovery",
        "T1203": "Execution",
        "T1189": "Initial Access",
        "T1187": "Credential Access",
    }

    techniques = []
    if cwe_ids:
        tech_tuples, tactics = CVEInference.infer_mitre_from_cwe(cwe_ids, description)
        for tech_id, confidence, default_tactic in tech_tuples:
            tech_name = technique_names.get(tech_id, f"Technique {tech_id}")
            tactic = tactic_map.get(tech_id, default_tactic)
            techniques.append({
                "id": tech_id,
                "name": tech_name,
                "tactic": tactic,
                "confidence": round(confidence, 2),
                "description": f"Inferred from CWE: {', '.join(cwe_ids)}",
                "mitigations": [],
            })
    else:
        mitre_techniques, _ = CVEInference.infer_mitre_techniques(description)
        for tech_id in mitre_techniques:
            tech_name = technique_names.get(tech_id, f"Technique {tech_id}")
            tactic = tactic_map.get(tech_id, "Multiple")
            techniques.append({
                "id": tech_id,
                "name": tech_name,
                "tactic": tactic,
                "confidence": 0.75,
                "description": f"Inferred from {', '.join(vuln_types)} vulnerability type(s)",
                "mitigations": [],
            })

    return {
        "cve_id": cve_id,
        "techniques": techniques,
        "threat_actors": [],
        "vulnerability_types": vuln_types,
        "cwe_ids": cwe_ids,
        "source": "inference",
    }


def infer_nist_controls(cve_id: str, description: str = "") -> dict:
    """
    Suy luận NIST SP 800-53 controls từ CVE ID và description
    Sử dụng CWE mapping cho analyst-grade quality

    Được gọi như một fallback khi database không có CVE này
    """
    cwe_ids = CVEInference.extract_cwe_from_description(description)

    if not cwe_ids:
        cwe_ids = CVEInference.infer_cwe_from_vulnerability_type(description)

    vuln_types = CVEInference.infer_vulnerability_type(description)

    control_names = {
        "AC-3": "Access Enforcement",
        "AC-6": "Least Privilege",
        "CM-6": "Configuration Settings",
        "IA-2": "Authentication",
        "IA-5": "Password Management",
        "SI-2": "Flaw Remediation",
        "SI-3": "Malicious Code Protection",
        "SI-7": "Software, Firmware, and Information Integrity",
        "SI-10": "Information and Communication Protection",
        "SC-7": "Boundary Protection",
        "SC-8": "Transmission Confidentiality and Integrity",
        "SC-13": "Cryptographic Protection",
        "RA-5": "Vulnerability Scanning",
    }

    controls = []
    if cwe_ids:
        nist_controls = CVEInference.infer_nist_from_cwe(cwe_ids)
        for ctrl_id in nist_controls:
            ctrl_name = control_names.get(ctrl_id, f"Control {ctrl_id}")
            controls.append({
                "id": ctrl_id,
                "title": ctrl_name,
                "description": f"Recommended for CWE: {', '.join(cwe_ids)}",
                "family": ctrl_id.split("-")[0],
            })
    else:
        nist_controls, _ = CVEInference.infer_nist_controls(description)
        for ctrl_id in nist_controls:
            ctrl_name = control_names.get(ctrl_id, f"Control {ctrl_id}")
            controls.append({
                "id": ctrl_id,
                "title": ctrl_name,
                "description": f"Recommended for vulnerability type: {', '.join(vuln_types)}",
                "family": ctrl_id.split("-")[0],
            })

    return {
        "cve_id": cve_id,
        "controls": controls,
        "priority": "HIGH",
        "timeframe": "Immediate",
        "vulnerability_types": vuln_types,
        "cwe_ids": cwe_ids,
        "source": "inference",
    }
