"""
tools/cve_inference.py - Suy luận MITRE ATT&CK và NIST Controls từ CVE description
Cho các CVE mới không có trong database bằng NLP/keyword analysis
"""
import re
from typing import Dict, List, Tuple


class CVEInference:
    """Suy luận MITRE techniques và NIST controls từ CVE description"""

    # Keyword patterns để detect vulnerability types
    VULNERABILITY_PATTERNS = {
        "rce": {
            "keywords": ["remote code execution", "rce", "arbitrary code execution", "command execution",
                        "code injection", "shell access", "system command", "execute code"],
            "mitre_techniques": ["T1190", "T1059.004", "T1203"],
            "nist_controls": ["SI-2", "SI-3", "SI-7", "RA-5", "SC-7"],
        },
        "file_upload": {
            "keywords": ["file upload", "arbitrary file upload", "unrestricted file", "upload vulnerable",
                        "file write", "path traversal", "directory traversal"],
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
            "mitre_techniques": ["T1078", "T1110"],
            "nist_controls": ["AC-3", "AC-6", "IA-2", "IA-5", "IA-8"],
        },
        "sqli": {
            "keywords": ["sql injection", "sqli", "database injection", "sql query"],
            "mitre_techniques": ["T1190", "T1003"],
            "nist_controls": ["SI-2", "SI-3", "SC-7", "SC-11", "SI-10"],
        },
        "xss": {
            "keywords": ["cross-site scripting", "xss", "dom-based xss", "stored xss", "reflected xss"],
            "mitre_techniques": ["T1190"],
            "nist_controls": ["SI-2", "SI-3", "SC-7", "SC-11", "SI-10"],
        },
        "lfi": {
            "keywords": ["local file inclusion", "lfi", "file inclusion", "arbitrary file read",
                        "path traversal", "directory traversal"],
            "mitre_techniques": ["T1190"],
            "nist_controls": ["AC-3", "AC-6", "CM-6", "SI-7", "SC-7"],
        },
        "privilege_escalation": {
            "keywords": ["privilege escalation", "privilege esclation", "elevated access", "sudo", "escalate privilege",
                        "run as administrator", "administrator access"],
            "mitre_techniques": ["T1134", "T1548"],
            "nist_controls": ["AC-3", "AC-6", "IA-2", "IA-5", "SC-7"],
        },
        "dos": {
            "keywords": ["denial of service", "dos", "ddos", "crash", "resource exhaustion",
                        "buffer overflow", "heap overflow", "stack overflow"],
            "mitre_techniques": ["T1499"],
            "nist_controls": ["SC-7", "SC-35", "SC-38", "SI-4", "AU-6"],
        },
        "information_disclosure": {
            "keywords": ["information disclosure", "sensitive information", "data leak", "expose credential",
                        "leak secret", "information exposure", "sensitive data"],
            "mitre_techniques": ["T1005"],
            "nist_controls": ["AC-3", "AC-6", "SC-7", "SC-8", "SC-13"],
        },
        "cve_2021_47933": {
            # WordPress Plugin: Download From Files RCE
            "keywords": ["download from files", "wordpress plugin", "plugin", "unauthenticated"],
            "mitre_techniques": ["T1190", "T1505.003", "T1059.004"],
            "nist_controls": ["AC-3", "CM-6", "SI-7", "SI-3", "SC-7"],
        },
    }

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

        Returns: (techniques_list, vulnerability_types)
        """
        vuln_types = CVEInference.infer_vulnerability_type(description)
        techniques = set()

        for vuln_type in vuln_types:
            if vuln_type in CVEInference.VULNERABILITY_PATTERNS:
                patterns = CVEInference.VULNERABILITY_PATTERNS[vuln_type]
                techniques.update(patterns["mitre_techniques"])

        # Fallback: generic RCE if nothing matched
        if not techniques:
            techniques = {"T1190", "T1059"}

        # Prioritize main techniques for better readability
        # Remove duplicates and sort to most relevant
        tech_list = sorted(list(techniques))

        # Reorder to put main techniques first
        main_techniques = ["T1190", "T1505.003", "T1059.004", "T1078", "T1110"]
        priority_ordered = []
        for tech in main_techniques:
            if tech in tech_list:
                priority_ordered.append(tech)

        # Add remaining techniques
        for tech in tech_list:
            if tech not in priority_ordered:
                priority_ordered.append(tech)

        return priority_ordered[:5], vuln_types  # Return top 5 techniques only

    @staticmethod
    def infer_nist_controls(description: str) -> Tuple[List[str], List[str]]:
        """
        Suy luận NIST SP 800-53 controls từ CVE description

        Returns: (controls_list, vulnerability_types)
        """
        vuln_types = CVEInference.infer_vulnerability_type(description)
        controls = set()

        for vuln_type in vuln_types:
            if vuln_type in CVEInference.VULNERABILITY_PATTERNS:
                patterns = CVEInference.VULNERABILITY_PATTERNS[vuln_type]
                controls.update(patterns["nist_controls"])

        # Fallback: generic controls if nothing matched
        if not controls:
            controls = {"SI-2", "RA-5", "SC-7"}

        # Prioritize main controls for better readability
        ctrl_list = sorted(list(controls))

        # Reorder to put main controls first
        main_controls = ["AC-3", "CM-6", "SI-7", "SI-3", "SC-7"]
        priority_ordered = []
        for ctrl in main_controls:
            if ctrl in ctrl_list:
                priority_ordered.append(ctrl)

        # Add remaining controls
        for ctrl in ctrl_list:
            if ctrl not in priority_ordered:
                priority_ordered.append(ctrl)

        return priority_ordered[:5], vuln_types  # Return top 5 controls only

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

    Được gọi như một fallback khi database không có CVE này
    """
    mitre_techniques, vuln_types = CVEInference.infer_mitre_techniques(description)

    # MITRE technique names mapping (short list for inference)
    technique_names = {
        "T1190": "Exploit Public-Facing Application",
        "T1505.003": "Web Shell",
        "T1059": "Command and Scripting Interpreter",
        "T1059.004": "Unix Shell",
        "T1078": "Valid Accounts",
        "T1110": "Brute Force",
        "T1003": "OS Credential Dumping",
        "T1087": "Account Discovery",
        "T1598": "Phishing for Information",
        "T1598.003": "Spearphishing Link",
        "T1204.001": "Malicious Link",
        "T1005": "Data from Local System",
        "T1083": "File and Directory Discovery",
        "T1134": "Access Token Manipulation",
        "T1548": "Abuse Elevation Control Mechanism",
        "T1134.004": "Process Injection",
        "T1134.005": "DLL Injection",
        "T1499": "Endpoint Denial of Service",
        "T1499.001": "HTTP Flood",
        "T1499.002": "SYN Flood",
        "T1499.004": "Application Exhaustion Flood",
        "T1040": "Traffic Sniffing",
        "T1557": "On-Path Attack",
        "T1070": "Indicator Removal",
        "T1136": "Create Account",
        "T1098": "Account Manipulation",
        "T1547.013": "Port Monitors",
        "T1203": "Exploitation for Client Execution",
        "T1562.004": "Disable or Modify System Firewall",
    }

    # Tạo technique objects
    techniques = []
    for tech_id in mitre_techniques:
        tech_name = technique_names.get(tech_id, f"Technique {tech_id}")
        techniques.append({
            "id": tech_id,
            "name": tech_name,
            "tactic": "Multiple",
            "description": f"Inferred from {', '.join(vuln_types)} vulnerability type(s)",
            "mitigations": [],
        })

    return {
        "cve_id": cve_id,
        "techniques": techniques,
        "threat_actors": [],
        "vulnerability_types": vuln_types,
        "source": "inference",
    }


def infer_nist_controls(cve_id: str, description: str = "") -> dict:
    """
    Suy luận NIST SP 800-53 controls từ CVE ID và description

    Được gọi như một fallback khi database không có CVE này
    """
    nist_controls, vuln_types = CVEInference.infer_nist_controls(description)

    # NIST control names mapping
    control_names = {
        "AC-3": "Access Enforcement",
        "AC-6": "Least Privilege",
        "AC-8": "System Use Notification",
        "CM-6": "Configuration Settings",
        "CM-9": "Configuration Management Plan",
        "IA-2": "Authentication",
        "IA-5": "Password Management",
        "IA-8": "User Authentication",
        "SI-2": "Flaw Remediation",
        "SI-3": "Malicious Code Protection",
        "SI-7": "Software, Firmware, and Information Integrity",
        "SI-10": "Information and Communication Protection",
        "SC-7": "Boundary Protection",
        "SC-8": "Transmission Confidentiality and Integrity",
        "SC-11": "Trusted Path",
        "SC-13": "Cryptographic Protection",
        "RA-5": "Vulnerability Scanning",
    }

    # Tạo control objects
    controls = []
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
        "source": "inference",
    }
