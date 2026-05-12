"""
tools/cwe_mapper.py - Map CWE to MITRE ATT&CK techniques and NIST controls
"""
import json
import os
from typing import Dict, List, Optional

# CWE to MITRE ATT&CK mapping (based on MITRE's official mappings)
CWE_TO_MITRE = {
    # Remote Code Execution / Command Injection
    "20": ["T1190"],  # CWE-20 Improper Input Validation -> Exploit Public-Facing Application
    "77": ["T1059"],  # CWE-77 Improper Neutralization of Special Elements -> Command and Scripting Interpreter
    "78": ["T1059"],  # CWE-78 Improper Neutralization of Special Elements used in OS Command
    "95": ["T1059"],  # CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code
    "94": ["T1059"],  # CWE-94 Improper Control of Generation of Code
    "215": ["T1087"],  # CWE-215 Information Exposure Through Debug Information
    "400": ["T1498"],  # CWE-400 Uncontrolled Resource Consumption -> Network Denial of Service
    "502": ["T1190"],  # CWE-502 Deserialization of Untrusted Data -> Exploitation
    "917": ["T1190"],  # CWE-917 Expression Language Injection -> Exploit Public-Facing Application

    # Path Traversal
    "22": ["T1083"],  # CWE-22 Improper Limitation of a Pathname to a Restricted Directory -> File and Directory Discovery

    # SQL Injection
    "89": ["T1190"],  # CWE-89 SQL Injection -> Exploitation

    # Cross-Site Scripting
    "79": ["T1059"],  # CWE-79 Improper Neutralization of Input During Web Page Generation -> Scripting

    # Authentication/Authorization
    "287": ["T1078"],  # CWE-287 Improper Authentication -> Valid Accounts
    "269": ["T1548"],  # CWE-269 Improper Access Control -> Privilege Escalation

    # Privilege Escalation
    "250": ["T1548"],  # CWE-250 Execution with Unnecessary Privileges
    "672": ["T1078"],  # CWE-672 Operation on Resource After Expiration or Release

    # File Upload
    "434": ["T1190"],  # CWE-434 Unrestricted Upload of File with Dangerous Type

    # XML External Entity
    "611": ["T1190"],  # CWE-611 Improper Restriction of XML External Entity Reference

    # Default Credentials
    "521": ["T1078"],  # CWE-521 Weak Password Requirements

    # Missing Authentication / Authorization
    "306": ["T1190"],  # CWE-306 Missing Authentication -> Exploit Public-Facing Application
    "862": ["T1548"],  # CWE-862 Missing Authorization -> Privilege Escalation
    "639": ["T1548"],  # CWE-639 Authorization Bypass Through User-Controlled Key -> Privilege Escalation

    # Cryptography Issues
    "327": ["T1040"],  # CWE-327 Use of Broken/Risky Cryptographic Algorithm -> Traffic Sniffing
    "330": ["T1040"],  # CWE-330 Use of Insufficiently Random Values -> Traffic Sniffing

    # Information Exposure
    "200": ["T1526"],  # CWE-200 Exposure of Sensitive Information to an Unauthorized Actor -> Discovery
    "404": ["T1526"],  # CWE-404 Improper Resource Validation -> Discovery
    "532": ["T1526"],  # CWE-532 Insertion of Sensitive Information Into Log File -> Discovery

    # Injection Issues
    "116": ["T1059"],  # CWE-116 Improper Encoding/Escaping of Output -> Command Execution
    "917": ["T1190"],  # CWE-917 Expression Language Injection -> Exploit (already included)

    # Logic Flaws
    "862": ["T1548"],  # CWE-862 Missing Authorization (already included)
}

# Update existing entry to avoid duplicate
CWE_TO_MITRE["434"] = ["T1505.003", "T1190"]  # File upload -> Web Shell + Exploit

# CWE to NIST controls mapping
CWE_TO_NIST = {
    "20": ["SI-10", "SI-7"],  # Input validation -> Information System Monitoring, Software, Firmware, and Information Integrity
    "22": ["AC-3", "SI-4"],  # Path traversal -> Access Control, Information System Monitoring
    "77": ["SI-10"],  # Command injection -> Information System Monitoring
    "78": ["SI-10", "AC-6"],  # OS command -> Information System Monitoring, Least Privilege
    "79": ["SI-10", "SC-7"],  # XSS -> Information System Monitoring, Boundary Protection
    "89": ["SI-10", "SI-7"],  # SQL injection -> Information System Monitoring, Software Integrity
    "95": ["SI-10"],  # Code evaluation -> Information System Monitoring
    "287": ["IA-2", "IA-8"],  # Authentication -> Identification and Authentication, Identification and Authentication (Organization)
    "269": ["AC-3", "AC-6"],  # Improper access -> Access Control, Least Privilege
    "400": ["SC-5", "SC-7"],  # Resource consumption -> Denial of Service Protection, Boundary Protection
    "434": ["SI-10", "CM-5"],  # File upload -> Information System Monitoring, Configuration Change Control
    "502": ["SI-16"],  # Deserialization -> Memory Protection
    "611": ["SI-10"],  # XML XXE -> Information System Monitoring
    "917": ["SI-10"],  # Expression Language -> Information System Monitoring

    # Missing Authentication / Authorization (CRITICAL)
    "306": ["AC-3", "IA-2", "IA-8"],  # Missing auth -> Access Control, Authentication
    "862": ["AC-3", "AC-6"],  # Missing authz -> Access Control, Least Privilege
    "639": ["AC-3", "AC-4"],  # Authorization bypass -> Access Control, Information Flow Control

    # Cryptography Issues
    "327": ["SC-7", "SC-13"],  # Weak crypto -> Boundary Protection, Cryptographic Protection
    "330": ["SC-12", "SI-16"],  # Weak randomness -> Key Management, Memory Protection

    # Information Exposure
    "200": ["AC-3", "SI-4"],  # Info exposure -> Access Control, Information Monitoring
    "404": ["AC-3", "SI-4"],  # Resource validation -> Access Control, Monitoring
    "532": ["AU-2", "AU-12"],  # Log injection -> Audit and Accountability

    # Additional File Upload
    "434": ["SI-10", "CM-5", "SI-4"],  # File upload -> Monitoring, Change Control, Detection
}


class CWEMapper:
    """Map CWE IDs to MITRE ATT&CK techniques and NIST controls"""

    def __init__(self):
        """Initialize with MITRE and NIST data"""
        self.mitre_data = self._load_mitre_data()
        self.nist_data = self._load_nist_data()

    def _load_mitre_data(self) -> Dict:
        """Load MITRE ATT&CK database"""
        try:
            mitre_path = os.path.join(
                os.path.dirname(__file__),
                "..",
                "data",
                "mitre_attack.json"
            )
            with open(mitre_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load MITRE data: {e}")
            return {}

    def _load_nist_data(self) -> Dict:
        """Load NIST controls database"""
        try:
            nist_path = os.path.join(
                os.path.dirname(__file__),
                "..",
                "data",
                "nist_controls.json"
            )
            with open(nist_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load NIST data: {e}")
            return {}

    def cwe_to_mitre_techniques(self, cwe_id: str) -> List[Dict]:
        """
        Map CWE ID to MITRE ATT&CK techniques
        Returns list of techniques with details
        """
        cwe_num = cwe_id.replace("CWE-", "")
        technique_ids = CWE_TO_MITRE.get(cwe_num, [])

        techniques = []
        mitre_techniques = self.mitre_data.get("techniques", {})

        for tech_id in technique_ids:
            tech_data = mitre_techniques.get(tech_id, {})
            techniques.append({
                "id": tech_id,
                "name": tech_data.get("name", f"Technique {tech_id}"),
                "description": tech_data.get("description", ""),
                "tactics": tech_data.get("tactics", []),
            })

        return techniques

    def cwe_to_nist_controls(self, cwe_id: str) -> List[Dict]:
        """
        Map CWE ID to NIST controls
        Returns list of controls with details
        """
        cwe_num = cwe_id.replace("CWE-", "")
        control_ids = CWE_TO_NIST.get(cwe_num, [])

        controls = []
        nist_controls = self.nist_data.get("controls", {})

        for control_id in control_ids:
            control_data = nist_controls.get(control_id, {})
            controls.append({
                "id": control_id,
                "name": control_data.get("name", f"Control {control_id}"),
                "description": control_data.get("description", ""),
                "family": control_data.get("family", ""),
            })

        return controls

    def analyze_cwe_ids(self, cwe_ids: List[str]) -> Dict:
        """
        Analyze multiple CWE IDs and aggregate their mappings
        Returns comprehensive analysis
        """
        all_techniques = {}
        all_controls = {}

        for cwe_id in cwe_ids:
            # Get MITRE techniques
            techniques = self.cwe_to_mitre_techniques(cwe_id)
            for tech in techniques:
                tech_id = tech["id"]
                if tech_id not in all_techniques:
                    all_techniques[tech_id] = tech

            # Get NIST controls
            controls = self.cwe_to_nist_controls(cwe_id)
            for ctrl in controls:
                ctrl_id = ctrl["id"]
                if ctrl_id not in all_controls:
                    all_controls[ctrl_id] = ctrl

        return {
            "cwe_ids": cwe_ids,
            "mitre_techniques": list(all_techniques.values()),
            "nist_controls": list(all_controls.values()),
            "total_techniques": len(all_techniques),
            "total_controls": len(all_controls),
        }


def get_cwe_analysis(cve_dict: Dict) -> Dict:
    """
    Get complete CWE analysis for a CVE
    Integrates with parse_cve_metadata output
    """
    mapper = CWEMapper()
    cwe_ids = cve_dict.get("cwe_ids", [])

    if not cwe_ids:
        return {
            "cwe_ids": [],
            "mitre_techniques": [],
            "nist_controls": [],
        }

    return mapper.analyze_cwe_ids(cwe_ids)
