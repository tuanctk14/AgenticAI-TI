"""
tools/vuln_ontology.py - Vulnerability Ontology Layer

Semantic normalization: command injection → RCE, arbitrary execution → RCE, etc.
This is the foundation for stable vulnerability classification.
"""

# Vulnerability Ontology - normalize various vulnerability descriptions to canonical classes
VULN_CLASSES = {
    "RCE": {
        "keywords": [
            "remote code execution", "rce", "arbitrary code execution",
            "command injection", "shell execution", "shell injection",
            "unsafe eval", "arbitrary command execution", "code injection",
            "os command injection", "system command injection",
            "execute arbitrary code", "arbitrary execution"
        ],
        "cwe_ids": ["CWE-78", "CWE-94", "CWE-95", "CWE-502"],
        "mitre_techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
            {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
        ],
        "nist_controls": ["AC-3", "CM-6", "SI-3", "SI-2"],
        "confidence": 0.92,
    },

    "SQLI": {
        "keywords": [
            "sql injection", "sqli", "sql query injection",
            "sql command injection", "database injection",
            "unsafe sql", "sql concatenation"
        ],
        "cwe_ids": ["CWE-89"],
        "mitre_techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
            {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement"},
        ],
        "nist_controls": ["AC-3", "SI-2", "SI-10"],
        "confidence": 0.90,
    },

    "XSS": {
        "keywords": [
            "cross-site scripting", "xss", "cross site scripting",
            "script injection", "html injection", "dom-based xss",
            "stored xss", "reflected xss"
        ],
        "cwe_ids": ["CWE-79"],
        "mitre_techniques": [
            {"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"},
            {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
        ],
        "nist_controls": ["AC-3", "SI-7", "SC-7"],
        "confidence": 0.88,
    },

    "LFI": {
        "keywords": [
            "local file inclusion", "lfi", "file inclusion",
            "path traversal", "directory traversal", "path disclosure",
            "file access", "arbitrary file read", "file enumeration"
        ],
        "cwe_ids": ["CWE-22", "CWE-23"],
        "mitre_techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
            {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
        ],
        "nist_controls": ["AC-3", "AC-6", "SI-7"],
        "confidence": 0.85,
    },

    "FILE_UPLOAD": {
        "keywords": [
            "arbitrary file upload", "unrestricted file upload",
            "file upload", "upload validation", "file type bypass",
            "upload rce", "upload vulnerability"
        ],
        "cwe_ids": ["CWE-434"],
        "mitre_techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
            {"id": "T1505.003", "name": "Web Shell", "tactic": "Persistence"},
        ],
        "nist_controls": ["AC-3", "SI-10", "SC-5"],
        "confidence": 0.87,
    },

    "AUTH_BYPASS": {
        "keywords": [
            "authentication bypass", "auth bypass", "password bypass",
            "authorization bypass", "broken authentication",
            "missing authentication", "weak authentication",
            "default credentials", "hardcoded password"
        ],
        "cwe_ids": ["CWE-287", "CWE-306"],
        "mitre_techniques": [
            {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
        ],
        "nist_controls": ["AC-2", "AC-3", "IA-2"],
        "confidence": 0.88,
    },

    "PRIVILEGE_ESCALATION": {
        "keywords": [
            "privilege escalation", "privilege elevation",
            "privilege escalation", "elevation of privilege", "eop",
            "unauthorized access", "unauthorized privileges",
            "escalate", "escalation"
        ],
        "cwe_ids": ["CWE-250", "CWE-269"],
        "mitre_techniques": [
            {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
        ],
        "nist_controls": ["AC-3", "AC-6", "SC-7"],
        "confidence": 0.89,
    },

    "DESERIALIZATION": {
        "keywords": [
            "deserialization", "insecure deserialization",
            "serialization", "object deserialization",
            "gadget chain", "unsafe deserialization"
        ],
        "cwe_ids": ["CWE-502"],
        "mitre_techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        ],
        "nist_controls": ["AC-3", "CM-6", "SI-3"],
        "confidence": 0.90,
    },

    "MEMORY_CORRUPTION": {
        "keywords": [
            "buffer overflow", "buffer overrun", "heap overflow",
            "stack overflow", "use-after-free", "memory corruption",
            "null pointer", "integer overflow", "out-of-bounds"
        ],
        "cwe_ids": ["CWE-787", "CWE-119", "CWE-416"],
        "mitre_techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
            {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
        ],
        "nist_controls": ["AC-3", "CM-6", "SI-3"],
        "confidence": 0.86,
    },

    "XXEA": {
        "keywords": [
            "xxe", "xml external entity", "external entity injection",
            "xml injection", "entity expansion", "xml bomb"
        ],
        "cwe_ids": ["CWE-611"],
        "mitre_techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        ],
        "nist_controls": ["AC-3", "SI-10"],
        "confidence": 0.85,
    },

    "CSRF": {
        "keywords": [
            "cross-site request forgery", "csrf", "cross site request forgery",
            "request forgery", "unvalidated redirects"
        ],
        "cwe_ids": ["CWE-352"],
        "mitre_techniques": [
            {"id": "T1583", "name": "Acquire Infrastructure", "tactic": "Resource Development"},
        ],
        "nist_controls": ["AC-3", "SI-2"],
        "confidence": 0.82,
    },

    "INFORMATION_DISCLOSURE": {
        "keywords": [
            "information disclosure", "data disclosure", "sensitive data exposure",
            "data leak", "confidentiality", "credential disclosure",
            "api key disclosure", "secret exposure"
        ],
        "cwe_ids": ["CWE-200"],
        "mitre_techniques": [
            {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access"},
            {"id": "T1590", "name": "Gather Victim Network Information", "tactic": "Reconnaissance"},
        ],
        "nist_controls": ["AC-3", "AU-2", "SC-7"],
        "confidence": 0.80,
    },
}


def classify_vulnerability(description: str, cwe_ids: list = None) -> dict:
    """
    Classify vulnerability using ontology.

    Returns: {
        class: "RCE" | "SQLI" | ...,
        confidence: float (0.0-1.0),
        matched_keywords: [list of matched keywords],
        source: "keyword_match" | "cwe_match" | "fallback"
    }
    """
    if not description and not cwe_ids:
        return {
            "class": None,
            "confidence": 0.0,
            "matched_keywords": [],
            "source": "none"
        }

    desc_lower = description.lower() if description else ""

    # Phase 1: Try CWE-based classification (higher confidence)
    if cwe_ids:
        for vuln_class, vuln_info in VULN_CLASSES.items():
            class_cwe_ids = set(vuln_info.get("cwe_ids", []))
            input_cwe_ids = set(cwe_ids)

            if class_cwe_ids & input_cwe_ids:  # intersection
                return {
                    "class": vuln_class,
                    "confidence": vuln_info.get("confidence", 0.80),
                    "matched_keywords": list(class_cwe_ids & input_cwe_ids),
                    "source": "cwe_match"
                }

    # Phase 2: Keyword-based classification
    for vuln_class, vuln_info in VULN_CLASSES.items():
        keywords = vuln_info.get("keywords", [])
        matched = [kw for kw in keywords if kw in desc_lower]

        if matched:
            return {
                "class": vuln_class,
                "confidence": vuln_info.get("confidence", 0.80),
                "matched_keywords": matched,
                "source": "keyword_match"
            }

    # No match found
    return {
        "class": None,
        "confidence": 0.0,
        "matched_keywords": [],
        "source": "none"
    }


def get_vuln_class_info(vuln_class: str) -> dict:
    """Get full ontology info for a vulnerability class."""
    return VULN_CLASSES.get(vuln_class, {})


def get_all_vuln_classes() -> list:
    """Get list of all vulnerability classes."""
    return list(VULN_CLASSES.keys())
