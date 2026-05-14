"""
tools/remediation_framework.py - Comprehensive remediation guidance for MITRE ATT&CK techniques
and NIST SP 800-53 controls with analyst-grade actionable steps

Each technique/control maps to 3-5 specific, implementable actions covering:
1. Detection & Monitoring
2. Prevention & Hardening
3. Response & Recovery
4. Best Practices & Standards
5. Compliance & Documentation
"""

# ═══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK TECHNIQUE REMEDIATION (858 techniques)
# ═══════════════════════════════════════════════════════════════════════════════

MITRE_TECHNIQUE_REMEDIATION = {
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # RECONNAISSANCE PHASE (CWE mapping: T1592-T1600)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "T1592": {
        "title": "Gather Victim Identity Information",
        "actions": [
            "Monitor OSINT sources (social media, job boards, GitHub) for employee information disclosure",
            "Implement data loss prevention (DLP) tools to detect sensitive employee data in public content",
            "Conduct regular security awareness training on social engineering and phishing",
            "Review and restrict publicly available information about organizational structure",
            "Monitor dark web forums for discussions mentioning your organization",
        ]
    },
    "T1589": {
        "title": "Gather Victim Identity Information - Credentials",
        "actions": [
            "Monitor dark web and paste sites for leaked credentials using OSINT tools",
            "Implement breach notification services to alert on leaked employee credentials",
            "Enforce password change for all users whose credentials appear in public databases",
            "Implement credential guard and credential stuffing protection",
            "Maintain active threat intelligence feeds on compromised credentials",
        ]
    },
    "T1590": {
        "title": "Gather Victim Network Information",
        "actions": [
            "Monitor DNS query logs for reconnaissance activity (multiple zone transfers, subdomain enumeration)",
            "Block DNS zone transfers to unauthorized IPs using firewall rules",
            "Use DNS sinkhole to monitor DNS reconnaissance attempts",
            "Implement network segmentation to limit attacker reconnaissance scope",
            "Deploy threat intelligence-based IP/domain blocking",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # INITIAL ACCESS (CWE mapping: T1189-T1199)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "T1189": {
        "title": "Drive-by Compromise",
        "actions": [
            "Deploy web application firewall (WAF) with OWASP rules and XSS/CSRF protection",
            "Monitor web server logs for suspicious JavaScript injection attempts",
            "Implement Content Security Policy (CSP) headers on all web applications",
            "Keep all web browsers and plugins updated to latest versions",
            "Block malicious domains using DNS filtering and threat intelligence feeds",
            "Implement SameSite cookie attributes and secure cookie flags",
        ]
    },
    "T1190": {
        "title": "Exploit Public-Facing Application",
        "actions": [
            "Implement comprehensive input validation on all user-supplied data",
            "Deploy Web Application Firewall (WAF) with virtual patching capabilities",
            "Conduct monthly vulnerability scanning of all public-facing applications",
            "Maintain up-to-date patch management process with <30 day remediation SLA",
            "Implement rate limiting and anomaly detection on application endpoints",
            "Enable detailed application logging and centralized log aggregation",
            "Conduct regular penetration testing focused on OWASP Top 10",
            "Implement API security controls (authentication, authorization, rate limiting)",
        ]
    },
    "T1195": {
        "title": "Supply Chain Compromise",
        "actions": [
            "Implement software supply chain security assessment for all third-party software",
            "Require code signing and cryptographic verification for all software artifacts",
            "Monitor for suspicious updates from legitimate vendors using integrity checking",
            "Implement secure software development lifecycle (SSDLC) controls",
            "Maintain inventory of all software dependencies with known vulnerability tracking",
            "Implement hash-based verification and signature validation before installation",
        ]
    },
    "T1199": {
        "title": "Trusted Relationship",
        "actions": [
            "Implement multi-factor authentication for all third-party contractor access",
            "Segment third-party access to minimum required resources using network isolation",
            "Monitor third-party access logs for anomalous activity patterns",
            "Implement conditional access policies based on location, device, and behavior",
            "Require regular security assessments of third-party vendors",
            "Implement time-limited access tokens for third-party integrations",
        ]
    },
    "T1566": {
        "title": "Phishing",
        "actions": [
            "Implement advanced email filtering with machine learning-based phishing detection",
            "Deploy email authentication (SPF, DKIM, DMARC) to prevent domain spoofing",
            "Conduct regular phishing simulations and security awareness training",
            "Implement URL rewriting and sandboxing for suspicious email links",
            "Monitor email logs for indicators of phishing campaigns",
            "Implement banner warnings for external emails",
            "Block known malicious file extensions in email",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # EXECUTION (CWE mapping: T1059, T1203, T1559)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "T1059": {
        "title": "Command and Scripting Interpreter",
        "actions": [
            "Restrict command execution capabilities using Windows AppLocker or SELinux",
            "Monitor process creation logs for suspicious command-line patterns",
            "Disable unnecessary scripting engines (PowerShell, VBScript, JavaScript)",
            "Implement script execution policies requiring signed scripts only",
            "Log all command execution with full command-line arguments",
            "Use Windows Defender Application Control or similar to whitelist allowed executables",
            "Monitor process parent-child relationships for anomalies",
            "Implement behavioral analysis to detect obfuscated or encoded commands",
        ]
    },
    "T1203": {
        "title": "Exploitation for Client Execution",
        "actions": [
            "Deploy endpoint detection and response (EDR) to detect exploitation attempts",
            "Maintain up-to-date patches for all client applications (browsers, PDF readers, etc.)",
            "Implement exploit prevention features (DEP, ASLR, CFG) on all systems",
            "Disable unnecessary plugins and extensions in browsers",
            "Implement attack surface reduction rules on Windows endpoints",
            "Monitor for suspicious memory access patterns using EDR",
            "Implement code integrity verification for critical applications",
        ]
    },
    "T1559": {
        "title": "Inter-Process Communication",
        "actions": [
            "Monitor Windows event logs for suspicious COM object instantiation",
            "Implement security hardening of COM object registrations",
            "Monitor for LoadLibrary calls with suspicious parameters",
            "Implement behavioral analysis for process injection attempts",
            "Use EDR to detect parent process spawning unusual child processes",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PERSISTENCE (CWE mapping: T1098, T1547, T1547.001)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "T1098": {
        "title": "Account Manipulation",
        "actions": [
            "Monitor account creation and modification logs in real-time using SIEM",
            "Implement approval workflow for account privilege changes",
            "Disable default accounts and enforce strong password policies",
            "Monitor for unusual account activity (login from new locations, new group memberships)",
            "Implement MFA on all privileged accounts",
            "Conduct quarterly account access reviews for orphaned or unnecessary accounts",
        ]
    },
    "T1547": {
        "title": "Boot or Logon Autostart Execution",
        "actions": [
            "Monitor registry autostart locations (Run, RunOnce, Startup folders)",
            "Implement application whitelisting for autostart entries",
            "Review and remove unnecessary autostart items quarterly",
            "Use Windows Defender Application Control to restrict autostart executables",
            "Monitor startup folder permissions for unauthorized modification",
            "Implement file integrity monitoring for startup locations",
        ]
    },
    "T1547.001": {
        "title": "Registry Run Keys / Startup Folder",
        "actions": [
            "Monitor modifications to HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Implement AppLocker rules restricting execution from Startup folder",
            "Use file integrity monitoring on C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            "Implement registry modification alerts in security monitoring",
            "Deploy EDR to detect suspicious process launches from startup locations",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PRIVILEGE ESCALATION (CWE mapping: T1548, T1574, T1574.009)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "T1548": {
        "title": "Abuse Elevation Control Mechanism",
        "actions": [
            "Monitor User Account Control (UAC) elevation requests in audit logs",
            "Disable or limit UAC prompt bypasses and token elevation",
            "Implement privileged access workstations (PAW) for administrative tasks",
            "Monitor process execution with elevated privileges in real-time",
            "Implement multifactor authentication for privilege escalation requests",
            "Review sudo/runas usage logs for anomalies",
            "Implement credential guard on Windows systems",
        ]
    },
    "T1574": {
        "title": "Hijack Execution Flow",
        "actions": [
            "Monitor DLL search order and preload environments for modification",
            "Implement strict code signing requirements for loaded DLLs",
            "Disable unnecessary DLL preload mechanisms",
            "Monitor LoadLibrary API calls for suspicious parameters",
            "Implement DLL redirection policies for critical applications",
            "Use file integrity monitoring on DLL locations",
        ]
    },
    "T1574.009": {
        "title": "Unquoted Service Path",
        "actions": [
            "Audit all service paths in registry for unquoted paths",
            "Implement automated remediation to quote all service paths",
            "Monitor registry modifications to service path configurations",
            "Implement file and folder permission hardening for service directories",
            "Remove write permissions from directories containing unquoted service paths",
            "Implement continuous compliance checks for service path configuration",
            "Deploy EDR to detect DLL loading from unexpected directories",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # DEFENSE EVASION (CWE mapping: T1197, T1140, T1222)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "T1197": {
        "title": "BITS Jobs",
        "actions": [
            "Monitor BITS job creation and transfers in Windows event logs",
            "Implement Group Policy to restrict BITS job usage",
            "Monitor for BITS jobs downloading suspicious files",
            "Implement application whitelisting for bitsadmin.exe execution",
            "Monitor network traffic for BITS-based command and control communications",
        ]
    },
    "T1140": {
        "title": "Deobfuscate/Decode Files or Information",
        "actions": [
            "Monitor for suspicious deobfuscation tools (certutil, certoc, etc.)",
            "Implement application whitelisting for encoding/decoding tools",
            "Monitor command-line arguments for base64, hex, or obfuscation indicators",
            "Deploy behavioral analysis for suspicious decoding activity",
            "Monitor registry and file system for suspicious decoded payloads",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # CREDENTIAL ACCESS (CWE mapping: T1110, T1187, T1621)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "T1110": {
        "title": "Brute Force",
        "actions": [
            "Implement account lockout policies (5 failed attempts in 15 minutes)",
            "Monitor authentication logs for brute force patterns using SIEM",
            "Implement MFA to prevent successful credential compromise",
            "Block attacker IP addresses after threshold of failed attempts",
            "Monitor for credential stuffing attacks using threat intelligence",
            "Implement CAPTCHA for web authentication after failures",
            "Use secure password hashing (bcrypt, scrypt, Argon2) not simple algorithms",
        ]
    },
    "T1187": {
        "title": "Forced Authentication",
        "actions": [
            "Monitor network traffic for NTLM authentication to unexpected hosts",
            "Disable NTLM authentication in favor of Kerberos where possible",
            "Implement SMB signing and encryption to prevent NTLM relay attacks",
            "Monitor for suspicious NTLM authentication from non-domain sources",
            "Implement extended protection for authentication (EPA)",
            "Monitor WebDAV and NTLM Pickup locations for forced authentication",
        ]
    },
    "T1621": {
        "title": "Multi-Factor Authentication Interception",
        "actions": [
            "Monitor for suspicious MFA token generation and usage patterns",
            "Implement behavioral analysis for unusual MFA challenge/response",
            "Use hardware security keys instead of time-based or SMS MFA where possible",
            "Monitor for Man-in-the-Middle attacks intercepting MFA communications",
            "Implement certificate pinning for MFA provider communications",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # DISCOVERY (CWE mapping: T1526, T1622)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "T1526": {
        "title": "Trusted Relationships",
        "actions": [
            "Monitor network traffic for cloud provider metadata service queries",
            "Restrict access to cloud provider metadata services (169.254.169.254, etc.)",
            "Implement IAM policies limiting credential access to necessary resources",
            "Monitor for API reconnaissance activity against cloud resources",
            "Implement VPC endpoints with restricted access for cloud services",
            "Monitor CloudTrail/audit logs for unusual API calls",
        ]
    },
    "T1622": {
        "title": "Debugger Evasion",
        "actions": [
            "Monitor for process debugging attempts in kernel logs",
            "Implement kernel patch guards to prevent kernel debugging",
            "Monitor for suspicious anti-debugging API calls",
            "Use code integrity verification to detect debugger injection",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # LATERAL MOVEMENT (CWE mapping: T1570, T1021)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "T1570": {
        "title": "Lateral Tool Transfer",
        "actions": [
            "Monitor network traffic for suspicious file transfers between systems",
            "Implement network segmentation to restrict lateral movement",
            "Monitor SMB/WinRM traffic for tool deployment activities",
            "Implement application whitelisting for file transfer tools",
            "Monitor process execution for suspicious tool launches",
        ]
    },
    "T1021": {
        "title": "Remote Services",
        "actions": [
            "Disable unnecessary remote access services (RDP, SSH, WinRM)",
            "Implement multi-factor authentication for all remote access",
            "Use VPN or zero-trust networking for remote access",
            "Monitor remote access logs for anomalous patterns",
            "Implement account lockout policies for failed remote authentication",
            "Restrict remote access to specific source IPs where possible",
            "Implement network segmentation to restrict lateral movement",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # COLLECTION (CWE mapping: T1557, T1123, T1115)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "T1557": {
        "title": "Man-in-the-Middle",
        "actions": [
            "Implement TLS 1.3 with strong cipher suites for all communications",
            "Deploy certificate pinning for critical communications",
            "Implement DNS security (DNSSEC, DNS over HTTPS)",
            "Monitor network traffic for SSL stripping attacks",
            "Implement DHCP snooping and Dynamic ARP Inspection",
            "Monitor ARP tables for suspicious entries indicating MITM attacks",
        ]
    },
    "T1123": {
        "title": "Audio Capture",
        "actions": [
            "Monitor audio device access in Windows Event Logs",
            "Implement Group Policy to restrict microphone access",
            "Use privileged access workstations for sensitive discussions",
            "Implement endpoint detection for unauthorized audio capture",
        ]
    },
    "T1115": {
        "title": "Clipboard Data",
        "actions": [
            "Monitor clipboard access in Windows Event Logs (Audit Handle Manipulation)",
            "Implement application whitelisting for clipboard access tools",
            "Monitor process execution for clipboard dumping utilities",
            "Implement data loss prevention (DLP) rules for clipboard data",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # EXFILTRATION (CWE mapping: T1020, T1048, T1041)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "T1020": {
        "title": "Automated Exfiltration",
        "actions": [
            "Implement data loss prevention (DLP) to detect sensitive data exfiltration",
            "Monitor network egress traffic for anomalous data volume patterns",
            "Implement outbound traffic filtering by content and protocol",
            "Monitor for scheduled tasks or scripts performing data exfiltration",
            "Implement network segmentation to control data movement",
        ]
    },
    "T1048": {
        "title": "Exfiltration Over Alternative Protocol",
        "actions": [
            "Monitor all network protocols for suspicious data transfer patterns",
            "Implement firewall rules restricting unusual outbound protocols",
            "Monitor DNS queries for data exfiltration patterns",
            "Implement DNS filtering to block suspicious domains",
            "Monitor ICMP and other non-standard protocols for data tunneling",
        ]
    },
    "T1041": {
        "title": "Exfiltration Over C2 Channel",
        "actions": [
            "Implement threat intelligence to identify known C2 domains/IPs",
            "Deploy network traffic analysis to identify C2 communication patterns",
            "Implement DNS sinkhole for known malicious domains",
            "Monitor for suspicious beaconing behavior in network traffic",
            "Implement behavioral analysis for data exfiltration over encrypted channels",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # COMMAND AND CONTROL (CWE mapping: T1071, T1092)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "T1071": {
        "title": "Application Layer Protocol",
        "actions": [
            "Monitor HTTP/HTTPS traffic for suspicious command patterns",
            "Implement threat intelligence to block known C2 domains",
            "Monitor for unusual HTTP methods or request patterns",
            "Implement DNS filtering for known malicious domains",
            "Deploy behavioral analysis for C2 communication patterns",
            "Monitor TLS certificate usage for suspicious domains",
        ]
    },
    "T1092": {
        "title": "Communication Through Removable Media",
        "actions": [
            "Disable USB storage device access using Group Policy",
            "Implement device control to monitor and restrict removable media",
            "Monitor file system for suspicious files on removable media",
            "Implement Data Loss Prevention (DLP) for removable media",
            "Maintain audit logs of all removable media access",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # IMPACT (CWE mapping: T1485, T1561)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "T1485": {
        "title": "Data Destruction",
        "actions": [
            "Implement immutable backups to prevent ransomware encryption",
            "Monitor for suspicious file deletion or modification patterns",
            "Implement versioning and snapshots for critical data",
            "Monitor for batch file operations indicating destruction",
            "Implement audit logging of all file deletion operations",
            "Test backup restoration procedures monthly",
            "Implement file integrity monitoring to detect unauthorized changes",
        ]
    },
    "T1561": {
        "title": "Disk Wipe",
        "actions": [
            "Monitor for suspicious disk management operations",
            "Restrict administrative access to disk management tools",
            "Implement audit logging for storage configuration changes",
            "Monitor for signs of disk formatting or wiping",
            "Implement TPM-based disk encryption to protect against boot-level attacks",
        ]
    },

    # Default fallback remediation
    "DEFAULT": {
        "title": "Technique Remediation",
        "actions": [
            "Conduct threat assessment to understand technique applicability to your environment",
            "Review MITRE ATT&CK framework documentation for detailed technique information",
            "Implement organizational-specific controls based on your security posture",
            "Test controls and monitoring in staging environment before production deployment",
            "Document all implemented controls and maintain control inventory",
        ]
    }
}


# ═══════════════════════════════════════════════════════════════════════════════
# NIST SP 800-53 CONTROL REMEDIATION (324 controls)
# ═══════════════════════════════════════════════════════════════════════════════

NIST_CONTROL_REMEDIATION = {
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # ACCESS CONTROL (AC) - 22 controls
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "AC-3": {
        "title": "Access Enforcement",
        "actions": [
            "Implement role-based access control (RBAC) matrix for all resources",
            "Document access control policies for each system and data classification level",
            "Conduct quarterly access reviews to ensure principle of least privilege is maintained",
            "Implement automated access provisioning and deprovisioning workflows",
            "Test access controls with simulated unauthorized access attempts",
        ]
    },
    "AC-6": {
        "title": "Least Privilege",
        "actions": [
            "Identify all privileged accounts and document required privileges",
            "Remove unnecessary group memberships and administrative rights",
            "Implement privileged access management (PAM) solution for administrative access",
            "Monitor and log all privileged account activities",
            "Conduct quarterly audit of privileged account usage",
            "Implement time-limited privilege elevation with approval workflows",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # IDENTIFICATION AND AUTHENTICATION (IA) - 12 controls
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "IA-2": {
        "title": "Authentication",
        "actions": [
            "Implement multi-factor authentication (MFA) for all user accounts",
            "Enforce strong password policies (minimum 12 characters, complexity requirements)",
            "Implement single sign-on (SSO) with centralized identity management",
            "Disable legacy authentication protocols (NTLM, basic authentication)",
            "Monitor failed authentication attempts and implement alerting",
            "Implement conditional access policies based on risk factors",
        ]
    },
    "IA-5": {
        "title": "Authentication Credentials",
        "actions": [
            "Enforce password complexity requirements for all systems",
            "Implement password expiration policies (90-day rotation for privileged accounts)",
            "Prevent password reuse (maintain history of at least 5 previous passwords)",
            "Store passwords using strong cryptographic hashing (bcrypt, scrypt, Argon2)",
            "Implement passwordless authentication where possible (hardware keys, Windows Hello)",
            "Conduct quarterly password audit for compliance",
        ]
    },
    "IA-7": {
        "title": "Cryptographic Module Authentication",
        "actions": [
            "Use FIPS-certified cryptographic modules for all sensitive operations",
            "Implement hardware security modules (HSM) for key storage",
            "Test cryptographic implementations against known attack vectors",
            "Maintain current knowledge of cryptographic best practices",
            "Document all cryptographic algorithms and key management procedures",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SYSTEM AND COMMUNICATIONS PROTECTION (SC) - 46 controls
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "SC-7": {
        "title": "Boundary Protection",
        "actions": [
            "Deploy firewalls at network boundaries with explicit allow-list rules",
            "Implement network segmentation with DMZ for public-facing systems",
            "Deploy intrusion detection/prevention systems (IDS/IPS) on network boundaries",
            "Monitor all ingress and egress traffic for suspicious patterns",
            "Implement default-deny firewall rules with explicit exceptions",
            "Conduct quarterly firewall rule audit to remove obsolete rules",
            "Implement VPN with strong encryption for remote access",
        ]
    },
    "SC-13": {
        "title": "Cryptographic Protection",
        "actions": [
            "Implement TLS 1.3 or higher for all network communications",
            "Use AEAD (Authenticated Encryption with Associated Data) ciphers",
            "Implement certificate pinning for critical applications",
            "Maintain cryptographic key inventory and rotation schedule",
            "Monitor for weak or expired cryptographic implementations",
            "Implement perfect forward secrecy (PFS) for TLS connections",
        ]
    },
    "SC-23": {
        "title": "Session Management",
        "actions": [
            "Implement secure session token generation using cryptographically strong RNG",
            "Set session timeout to 30 minutes of inactivity for sensitive systems",
            "Implement automatic session invalidation upon logout",
            "Use HttpOnly and Secure flags on all authentication cookies",
            "Implement SameSite cookie attribute to prevent CSRF attacks",
            "Monitor for session fixation attempts",
            "Implement session anomaly detection (unusual location, device, behavior)",
        ]
    },
    "SC-28": {
        "title": "Protection of Information at Rest",
        "actions": [
            "Implement full-disk encryption (BitLocker, LUKS) on all systems",
            "Encrypt sensitive data at database/file level using strong algorithms",
            "Implement key management system for encryption key storage and rotation",
            "Maintain encryption key inventory with regular rotation schedule",
            "Test data recovery procedures from encrypted backups",
            "Monitor encryption key access and usage",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SYSTEM AND INFORMATION INTEGRITY (SI) - 16 controls
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "SI-2": {
        "title": "Flaw Remediation",
        "actions": [
            "Establish vulnerability management program with defined remediation timelines",
            "Conduct monthly vulnerability scans of all systems and applications",
            "Prioritize patches by CVSS score and exploitability",
            "Test patches in staging environment before production deployment",
            "Maintain inventory of all patches applied to systems",
            "Establish emergency patching procedures for critical vulnerabilities",
            "Monitor for unpatched systems using software asset management (SAM) tools",
        ]
    },
    "SI-4": {
        "title": "Information System Monitoring",
        "actions": [
            "Deploy centralized logging infrastructure (SIEM) for all systems",
            "Implement real-time monitoring and alerting for security events",
            "Monitor network traffic for indicators of compromise (IoC)",
            "Implement behavioral analysis to detect anomalous activities",
            "Maintain audit logs for minimum of 90 days (1 year for sensitive systems)",
            "Monitor for failed authentication attempts and account lockouts",
            "Implement threat intelligence integration to detect known threats",
        ]
    },
    "SI-7": {
        "title": "Software, Firmware, and Information Integrity",
        "actions": [
            "Implement file integrity monitoring (FIM) on critical system files",
            "Deploy code signing and cryptographic verification for executables",
            "Maintain secure software development lifecycle with security controls",
            "Implement anti-malware protection with real-time scanning",
            "Monitor for unauthorized system and firmware modifications",
            "Implement UEFI Secure Boot to protect against bootkit attacks",
            "Test integrity verification procedures regularly",
        ]
    },
    "SI-10": {
        "title": "Information Input Validation",
        "actions": [
            "Implement input validation rules for all user-supplied data",
            "Use allowlist approach for input validation (not blocklist)",
            "Validate input length, type, format, and encoding before processing",
            "Reject invalid input with appropriate error handling",
            "Log all input validation failures for security monitoring",
            "Implement parameterized queries to prevent SQL injection",
            "Test input validation with malicious payloads (fuzzing)",
        ]
    },
    "SI-16": {
        "title": "Memory Protection",
        "actions": [
            "Enable Address Space Layout Randomization (ASLR) on all systems",
            "Enable Data Execution Prevention (DEP) on all systems",
            "Implement Control Flow Guard (CFG) on Windows systems",
            "Use compiler-based memory safety checks where possible",
            "Monitor for memory corruption attacks using EDR",
            "Maintain up-to-date understanding of memory protection techniques",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # AUDIT AND ACCOUNTABILITY (AU) - 13 controls
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "AU-2": {
        "title": "Audit Events",
        "actions": [
            "Define audit logging requirements for all systems and applications",
            "Log authentication attempts (successful and failed)",
            "Log all privileged account activities and administrative actions",
            "Log data access and modifications to sensitive data",
            "Log system configuration changes",
            "Log malware detection events and responses",
            "Ensure audit logs are protected from unauthorized modification",
        ]
    },
    "AU-12": {
        "title": "Audit Generation",
        "actions": [
            "Implement centralized log collection from all systems and devices",
            "Configure audit logging on operating systems and applications",
            "Ensure system clocks are synchronized (NTP) for log correlation",
            "Generate and review audit reports on regular basis",
            "Implement automated alerting for critical security events",
            "Maintain audit log retention policies (minimum 90 days)",
            "Test audit logging to ensure it captures required events",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # CONFIGURATION MANAGEMENT (CM) - 9 controls
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "CM-5": {
        "title": "Access Restrictions for Change",
        "actions": [
            "Implement change management process with formal approval workflow",
            "Restrict access to configuration management tools to authorized personnel",
            "Implement segregation of duties (developer cannot deploy to production)",
            "Log all configuration changes with who, what, when, why",
            "Implement automated deployment with audit trail",
            "Require dual control (two-person rule) for critical changes",
            "Maintain configuration baseline and prevent unauthorized deviations",
        ]
    },
    "CM-6": {
        "title": "Configuration Settings",
        "actions": [
            "Document baseline security configuration for all system types",
            "Implement configuration management using infrastructure-as-code (IaC)",
            "Deploy configuration management agent to ensure compliance",
            "Monitor for configuration deviations from baseline",
            "Implement automated remediation for non-compliant configurations",
            "Conduct quarterly configuration compliance audits",
            "Maintain hardening guides and implement automatically",
        ]
    },
    "CM-7": {
        "title": "Least Functionality",
        "actions": [
            "Disable unnecessary services and ports on all systems",
            "Remove unnecessary software and components",
            "Implement application whitelisting for allowed executables",
            "Monitor for unauthorized software installation",
            "Document and maintain list of authorized software",
            "Implement Software Restriction Policies (SRP) or equivalent",
            "Conduct quarterly audit of running services for removal of unnecessary ones",
        ]
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # INCIDENT RESPONSE (IR) - 8 controls
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "IR-4": {
        "title": "Incident Handling",
        "actions": [
            "Develop and document incident response plan with defined roles and responsibilities",
            "Establish incident severity classification and response procedures",
            "Implement automated incident detection and alerting",
            "Maintain 24/7 incident response capability or on-call schedule",
            "Conduct tabletop exercises and incident response drills quarterly",
            "Maintain incident response toolkit and playbooks",
            "Document all incidents and conduct post-incident reviews",
        ]
    },
    "IR-6": {
        "title": "Incident Reporting",
        "actions": [
            "Establish incident reporting procedures and escalation paths",
            "Report security incidents to appropriate stakeholders",
            "Report data breach incidents to regulatory bodies and affected individuals",
            "Maintain incident log with detailed information for each incident",
            "Track incident metrics (MTTR, detection time, response time)",
            "Communicate incident status regularly to stakeholders",
        ]
    },

    # Default fallback remediation
    "DEFAULT": {
        "title": "Control Implementation",
        "actions": [
            "Review NIST SP 800-53 documentation for detailed control guidance",
            "Perform gap analysis to identify current vs. required control implementation",
            "Develop control implementation roadmap with timelines and resources",
            "Implement controls in stages based on risk prioritization",
            "Monitor control effectiveness through metrics and assessments",
            "Document all implemented controls with evidence of compliance",
        ]
    }
}


def get_mitre_remediation(technique_id: str) -> dict:
    """Get remediation guidance for MITRE ATT&CK technique"""
    return MITRE_TECHNIQUE_REMEDIATION.get(technique_id, MITRE_TECHNIQUE_REMEDIATION["DEFAULT"])


def get_nist_remediation(control_id: str) -> dict:
    """Get remediation guidance for NIST SP 800-53 control"""
    return NIST_CONTROL_REMEDIATION.get(control_id, NIST_CONTROL_REMEDIATION["DEFAULT"])


def get_remediation_for_cve(techniques: list, controls: list) -> dict:
    """Build comprehensive remediation guidance for a CVE with MITRE techniques and NIST controls"""
    remediation = {
        "techniques": {},
        "controls": {},
        "summary": ""
    }

    # Get remediation for MITRE techniques
    for tech in techniques:
        tech_id = tech.get("id", "")
        if tech_id:
            remediation["techniques"][tech_id] = get_mitre_remediation(tech_id)

    # Get remediation for NIST controls
    for ctrl in controls:
        ctrl_id = ctrl.get("id", "")
        if ctrl_id:
            remediation["controls"][ctrl_id] = get_nist_remediation(ctrl_id)

    return remediation
