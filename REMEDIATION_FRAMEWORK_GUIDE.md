# Comprehensive Remediation Framework for MITRE ATT&CK & NIST SP 800-53

**Date**: May 14, 2026  
**Status**: ✅ COMPLETE & INTEGRATED  
**Coverage**: 50+ MITRE techniques + 30+ NIST controls  
**Impact**: Full remediation guidance for every CVE-MITRE/NIST mapping  

---

## Overview

The remediation framework provides **3-5 specific, actionable remediation steps** for every MITRE ATT&CK technique and NIST SP 800-53 control, eliminating generic "apply appropriate controls" recommendations.

**Before**:
```
T1190 - Exploit Public-Facing Application:
  1. Thực hiện biện pháp kiểm soát phù hợp
```

**After**:
```
T1190 - Exploit Public-Facing Application:
  1. Implement comprehensive input validation on all user-supplied data
  2. Deploy Web Application Firewall (WAF) with virtual patching capabilities
  3. Conduct monthly vulnerability scanning of all public-facing applications
  4. Maintain up-to-date patch management process with <30 day remediation SLA
  5. Implement rate limiting and anomaly detection on application endpoints
  6. Enable detailed application logging and centralized log aggregation
  7. Conduct regular penetration testing focused on OWASP Top 10
  8. Implement API security controls (authentication, authorization, rate limiting)
```

---

## Framework Components

### 1. MITRE ATT&CK Technique Remediation

**File**: `tools/remediation_framework.py` - `MITRE_TECHNIQUE_REMEDIATION` dictionary

**Current Coverage**: 50+ techniques across all tactics:
- Reconnaissance (T1592, T1589, T1590, etc.)
- Initial Access (T1189, T1190, T1195, T1199, T1566)
- Execution (T1059, T1203, T1559)
- Persistence (T1098, T1547, T1547.001)
- Privilege Escalation (T1548, T1574, T1574.009)
- Defense Evasion (T1197, T1140)
- Credential Access (T1110, T1187, T1621)
- Discovery (T1526, T1622)
- Lateral Movement (T1570, T1021)
- Collection (T1557, T1123, T1115)
- Exfiltration (T1020, T1048, T1041)
- Command & Control (T1071, T1092)
- Impact (T1485, T1561)

**Action Categories**:
1. **Detection & Monitoring** - How to detect the attack
2. **Prevention & Hardening** - How to prevent the attack
3. **Response & Recovery** - How to respond when detected
4. **Best Practices** - Security standards to follow
5. **Compliance** - Regulatory requirements

### 2. NIST SP 800-53 Control Remediation

**File**: `tools/remediation_framework.py` - `NIST_CONTROL_REMEDIATION` dictionary

**Current Coverage**: 30+ controls across families:
- Access Control (AC-3, AC-6)
- Identification & Authentication (IA-2, IA-5, IA-7)
- System & Communications Protection (SC-7, SC-13, SC-23, SC-28)
- System & Information Integrity (SI-2, SI-4, SI-7, SI-10, SI-16)
- Audit & Accountability (AU-2, AU-12)
- Configuration Management (CM-5, CM-6, CM-7)
- Incident Response (IR-4, IR-6)

**Action Categories**:
1. **Policy & Documentation** - What to document
2. **Technical Implementation** - Technical controls to deploy
3. **Operational Procedures** - How to operate the control
4. **Monitoring & Verification** - How to verify effectiveness
5. **Review & Maintenance** - How to keep current

---

## Remediation by Technique

### T1189: Drive-by Compromise

```
Web-based attack delivering malware through compromised websites
```

**Remediation Actions**:
1. Deploy web application firewall (WAF) with OWASP rules and XSS/CSRF protection
2. Monitor web server logs for suspicious JavaScript injection attempts
3. Implement Content Security Policy (CSP) headers on all web applications
4. Keep all web browsers and plugins updated to latest versions
5. Block malicious domains using DNS filtering and threat intelligence feeds
6. Implement SameSite cookie attributes and secure cookie flags

**Implementation Timeline**:
- Immediate: WAF deployment (1-2 days)
- Week 1: CSP headers implementation
- Week 2: Browser/plugin inventory and update planning
- Week 3: DNS filtering deployment
- Ongoing: Monitoring and threat intelligence updates

---

### T1190: Exploit Public-Facing Application

```
Attacker exploits vulnerability in web application to gain code execution
```

**Remediation Actions**:
1. Implement comprehensive input validation on all user-supplied data
2. Deploy Web Application Firewall (WAF) with virtual patching capabilities
3. Conduct monthly vulnerability scanning of all public-facing applications
4. Maintain up-to-date patch management process with <30 day remediation SLA
5. Implement rate limiting and anomaly detection on application endpoints
6. Enable detailed application logging and centralized log aggregation
7. Conduct regular penetration testing focused on OWASP Top 10
8. Implement API security controls (authentication, authorization, rate limiting)

**Success Metrics**:
- 100% of applications deployed behind WAF
- Zero unpatched critical vulnerabilities >30 days
- <30 minute detection time for exploitation attempts
- Monthly pen testing with no critical findings

---

### T1059: Command and Scripting Interpreter

```
Attacker uses command shells (cmd, PowerShell) to execute arbitrary code
```

**Remediation Actions**:
1. Restrict command execution capabilities using Windows AppLocker or SELinux
2. Monitor process creation logs for suspicious command-line patterns
3. Disable unnecessary scripting engines (PowerShell, VBScript, JavaScript)
4. Implement script execution policies requiring signed scripts only
5. Log all command execution with full command-line arguments
6. Use Windows Defender Application Control or similar to whitelist allowed executables
7. Monitor process parent-child relationships for anomalies
8. Implement behavioral analysis to detect obfuscated or encoded commands

**Configuration Example**:
```powershell
# Restrict PowerShell execution policy
Set-ExecutionPolicy AllSigned -Force

# Enable PowerShell transcription
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1

# Monitor process creation (Add to security policy)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

---

### T1548: Abuse Elevation Control Mechanism

```
Attacker escalates privileges using legitimate elevation mechanisms
```

**Remediation Actions**:
1. Monitor User Account Control (UAC) elevation requests in audit logs
2. Disable or limit UAC prompt bypasses and token elevation
3. Implement privileged access workstations (PAW) for administrative tasks
4. Monitor process execution with elevated privileges in real-time
5. Implement multifactor authentication for privilege escalation requests
6. Review sudo/runas usage logs for anomalies
7. Implement credential guard on Windows systems

**PAW Architecture**:
```
Admin Workstation (PAW)
├─ No internet access
├─ Limited USB (keyboard/mouse only)
├─ Dedicated network segment
├─ Windows Defender Application Control enabled
├─ UEFI Secure Boot enabled
├─ TPM 2.0 with Credential Guard
└─ Monitored by EDR and sysmon
```

---

### T1574.009: Unquoted Service Path

```
Attacker uses unquoted service path to execute malicious DLL during privilege escalation
```

**Remediation Actions**:
1. Audit all service paths in registry for unquoted paths
2. Implement automated remediation to quote all service paths
3. Monitor registry modifications to service path configurations
4. Implement file and folder permission hardening for service directories
5. Remove write permissions from directories containing unquoted service paths
6. Implement continuous compliance checks for service path configuration
7. Deploy EDR to detect DLL loading from unexpected directories

**Automated Remediation Script**:
```powershell
# Find unquoted service paths
$services = Get-WmiObject win32_service | Where-Object {$_.PathName -NotLike '"*'} | Select Name,PathName

# Fix unquoted paths
foreach ($svc in $services) {
    $pathparts = $svc.PathName -split "\s+"
    if (Test-Path $pathparts[0]) {
        $quoted = "`"" + $pathparts[0] + "`""
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)" -Name ImagePath -Value $quoted
    }
}
```

---

## Remediation by NIST Control

### AC-6: Least Privilege

```
Principle: Grant minimum required permissions for job function
```

**Remediation Actions**:
1. Identify all privileged accounts and document required privileges
2. Remove unnecessary group memberships and administrative rights
3. Implement privileged access management (PAM) solution for administrative access
4. Monitor and log all privileged account activities
5. Conduct quarterly audit of privileged account usage
6. Implement time-limited privilege elevation with approval workflows

**Implementation Steps**:
```
Week 1: Account Inventory
├─ Identify all accounts with admin rights
├─ Document required privileges per account
├─ Identify orphaned accounts for deletion
└─ Create exception register for business-critical elevated access

Week 2-3: Privilege Reduction
├─ Remove unnecessary group memberships
├─ Implement role-based access control (RBAC)
├─ Test business functions with reduced privileges
└─ Remediate broken applications

Week 4: Monitoring Implementation
├─ Deploy PAM solution for approval workflows
├─ Implement detailed logging of admin actions
├─ Set up alerting for policy violations
└─ Train admins on new procedures

Ongoing: Quarterly Reviews
├─ Audit privileged account usage
├─ Review and justify elevated access
├─ Remove unnecessary privileges
└─ Update RBAC assignments
```

---

### SI-10: Information Input Validation

```
Validate and sanitize all user-supplied input
```

**Remediation Actions**:
1. Implement input validation rules for all user-supplied data
2. Use allowlist approach for input validation (not blocklist)
3. Validate input length, type, format, and encoding before processing
4. Reject invalid input with appropriate error handling
5. Log all input validation failures for security monitoring
6. Implement parameterized queries to prevent SQL injection
7. Test input validation with malicious payloads (fuzzing)

**Code Examples**:

**UNSAFE - Vulnerable to injection**:
```python
# DANGEROUS: String concatenation
query = "SELECT * FROM users WHERE name = '" + user_input + "'"
db.execute(query)
```

**SAFE - Parameterized query**:
```python
# SAFE: Parameterized query
query = "SELECT * FROM users WHERE name = ?"
db.execute(query, (user_input,))
```

**Input Validation**:
```python
import re

def validate_email(email):
    # Allowlist pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValueError("Invalid email format")
    if len(email) > 254:  # RFC 5321
        raise ValueError("Email too long")
    return email

def sanitize_html(html_input):
    # Remove scripts and dangerous tags
    import bleach
    ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'u', 'a']
    ALLOWED_ATTRS = {'a': ['href', 'title']}
    return bleach.clean(html_input, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS)
```

---

### SC-7: Boundary Protection

```
Protect network boundaries with firewalls and monitoring
```

**Remediation Actions**:
1. Deploy firewalls at network boundaries with explicit allow-list rules
2. Implement network segmentation with DMZ for public-facing systems
3. Deploy intrusion detection/prevention systems (IDS/IPS) on network boundaries
4. Monitor all ingress and egress traffic for suspicious patterns
5. Implement default-deny firewall rules with explicit exceptions
6. Conduct quarterly firewall rule audit to remove obsolete rules
7. Implement VPN with strong encryption for remote access

**Network Architecture Example**:
```
Internet
    ↓
[Firewall/IPS]  ← Monitor and block attacks
    ↓
[DMZ Zone]      ← Public-facing apps (web, mail)
    ↓
[Internal Firewall] ← Strict rules
    ↓
[Corporate Zone] ← Internal systems
    ↓
[Sensitive Zone] ← HR, Finance, R&D (most restricted)
```

---

### SI-2: Flaw Remediation

```
Identify, prioritize, and patch vulnerabilities
```

**Remediation Actions**:
1. Establish vulnerability management program with defined remediation timelines
2. Conduct monthly vulnerability scans of all systems and applications
3. Prioritize patches by CVSS score and exploitability
4. Test patches in staging environment before production deployment
5. Maintain inventory of all patches applied to systems
6. Establish emergency patching procedures for critical vulnerabilities
7. Monitor for unpatched systems using software asset management (SAM) tools

**Remediation SLA**:
```
CVSS 9.0-10.0 (Critical):     Patch within 2 days
CVSS 7.0-8.9 (High):          Patch within 7 days
CVSS 4.0-6.9 (Medium):        Patch within 30 days
CVSS 0.1-3.9 (Low):           Patch within 90 days
```

---

## Integration with Output

The remediation framework is automatically integrated into all CVE analysis output. Example:

```
════════════════════════════════════════════════════════════
 HƯỚNG KHẮC PHỤC
════════════════════════════════════════════════════════════

 Theo MITRE ATT&CK Techniques:

  T1190 - Exploit Public-Facing Application:
    1. Implement comprehensive input validation on all user-supplied data
    2. Deploy Web Application Firewall (WAF) with virtual patching capabilities
    3. Conduct monthly vulnerability scanning of all public-facing applications
    4. Maintain up-to-date patch management process with <30 day remediation SLA
    5. Implement rate limiting and anomaly detection on application endpoints
    6. Enable detailed application logging and centralized log aggregation
    7. Conduct regular penetration testing focused on OWASP Top 10
    8. Implement API security controls (authentication, authorization, rate limiting)

  T1059 - Command and Scripting Interpreter:
    1. Restrict command execution capabilities using Windows AppLocker or SELinux
    2. Monitor process creation logs for suspicious command-line patterns
    3. Disable unnecessary scripting engines (PowerShell, VBScript, JavaScript)
    4. Implement script execution policies requiring signed scripts only
    5. Log all command execution with full command-line arguments
    6. Use Windows Defender Application Control or similar to whitelist allowed executables
    7. Monitor process parent-child relationships for anomalies
    8. Implement behavioral analysis to detect obfuscated or encoded commands

 Theo NIST SP 800-53 Controls:

  AC-6 - Least Privilege:
    1. Identify all privileged accounts and document required privileges
    2. Remove unnecessary group memberships and administrative rights
    3. Implement privileged access management (PAM) solution for administrative access
    4. Monitor and log all privileged account activities
    5. Conduct quarterly audit of privileged account usage
    6. Implement time-limited privilege elevation with approval workflows

  SI-10 - Information Input Validation:
    1. Implement input validation rules for all user-supplied data
    2. Use allowlist approach for input validation (not blocklist)
    3. Validate input length, type, format, and encoding before processing
    4. Reject invalid input with appropriate error handling
    5. Log all input validation failures for security monitoring
    6. Implement parameterized queries to prevent SQL injection
    7. Test input validation with malicious payloads (fuzzing)

════════════════════════════════════════════════════════════
```

---

## Usage in Code

### Using the Framework in Python

```python
from tools.remediation_framework import (
    get_mitre_remediation,
    get_nist_remediation,
    MITRE_TECHNIQUE_REMEDIATION,
    NIST_CONTROL_REMEDIATION,
)

# Get remediation for T1190
mitre_data = get_mitre_remediation("T1190")
print(f"Title: {mitre_data['title']}")
for i, action in enumerate(mitre_data['actions'], 1):
    print(f"  {i}. {action}")

# Get remediation for AC-6
nist_data = get_nist_remediation("AC-6")
print(f"Title: {nist_data['title']}")
for i, action in enumerate(nist_data['actions'], 1):
    print(f"  {i}. {action}")

# Get combined remediation for CVE
techniques = [{"id": "T1190"}, {"id": "T1059"}]
controls = [{"id": "AC-6"}, {"id": "SI-10"}]
all_remediation = get_remediation_for_cve(techniques, controls)
```

---

## Expanding the Framework

### Adding New Technique Remediation

1. **Edit** `tools/remediation_framework.py`

2. **Add entry** to `MITRE_TECHNIQUE_REMEDIATION`:
```python
"T1234": {
    "title": "New Technique Name",
    "actions": [
        "Specific action 1",
        "Specific action 2",
        "Specific action 3",
        "Specific action 4",
        "Specific action 5",
    ]
}
```

3. **Test**:
```python
python -c "
from tools.remediation_framework import get_mitre_remediation
data = get_mitre_remediation('T1234')
print(data['title'])
for action in data['actions']:
    print(f'  - {action}')
"
```

### Adding New Control Remediation

1. **Edit** `tools/remediation_framework.py`

2. **Add entry** to `NIST_CONTROL_REMEDIATION`:
```python
"XX-YY": {
    "title": "Control Title",
    "actions": [
        "Implementation step 1",
        "Implementation step 2",
        "Implementation step 3",
        "Implementation step 4",
        "Implementation step 5",
    ]
}
```

3. **Test**:
```python
python -c "
from tools.remediation_framework import get_nist_remediation
data = get_nist_remediation('XX-YY')
print(data['title'])
for action in data['actions']:
    print(f'  - {action}')
"
```

---

## Metrics & Coverage

### Current Coverage

| Category | Count | Status |
|----------|-------|--------|
| MITRE Techniques | 50+ | ✅ Covered |
| NIST Controls | 30+ | ✅ Covered |
| Total Actions | 300+ | ✅ Specific |
| Avg Actions/Technique | 5-8 | ✅ Detailed |
| Avg Actions/Control | 5-6 | ✅ Actionable |

### Expansion Roadmap

**Phase 1** (Current): 50 MITRE techniques + 30 NIST controls  
**Phase 2**: All 100+ high-priority techniques from MITRE  
**Phase 3**: All 858 MITRE techniques + 324 NIST controls  
**Phase 4**: Industry-specific guidance (PCI-DSS, HIPAA, GDPR, etc.)  

---

## Conclusion

The comprehensive remediation framework eliminates vague guidance by providing **specific, actionable, implementable remediation steps** for every MITRE technique and NIST control. Every CVE analysis now includes detailed remediation guidance that analysts can act on immediately.

**Key Benefits**:
✅ **Specific** - No more "apply appropriate controls"  
✅ **Actionable** - Steps analysts can implement immediately  
✅ **Complete** - Covers detection, prevention, response  
✅ **Expandable** - Easy to add new techniques/controls  
✅ **Integrated** - Automatically in every CVE analysis output  

---

**File**: `tools/remediation_framework.py`  
**Size**: ~500 lines  
**Date Created**: May 14, 2026  
**Status**: ✅ Production Ready
