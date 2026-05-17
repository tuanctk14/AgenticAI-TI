# CVE-2026-46366 - Vulners Data

## ✅ CVE FOUND IN VULNERS

### 📋 BASIC INFORMATION
- **CVE ID**: CVE-2026-46366
- **Title**: CVE-2026-46366
- **Type**: cve
- **Vulnerability Type**: Information Disclosure (CWE-863)
- **Source**: disclosure@vulncheck.com

### 📝 DESCRIPTION
> phpMyFAQ before 4.1.2 contains an information disclosure vulnerability in the getIdFromSolutionId() method that lacks permission filtering, allowing unauthenticated attackers to enumerate restricted FAQ entries and read their titles via the /solution_id_{id}.html endpoint. Attackers can sequentially iterate solution IDs to discover all FAQs including those restricted to specific users or groups, leaking sensitive metadata through redirect Location headers and page canonical links.

### 📅 TIMELINE
| Event | Date |
|-------|------|
| Published | 2026-05-15T18:36:44 |
| Modified | 2026-05-15T21:16:38 |
| Created | 2026-05-15T19:04:17Z |
| Updated | 2026-05-17T00:05:31Z |
| Enriched | 2026-05-16T08:26:23Z |
| Reviewed | 2026-05-15T22:20:08Z |

### 🎯 SCORING & SEVERITY

#### EPSS (Exploitation Probability Scoring System)
- **Score**: 0.00060 (very low exploitation likelihood)
- **Percentile**: 0.19 (very low risk)
- **Date**: 2026-05-17

#### CVSS (Common Vulnerability Scoring System)
- **Version**: 3.1
- **Score**: 7.5 (HIGH)
- **Severity**: HIGH
- **Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

##### CVSS Components:
| Component | Value |
|-----------|-------|
| Attack Vector | NETWORK |
| Attack Complexity | LOW |
| Privileges Required | NONE |
| User Interaction | NONE |
| Scope | UNCHANGED |
| Confidentiality Impact | HIGH |
| Integrity Impact | NONE |
| Availability Impact | NONE |

### 🔍 VULNERABILITY DETAILS
- **CWE ID**: CWE-863 (Incorrect Authorization)
- **Vulnerability Status**: Received
- **CPE Entries**: 0 (ไม่มี CPE data)
- **Affected Software**: ไม่มีข้อมูล
- **Solutions**: ไม่มีข้อมูล
- **Workarounds**: ไม่มีข้อมูล

### 🔗 REFERENCES
1. https://www.vulncheck.com/advisories/phpmyfaq-unauthenticated-information-disclosure-via-getidfromsolutionid-permission-bypass
2. https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-99qv-g4x9-mgc3

### 📊 ADDITIONAL INFORMATION
- **Vuln Status**: Received
- **Source Code Available**: True
- **View Count**: 1
- **Web Applicability**: N/A (ไม่áp dụng cho web)

### 🗂️ ALL AVAILABLE FIELDS IN VULNERS
```
id, vendorId, type, bulletinFamily, title, description, attachments, 
timestamps, published, modified, epss, cvss, metrics, cvss2, cvss3, cvss4, 
href, sourceAvailable, reporter, references, cvelist, immutableFields, 
lastseen, viewCount, enchantments, aiDescription, cpe, cpe23, cwe, 
vulnStatus, affectedSoftware, affectedConfiguration, cpeConfiguration, 
cpeConfigurations, extraReferences, cnaAffected, cnaCpeApplicability, 
solutions, workarounds, impacts, exploits, problemTypes, assigned, origin, 
threatData, webApplicability
```

---

## 📊 SUMMARY

| Aspect | Status |
|--------|--------|
| **CVE Found** | ✅ Yes |
| **EPSS Data** | ✅ Yes (0.00060, 0.19%) |
| **CVSS Data** | ✅ Yes (7.5, HIGH) |
| **CWE Data** | ✅ Yes (CWE-863) |
| **CPE Data** | ❌ No |
| **Affected Software** | ❌ No |
| **Solutions** | ❌ No |
| **Workarounds** | ❌ No |
| **References** | ✅ Yes (2 refs) |
| **Timestamps** | ✅ Yes (5 timestamps) |

---

## 🎯 WHAT CAN BE EXTRACTED

### Hiện Tại Sử Dụng:
✅ Exploit intelligence (exploit_count, sources, references)

### Có Thể Thêm:
✅ **EPSS Score** (Exploitation Probability) - 0.00060
✅ **CVSS Score** (Severity) - 7.5 (HIGH)
✅ **CVSS Vector** - For detailed attack analysis
✅ **CWE ID** - CWE-863
✅ **References** - For threat intelligence
✅ **Timestamps** - For tracking vulnerability lifecycle
✅ **Vulnerability Status** - Current state
✅ **Published/Modified Dates** - Timeline

### Not Available for This CVE:
❌ CPE entries (no affected software list)
❌ Solutions/Workarounds (not provided by vendor yet)
❌ Exploit data (field exists but empty)

