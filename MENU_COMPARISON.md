# Menu Option 1 vs Menu Option 2 - Complete Comparison

## Side-by-Side Comparison

### **MENU OPTION 1: CVE Scanning (Quet CVE)**

```
INPUT:
  User enters: "log4j"

PROCESSING:
  Supervisor → CVE Agent (agent_ti)
              → fetch_nvd_cves() → NVD API
              → Device Matcher (agent_matcher)
              → match_cves_with_cmdb() → CMDB

OUTPUT - STRUCTURED DATA:
  📋 CVE DETAILS (All 10 found):
     1. CVE-2021-4104: CVSS 7.5, HIGH, Published 2021-12-14
     2. CVE-2022-23302: CVSS 8.8, HIGH, Published 2022-01-18
     ... (8 more)

  💻 DEVICE IMPACT (Specific devices):
     • Device: SRV-002 (db-server-01)
       Criticality: CRITICAL
       Affected by 10 CVEs:
         - CVE-2021-4104: HIGH (CVSS: 7.5)
         - CVE-2022-23302: HIGH (CVSS: 8.8)
         - CVE-2022-23307: HIGH (CVSS: 8.8)
         ... (7 more)

     • Device: SRV-001 (web-server-01)
       Criticality: HIGH
       Affected by 5 CVEs:
         - CVE-2022-23307: HIGH (CVSS: 8.8)
         ... (4 more)

RESULT FOR USER:
  ✅ Know which devices are vulnerable
  ✅ Know exactly which CVEs affect each device
  ✅ Understand device-level risk
  ✅ Plan patching strategy
```

---

### **MENU OPTION 2: IOC/Malware/APT Scanning (Lay Threat Intelligence)**

```
INPUT:
  User enters: "ransomware"

PROCESSING:
  Supervisor → IOC Agent (agent_ti_extended)
              → fetch_opencti_indicators() → OpenCTI API
              → [NO device matching - returns threat intel only]

OUTPUT - STRUCTURED DATA:
  🔍 IOC/MALWARE DETAILS (All 4 found):
     1. ransomware_mallox
        ID: 47744207-25cd-40e7-b579-f7dd81a8058e
        Score: 78/100, Confidence: 100%
        Pattern: rule ransomware_mallox { ... YARA rule ... }
        Description: Rule to detect mallox ransomware samples

     2. CactusRansomware
        ID: 4f08a107-ba6b-4ac0-a3ec-647632c8d95b
        Score: 50/100, Confidence: 100%
        Pattern: /* MIT License ... detection rule ... */
        Description: Rule to detect Cactus Ransomware

     3. INDICATOR_SUSPICIOUS_GENRansomware
        ID: 1974c6c5-c0e8-45df-9eed-36e5d4d2effb
        Score: 78/100, Confidence: 100%
        Pattern: rule INDICATOR_SUSPICIOUS_GENRansomware { ... }
        Description: Detects command variations used by ransomware

     4. ransomware_XX_RansomHouse_Mario
        ID: ebbf7cb9-b4d7-4aaa-9029-8c16e2be48d3
        Score: 62/100, Confidence: 100%
        Pattern: rule ransomware_XX_RansomHouse_Mario { ... }
        Description: Detects RansomHouse/Mario ransomware

[NOTE: No device matching - these are generic threat indicators]

RESULT FOR USER:
  ✅ Know malware families in the wild
  ✅ Get detection rules (YARA) to deploy to SIEM
  ✅ Understand threat landscape
  ✅ Plan detection & response strategy
```

---

## Key Differences

| Aspect | Menu 1 (CVE) | Menu 2 (IOC) |
|--------|---|---|
| **Data Source** | NVD (CVE Database) | OpenCTI (Threat Intelligence) |
| **Search Term** | Vulnerability keyword (log4j, apache, etc.) | Threat term (ransomware, APT41, emotet, etc.) |
| **Processing** | CVE search → Device matching | Direct threat intelligence lookup |
| **Device Matching** | ✅ YES - Maps to YOUR devices | ❌ NO - Generic threat info |
| **Shows YOUR Impact** | ✅ YES - Which of your devices are vulnerable | ❌ NO - Doesn't know about your devices |
| **Main Purpose** | Find and patch vulnerabilities in your systems | Research threats and get detection rules |
| **Use Case** | "We need to patch these devices" | "We need detection rules for malware X" |
| **Agent Pipeline** | Supervisor → CVE Agent → Matcher | Supervisor → IOC Agent |
| **Steps in Workflow** | 5 steps | 3 steps |

---

## What You Get from Each

### Menu 1 Results Answer:
- 📊 "Which of my devices have CVEs?"
- 🎯 "Which specific CVEs affect which devices?"
- 🚨 "What's the severity/risk per device?"
- 📋 "What's my patching priority?"

### Menu 2 Results Answer:
- 🔍 "What malware families are currently active?"
- 🛡️ "What detection rules should I deploy?"
- 🎭 "What threat actors are we facing?"
- 📌 "What IOC indicators should I block?"
- 🧬 "What file hashes are malicious?"
- 📜 "What's the confidence level of indicators?"

---

## Example Workflow

### Scenario: Complete Security Assessment

```
STEP 1: Check for vulnerabilities (Menu 1)
───────────────────────────────────────
User: Selects Menu 1, enters "log4j"

Result:
  ✅ SRV-002 has 10 CVEs (CRITICAL)
  ✅ SRV-001 has 5 CVEs (HIGH)
  
Decision: Need to patch these devices immediately


STEP 2: Research threat landscape (Menu 2)
──────────────────────────────────────────
User: Selects Menu 2, enters "ransomware"

Result:
  ✅ 4 ransomware families active
  ✅ Got YARA rules for detection
  ✅ Confidence: 100% for all indicators
  
Decision: Deploy detection rules to SIEM


STEP 3: Create action plan (Menu 3)
───────────────────────────────────
User: Selects Menu 3 (Report)

Result:
  ✅ Executive summary with:
     - Top 3 patches needed
     - Timeline recommendations
     - Risk assessment
```

---

## When to Use Which Menu

### Use Menu 1 If:
- ✅ You want to know **which of YOUR devices** are vulnerable
- ✅ You need **device-level risk assessment**
- ✅ You're planning a **patch management** project
- ✅ You want to identify **critical systems** needing fixes
- ✅ Your question contains: "CVE", "vulnerability", "log4j", etc.

### Use Menu 2 If:
- ✅ You want to research **malware threats** (no device matching needed)
- ✅ You need **detection rules** for your SIEM/IDS
- ✅ You want to know about **threat actors/APT groups**
- ✅ You want **file hashes/IOCs** to block
- ✅ Your question contains: "IOC", "malware", "APT", "threat actor", "ransomware"

### Use Menu 6 (Free Query) If:
- ✅ You're not sure which menu to use
- ✅ You want to ask a **combined question** (both CVE and IOC)
- ✅ System will **auto-route** to the right agent

---

## Important Note

⚠️ **Menu 2 does NOT match devices to IOC**

This is intentional because:
- IOC (Indicators of Compromise) are generic threat signatures
- They may not apply to your specific devices
- You typically use them in SIEM/IDS rules, not for device patching
- Device-device matching is only done for CVEs (known vulnerabilities)

If you want to know if your devices are affected by a **specific CVE**, use Menu 1.
If you want threat intelligence and detection rules, use Menu 2.

---

