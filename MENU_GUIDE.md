# CyberSec Multi-Agent System - Menu Guide

## 🎯 Quick Reference: What Each Menu Option Does

---

## **Menu Option 1: Quet CVE va tim thiet bi bi anh huong** (CVE Scan)
### What it does:
✅ Searches NVD for CVEs  
✅ Automatically matches CVEs to your devices  
✅ Shows **device-level impact**

### You provide:
- CVE keyword (e.g., "log4j", "apache", "spring")

### You get:
- List of CVEs found with details (CVSS, severity, description)
- **Affected devices** with specific CVEs per device
- Risk levels for each device

### Example:
```
Input: Menu 1 → Enter keyword "log4j"

Output:
- 10 CVEs found from NVD
- 2 devices affected:
  * SRV-002 (CRITICAL): 10 CVEs (CVE-2021-4104, CVE-2022-23302, ...)
  * SRV-001 (HIGH): 5 CVEs (CVE-2022-23307, CVE-2021-3100, ...)
```

---

## **Menu Option 2: Lay Threat Intelligence - IOC / Malware / APT** (IOC Scan)
### What it does:
✅ Searches OpenCTI for IOC/indicators  
✅ Gets malware information  
✅ Finds threat actors and APT details  
⚠️ **Does NOT match to devices**

### You provide:
- Search term (e.g., "ransomware", "emotet", "APT41", "malware")

### You get:
- IOC indicators (file hashes, patterns, rules)
- Malware family names
- Threat actor profiles
- Confidence scores
- YARA rules and detection patterns

### Example:
```
Input: Menu 2 → Enter search "ransomware"

Output:
- 4 malware indicators found
- Families: Mallox, CactusRansomware, RansomHouse_Mario
- Details: file hashes, YARA rules, confidence 100%
```

---

## **Menu Option 3: Tao bao cao** (Report Generation)
### What it does:
✅ Creates executive summary reports  
✅ Aggregates all previous findings  
✅ Provides actionable recommendations

### You provide:
- (No input needed, uses previous results)

### You get:
- Executive summary report
- Risk assessment
- Timeline recommendations
- File saved in `./reports/` directory

---

## **Menu Option 4: Upload / xu ly tai lieu noi bo** (Document Upload)
### What it does:
✅ Upload internal documents  
✅ Analyze document content  
✅ Extract security insights

### You provide:
- Document name
- Document content (paste multiline text)

### You get:
- Summary of document
- Security insights
- Relevant recommendations

---

## **Menu Option 5: Liet ke thiet bi trong CMDB** (Device Inventory)
### What it does:
✅ Lists all devices in your inventory  
✅ Shows device properties  
✅ Shows CVE mappings (if previously searched)

### You provide:
- (No input needed)

### You get:
- List of all devices
- Device properties (hostname, IP, OS, criticality)
- Software inventory
- CVE counts per device (if searched)

---

## **Menu Option 6: Cau hoi tu do** (Free Query)
### What it does:
✅ Ask anything  
✅ System auto-routes to correct agent  
✅ Combines multiple data sources

### You provide:
- Any question in Vietnamese or English

### System routes to:
- **CVE Agent** if you mention: "CVE", "lỗi", "log4j", "vulnerability"
- **IOC Agent** if you mention: "IOC", "malware", "APT", "threat actor"
- **Device Agent** if you mention: "device", "thiết bị", "CMDB"
- **Reporter** if you mention: "báo cáo", "report", "summary"

### Example Queries:
```
"Quet CVE log4j va tim thiet bi bi anh huong"
→ Routes to: CVE Agent → Device Matcher

"Lay IOC emotet va ransomware"
→ Routes to: IOC Agent

"Hien thi thiet bi bi anh huong boi CVE cao"
→ Routes to: Device Agent

"Tao bao cao tong hop"
→ Routes to: Reporter
```

---

## 📊 Comparison Table

| Feature | Menu 1 (CVE) | Menu 2 (IOC) | Menu 5 (CMDB) | Menu 6 (Free) |
|---------|---|---|---|---|
| **Data Source** | NVD | OpenCTI | Local CMDB | All |
| **Device Matching** | ✅ Yes | ❌ No | ✅ Yes | Auto-detected |
| **CVE Info** | ✅ Full | ❌ No | ✅ Related | Auto-detected |
| **IOC/Malware** | ❌ No | ✅ Full | ❌ No | Auto-detected |
| **Threat Actors** | ❌ No | ✅ Yes | ❌ No | Auto-detected |
| **User Input** | Keyword | Keyword | None | Query |

---

## 🔍 When to Use Each Option

### **Use Menu 1 (CVE) when:**
- ✅ You want to find vulnerabilities (e.g., "Any log4j issues?")
- ✅ You need to know **which devices are affected**
- ✅ You need risk prioritization per device
- ✅ You need to patch planning

### **Use Menu 2 (IOC) when:**
- ✅ You want to research **malware** (e.g., "Ransomware detection rules?")
- ✅ You want to **identify threat actors** (e.g., "APT41 indicators?")
- ✅ You want **file hashes and indicators** for your SIEM
- ✅ You want **detection rules (YARA)** to deploy

### **Use Menu 5 (CMDB) when:**
- ✅ You want to see your **complete device inventory**
- ✅ You want to understand **device properties**
- ✅ You want to see **which devices have CVE issues**

### **Use Menu 6 (Free) when:**
- ✅ You're not sure which option to use
- ✅ You want to ask a **complex question** combining multiple data types
- ✅ You want the system to **auto-detect** what you're asking for

---

## 📋 Result Format

### Menu 1 (CVE) Results Show:
```
📋 CVE DETAILS - ALL
  - CVE ID, CVSS Score, Severity, Published date, Description

💻 DEVICE IMPACT - SPECIFIC
  - Device hostname, IP, OS, Criticality
  - Number of CVEs affecting it
  - **Specific CVE list** with risk level per device
```

### Menu 2 (IOC) Results Show:
```
🔍 IOC/MALWARE DETAILS - ALL
  - IOC ID, Name, Score, Confidence
  - Pattern/YARA rule
  - Complete description
```

### Menu 5 (CMDB) Results Show:
```
Device list with:
  - Device ID, hostname, IP address, OS
  - Criticality level
  - Software inventory
  - Related CVEs (if Menu 1 was used)
```

---

## 💡 Pro Tips

1. **Combine searches:** Use Menu 1, then Menu 2 to get full threat picture
2. **Device focus:** Use Menu 1 to find affected devices, then prioritize patching
3. **Threat research:** Use Menu 2 to get malware details and detection rules
4. **When confused:** Use Menu 6 (Free Query) - system will route correctly
5. **Generate reports:** Use Menu 3 after gathering all information

---

## 🚀 Example Workflow

### Scenario: Security Assessment for Web Servers

```
Step 1: Check devices
  → Menu 5 (List CMDB)
  → See: 5 devices total

Step 2: Check for critical vulnerabilities
  → Menu 1 (CVE Scan)
  → Enter: "log4j"
  → See: 10 CVEs, 2 affected devices

Step 3: Research threat landscape
  → Menu 2 (IOC Scan)
  → Enter: "ransomware"
  → See: 4 malware families, detection rules

Step 4: Create action plan
  → Menu 3 (Report)
  → Get: Executive summary with priorities
```

---

**Need help? Use Menu 6 to ask any question!**

