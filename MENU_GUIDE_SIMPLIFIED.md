# CyberSec Multi-Agent System - Simplified 5-Menu Guide

## 🎯 Quick Menu Overview

```
+--------------------------------------------------------------+
|                    MENU CHINH                                |
+--------------------------------------------------------------+
|  1. Quet CVE va tim thiet bi bi anh huong                    |
|  2. Tao bao cao (Report generation)                          |
|  3. Upload / xu ly tai lieu noi bo (Document handling)       |
|  4. Liet ke thiet bi trong CMDB (Device inventory)           |
|  5. Cau hoi tu do - IOC/Malware/APT/CVE (Free query)         |
|  0. Thoat (Exit)                                             |
+--------------------------------------------------------------+
```

---

## **Menu Option 1: Quet CVE va tim thiet bi bi anh huong**
### CVE Scanning with Device Impact

**What it does:**
✅ Searches NVD for CVEs  
✅ Automatically matches CVEs to your devices  
✅ Shows **device-level impact**

**You provide:**
- CVE keyword (e.g., "log4j", "apache", "spring")

**You get:**
- List of CVEs with CVSS scores, severity, descriptions
- **Affected devices** with specific CVEs per device
- Risk levels for each device

**Example:**
```
Input: Menu 1 → Enter "log4j"

Output:
- 10 CVEs found from NVD
- 2 devices affected:
  * SRV-002: 10 CVEs (CVE-2021-4104, CVE-2022-23302, ...)
  * SRV-001: 5 CVEs (CVE-2022-23307, ...)
```

---

## **Menu Option 2: Tao bao cao**
### Report Generation

**What it does:**
✅ Creates executive summary reports  
✅ Aggregates all previous findings  
✅ Provides actionable recommendations

**You provide:**
- (No input needed, uses previous results)

**You get:**
- Executive summary report
- Risk assessment
- Timeline recommendations
- File saved in `./reports/` directory

---

## **Menu Option 3: Upload / xu ly tai lieu noi bo**
### Document Handling

**What it does:**
✅ Upload internal documents  
✅ Analyze document content  
✅ Extract security insights

**You provide:**
- Document name
- Document content (paste multiline text, end with "END")

**You get:**
- Summary of document
- Security insights
- Relevant recommendations

---

## **Menu Option 4: Liet ke thiet bi trong CMDB**
### Device Inventory

**What it does:**
✅ Lists all devices in your inventory  
✅ Shows device properties  
✅ Shows CVE mappings (if previously searched)

**You provide:**
- (No input needed)

**You get:**
- List of all devices
- Device properties (hostname, IP, OS, criticality)
- Software inventory
- CVE counts per device (if Menu 1 was used)

---

## **Menu Option 5: Cau hoi tu do - IOC/Malware/APT/CVE**
### Free Query (Auto-Routing)

**What it does:**
✅ Ask anything in natural language  
✅ System auto-detects query type  
✅ Routes to correct agent automatically

**You provide:**
- Any question in Vietnamese or English

**System detects and routes:**

| Your Question | System Routes To | Data From |
|---|---|---|
| "Quet CVE log4j" | CVE Agent | NVD API |
| "Tim malware ransomware" | IOC Agent | OpenCTI API |
| "Tim threat actor APT" | IOC Agent | OpenCTI API |
| "Thiet bi nao bi anh huong" | Device Matcher | CMDB |
| "Tao bao cao" | Reporter | All collected data |

**Example Queries:**
```
"Quet CVE log4j va tim thiet bi bi anh huong"
→ Routes to: CVE Agent → Device Matcher

"Lay thong tin ve malware ransomware"
→ Routes to: IOC Agent → Returns 83 results (4 IOC + 50 Malware + 29 Patterns)

"Tim threat actor emotet"
→ Routes to: IOC Agent → Returns threat intelligence

"Thiet bi nao co lo hong cao"
→ Routes to: Device Agent → Shows devices with high-risk CVEs

"Tao bao cao tong hop"
→ Routes to: Reporter → Generates executive summary
```

---

## **Why Only 5 Menu Options?**

### Original Design (6 Options)
1. ✅ CVE Scan
2. ❌ **IOC/Malware/APT** (redundant)
3. ✅ Report
4. ✅ Document Upload
5. ✅ Device List
6. ✅ Free Query

### Problem
Menu 2 and Menu 6 did the same thing:
- Menu 2: Enter "ransomware" → Get IOC data
- Menu 6: Enter "malware ransomware" → Get IOC data (via auto-routing)

### Solution
**Merged into simplified 5-menu structure:**

| Now | Purpose | Instead of |
|---|---|---|
| Menu 1 | **CVE + Device Matching** | Specific CVE search |
| Menu 2 | **Report Generation** | N/A |
| Menu 3 | **Document Upload** | Moved up |
| Menu 4 | **Device List** | Moved up |
| Menu 5 | **Free Query (ALL features)** | Menu 2 (IOC) + Old Menu 6 |

Menu 5 now handles:
- ✅ CVE queries
- ✅ IOC/Malware queries
- ✅ Threat actor queries
- ✅ Device queries
- ✅ Report queries
- ✅ Document queries

---

## 🎯 When to Use Each Menu

### Use Menu 1 when:
- ✅ You want to find vulnerable devices
- ✅ You need device-level risk assessment
- ✅ You're planning a patch project
- ✅ Your question is specifically about **CVEs and devices**

### Use Menu 2 when:
- ✅ You have previous query results
- ✅ You want to generate a report
- ✅ You need an executive summary

### Use Menu 3 when:
- ✅ You have documents to analyze
- ✅ You need security insights from text

### Use Menu 4 when:
- ✅ You want to see your inventory
- ✅ You want to understand device properties
- ✅ You want to see CVE per device (after Menu 1)

### Use Menu 5 when:
- ✅ You're not sure which menu to use
- ✅ Your question is complex (combines multiple data types)
- ✅ You want malware/IOC/APT information
- ✅ You want system to auto-detect your question type

---

## 💡 Recommended Workflows

### Workflow 1: Patch Planning
```
Step 1: Menu 1 → Search "log4j"
        → Get: CVEs + affected devices

Step 2: Menu 2 → Report
        → Get: Executive summary with patch timeline

Step 3: Menu 4 → List devices
        → Get: Device inventory for verification
```

### Workflow 2: Threat Research
```
Step 1: Menu 5 → Ask "Tim malware ransomware"
        → Get: 83 results (malware families, detection rules)

Step 2: Menu 5 → Ask "Tim threat actor emotet"
        → Get: Threat actor information and IOC

Step 3: Menu 5 → Ask "Tim device bi anh huong"
        → Get: Device impact (if any CVE matches)
```

### Workflow 3: Complete Security Assessment
```
Step 1: Menu 1 → "log4j"
        → Get: Vulnerabilities + affected devices

Step 2: Menu 5 → "Lay IOC ransomware"
        → Get: Malware detection rules

Step 3: Menu 3 → Upload internal doc
        → Get: Document analysis

Step 4: Menu 2 → Generate report
        → Get: Complete executive summary

Step 5: Menu 4 → List devices
        → Get: Full device inventory with findings
```

---

## ✅ All Capabilities in Menu 5 (Free Query)

You can do **everything** via Menu 5:
- 🔍 Search CVEs: "Quet CVE spring"
- 🦠 Search malware: "Tim malware emotet"
- 👥 Search threat actors: "APT41 chi tiet"
- 🛡️ Check device impact: "Thiet bi nao bi anh huong boi CVE"
- 📊 Generate reports: "Tao bao cao"
- 📄 Upload and analyze: "Upload document"

**Menu 1-4** are shortcuts for common tasks. **Menu 5** does everything.

---

## 🎯 Key Takeaway

The system is now **simpler and cleaner**:
- **No duplicate functionality**
- **Clearer menu structure** (5 options)
- **Menu 5 handles all queries** via smart auto-routing
- **Menu 1 remains for quick CVE + device searches**

