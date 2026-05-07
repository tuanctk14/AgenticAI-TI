# CyberSec Multi-Agent System - User Guide

**Hệ thống An Toàn Mạng Đa Tác Nhân với CVE & IOC Intelligence**

---

## Quick Start (2 phút)

### 1. Kiểm tra kết nối
```bash
python main.py --check
```
✅ Nếu in "✅ OK" → Hệ thống sẵn sàng

### 2. Chạy chế độ tương tác
```bash
python main.py
```

### 3. Chọn chức năng từ menu:
```
1. Quet CVE va tim thiet bi bi anh huong              [CVE Scanning with Device Impact]
2. Tao bao cao                                        [Report Generation]
3. Upload / xu ly tai lieu noi bo                     [Document Handling]
4. Liet ke thiet bi trong CMDB                        [Device Inventory]
5. Cau hoi tu do - IOC/Malware/APT/CVE                [Free Query - Ask Anything]
0. Thoat                                              [Exit]
```

---

## Usage Examples

### 📊 Example 1: Scan CVE Log4j
```
Query: "Quet CVE Log4j va tim thiet bi bi anh huong"

Result:
  ✅ Found 10 CVEs
  ✅ Matched to 2 devices
  ✅ Device SRV-002 has 3 CVEs (severity HIGH)
  ✅ Device SRV-001 has 2 CVEs (severity MEDIUM)
```

### 🔍 Example 2: Get Ransomware IOC
```
Query: "Lay IOC malware ransomware"

Result:
  ✅ Found 4 IOC indicators
  ✅ Malware families:
     - Mallox ransomware
     - CactusRansomware
  ✅ Confidence: 100%
```

### 👥 Example 3: Threat Actor Intelligence
```
Query: "Tim threat actor APT"

Result:
  ✅ Found 37 APT indicators
  ✅ Malware hashes with threat actor attribution
  ✅ Real-time data from OpenCTI
```

### 🏢 Example 4: List CMDB Devices
```
Query: "Liet ke thiet bi trong CMDB"

Result:
  ✅ 5 devices found:
     - SRV-001 (web-server-01)
     - SRV-002 (db-server-01)
     - ... and 3 more
```

---

## How It Works

### Smart Router (Supervisor Agent)
Hệ thống tự động nhận diện loại truy vấn:

| You Ask | System Routes | Gets Data From | Returns |
|--------|---|---|---|
| "CVE log4j" | → CVE Agent | NVD API | Vulnerabilities + Affected Devices |
| "IOC emotet", "Malware ransomware", "APT41" | → IOC Agent | OpenCTI API | Indicators, Hashes, Threat Actors, Confidence Scores |
| "Thiết bị" | → Device Matcher | CMDB | Device List + CVE Mappings |
| "Báo cáo" | → Reporter | Generated | Executive Summary Report |

### Two Data Sources

**1. CVE Data (NVD)**
- Official CVE database
- CVSS scores
- Affected products
- Real-time updates

**2. IOC Data (OpenCTI)**
- Malware indicators
- File hashes
- C2 infrastructure
- Threat actor profiles
- 100% confidence scores

---

## Key Features

### ✅ CVE Vulnerability Scanning (Menu Option 1)
**What it does:** Searches NVD for vulnerabilities and automatically matches them to your devices
- Search CVEs by keyword (log4j, apache, etc.)
- Filter by severity (HIGH, CRITICAL)
- Automatically matches CVEs to devices in your CMDB inventory
- Shows which devices are affected by which CVE
- Get device-level impact assessment

**Example:** Menu 1 → Enter "log4j" → Get: 10 CVEs + 2 affected devices with specific CVE mappings

### ✅ Report Generation (Menu Option 2)
**What it does:** Creates executive summary reports based on collected data
- Aggregates findings from previous queries
- Risk assessment and prioritization
- Timeline recommendations
- Saves report to `./reports/` directory

### ✅ Free Query - All Data Sources (Menu Option 5)
**What it does:** Ask anything - system auto-detects and routes to right agent
- **CVE queries:** "Quet CVE log4j" → Routes to CVE Agent → Device Matcher
- **IOC/Malware queries:** "Tim malware ransomware" → Routes to IOC Agent
- **Threat actor queries:** "APT41 chi tiet" → Routes to IOC Agent
- **Device queries:** "Thiet bi nao bi anh huong" → Routes to Device Agent
- **Report queries:** "Tao bao cao" → Routes to Reporter

**Example:** Menu 5 → Enter "malware emotet" → Get: All malware families, detection rules, threat associations

### ✅ Device Management
- List all devices
- Check software inventory
- See affected devices per CVE
- Device criticality levels

### ✅ Report Generation
- Executive summaries
- Risk dashboards
- Device impact lists
- Timeline recommendations

---

## Query Types Supported

### CVE Queries
```
"Quet CVE log4j"
"Lay CVE high severity"
"Quet lo hong Apache"
"Quet cve 2021-44228"
"CVE scan spring framework"
```

### IOC/Malware Queries
```
"Lay IOC emotet"
"Tim malware ransomware"
"Lay threat actor APT41"
"Quet C2 infrastructure"
"Lay file hash malware"
```

### Device Queries
```
"Liet ke thiet bi"
"Thiet bi nao bi anh huong"
"Quet device trong CMDB"
```

### Report Queries
```
"Tao bao cao"
"Tao executive summary"
"List reports"
```

---

## Command Line Usage

### Query with result
```bash
python main.py -q "Quet CVE log4j"
```

### Check connection
```bash
python main.py --check
```

### Run tests
```bash
python main.py --test
```

---

## What Each Agent Does

### 🤖 Supervisor Agent
- Reads your question
- Detects query type (CVE vs IOC)
- Routes to right specialist
- Never answers, only routes

### 🤖 CVE Agent (agent_ti)
- Searches NVD for CVEs
- Gets CVE details
- Hands off to matcher for devices

### 🤖 IOC Agent (agent_ti_extended)
- Queries OpenCTI for indicators
- Gets malware/APT info
- Returns confidence scores

### 🤖 Matcher Agent
- Matches CVEs to your devices
- Shows affected devices
- Groups by device

### 🤖 Reporter Agent
- Creates executive summaries
- Risk dashboards
- Severity reports

---

## Interpreting Results

### CVE Results Include:
```
- CVE ID (e.g., CVE-2021-44228)
- CVSS Score (0-10)
- Severity Level (LOW, MEDIUM, HIGH, CRITICAL)
- Description
- Affected Devices
- Risk Assessment
```

### IOC Results Include:
```
- IOC Type (malware, threat_actor, etc.)
- Name/Description
- Confidence Score (%)
- Threat Actor Attribution
- Pattern/Hash
- Real-time source (OpenCTI)
```

---

## Troubleshooting

### Problem: System won't start
**Solution:**
```bash
# Check Ollama is running
python main.py --check

# If fails, start Ollama
ollama serve
```

### Problem: No CVE results
**Solution:**
```
- Try different keyword: "Apache" instead of "HTTPd"
- Check network connectivity to NVD
- Try with severity filter: "HIGH"
```

### Problem: No IOC results
**Solution:**
- Check OPENCTI_TOKEN is set correctly
- Try simpler search: "APT" instead of "APT41"
- Verify OpenCTI server is running
- Check network access to 157.66.26.232:8080

### Problem: Device matching shows 0
**Solution:**
- Devices may not have matching software
- Check device CMDB data
- Try different CVE keyword

---

## Best Practices

### 1. Start with Specific Searches
✅ Good: "Quet CVE log4j severity HIGH"
❌ Bad: "Quet lo hong"

### 2. Use Keywords
✅ "CVE", "IOC", "malware", "threat actor"
✅ "device", "CMDB", "thiết bị"
✅ "report", "bảo cáo"

### 3. Check Results Carefully
- Note CVSS scores
- Check device criticality
- Review confidence scores

### 4. Generate Reports
```
Query: "Tao bao cao"
Get: Executive summary with all findings
```

---

## Data Sources

| Data Type | Source | Updates |
|---|---|---|
| CVE | NVD (nist.gov) | Real-time |
| IOC | OpenCTI | Real-time |
| Devices | Local CMDB | Manual |
| Reports | Generated | Per request |

---

## Limits & Performance

| Operation | Limit | Time |
|---|---|---|
| CVE per query | 10 results | 2-3s |
| IOC per query | 50 results | 2-3s |
| Device list | All in CMDB | 1s |
| Report generation | Unlimited | 1-2s |

---

## Keyboard Shortcuts

```
[Enter]  - Continue after results
[Ctrl+C] - Exit (anytime)
[0]      - Exit from menu
```

---

## Example Workflow

**Scenario: Security Check for Web Servers**

```
Step 1: List devices
Q: "Liet ke thiet bi"
A: [Shows 5 devices]

Step 2: Check log4j CVE
Q: "Quet CVE log4j"
A: [10 CVEs found, 2 devices affected]

Step 3: Check ransomware IOC
Q: "Lay IOC malware ransomware"
A: [4 indicators, confidence 100%]

Step 4: Generate report
Q: "Tao bao cao"
A: [Executive summary created]
```

---

## Support & Help

### System Status
```bash
python main.py --check
```

### View Results
Reports are saved in `./reports/` directory

### Configuration
Edit `.env` file for OpenCTI settings:
```
OPENCTI_URL=http://157.66.26.232:8080/
OPENCTI_TOKEN=your_token_here
```

---

## Security Notes

⚠️ **Keep OpenCTI Token Secret**
- Never share OPENCTI_TOKEN
- Never commit .env to git
- Rotate tokens regularly

⚠️ **Data Privacy**
- Results contain sensitive information
- Keep reports secure
- Don't share CVE lists publicly

---

## Menu Translation

| Menu Item | Vietnamese | English | Function | Data Source |
|---|---|---|---|---|
| **1** | Quet CVE | Scan CVE | Search vulnerabilities & affected devices | NVD API |
| **2** | Tao bao cao | Generate Report | Create executive summary | All collected data |
| **3** | Upload tai lieu | Upload document | Add/analyze documents | User input |
| **4** | Liet ke thiet bi | List devices | Show inventory & CVE mappings | CMDB |
| **5** | Cau hoi tu do | Free query | Ask anything (auto-routed) - CVE/IOC/Malware/APT/Device | All sources |

---

## Tips for Better Results

1. **Be Specific**
   - "Log4j" better than "Java"
   - "Ransomware" better than "malware"
   - "APT41" better than "APT"

2. **Use Multiple Queries**
   - First: Search CVE
   - Second: Check IOC
   - Third: View devices
   - Fourth: Generate report

3. **Cross-Reference**
   - Match CVE results with IOC
   - Check affected devices
   - Review confidence scores

---

## Frequently Asked Questions

**Q: How often are CVEs updated?**
A: Real-time from NVD API

**Q: How often are IOC updated?**
A: Real-time from OpenCTI

**Q: Can I export results?**
A: Reports are saved as files in ./reports/

**Q: Is data stored locally?**
A: Chat history in memory, reports on disk

**Q: Can I search for older CVEs?**
A: Yes, NVD has all historical CVEs

**Q: Is this tool for production?**
A: Yes, all systems production-ready

---

## Getting Started Checklist

- [ ] Run `python main.py --check`
- [ ] Try menu option 5 (List devices)
- [ ] Search a CVE ("log4j")
- [ ] Search IOC ("ransomware")
- [ ] Generate a report
- [ ] Check ./reports/ folder

**You're ready to use the system! 🚀**

---

**Need Help? System is self-documenting - Ask it anything!**
```
python main.py
→ Select option 6: "Cau hoi tu do"
→ Ask any security question
```
