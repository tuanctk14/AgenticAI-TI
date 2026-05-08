# 🔍 ATI-AgenticThreatIntelligence

**Intelligent Threat Analysis System** - A multi-agent cybersecurity platform that combines local LLM reasoning with multiple threat intelligence sources to identify vulnerabilities and correlate threats to your infrastructure.

[![Ollama Local](https://img.shields.io/badge/Ollama-Local%20LLM-blue)](https://ollama.ai)
[![LangGraph](https://img.shields.io/badge/LangGraph-Multi%20Agent-green)](https://langchain.com)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)]()

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Quick Start](#-quick-start)
- [System Architecture](#-system-architecture)
- [Usage Guide](#-usage-guide)
- [Features](#-features)
- [Data Sources](#-data-sources)
- [Configuration](#-configuration)
- [Troubleshooting](#-troubleshooting)

---

## 🎯 Overview

ATI-AgenticThreatIntelligence is an **offline-first** cybersecurity analysis platform that leverages:

- **Local LLM** (Ollama) for reasoning and decision-making
- **Multi-agent system** (LangGraph) for specialized threat analysis
- **Multiple threat sources** (NVD, OpenCTI, Internal KB, CMDB)
- **Intelligent correlation** between CVEs and your infrastructure

### Key Capabilities

✅ **CVE Intelligence** - Fetch and analyze vulnerabilities from NVD in real-time  
✅ **IOC Tracking** - Detect indicators of compromise (malware, APTs, domains, hashes)  
✅ **Device Impact** - Correlate CVEs to devices based on installed software  
✅ **Risk Prioritization** - Automatic CVSS-based severity classification  
✅ **Report Generation** - Executive summaries in HTML format  
✅ **Knowledge Base** - Upload and manage internal threat data  
✅ **Remediation** - Automatic mitigation steps for each vulnerability  
✅ **Offline Operation** - No cloud LLM dependency (uses local Ollama)  

---

## ⚡ Quick Start

### 1. Prerequisites

- **Python 3.11+**
- **Ollama** (running locally on port 11434)
  - Download: https://ollama.ai
  - Start: `ollama serve`
- **qwen2.5:7b model** (pulls automatically or: `ollama pull qwen2.5:7b`)

### 2. Installation

```bash
# Clone repository
git clone <repo-url>
cd ATI-AgenticThreatIntelligence

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Verify Ollama connection
python main.py --check
# ✅ Ollama connection OK - qwen2.5:7b ready
```

### 3. Run the System

**Interactive Mode** (Recommended):
```bash
python main.py
```

Menu options:
1. **CVE Scan** - Search CVEs by keyword and see affected devices
2. **Generate Report** - Create date-range filtered security reports
3. **Upload Document** - Add internal CVE/IOC/Malware data to KB
4. **Free Query** - Ask any cybersecurity question

**Direct Query**:
```bash
python main.py --query "Find CVE-2021-44228 and affected devices"
```

**Example Outputs**:
- `Menu 1`: "Find log4j CVEs" → Lists vulnerabilities + affected servers
- `Menu 2`: "Generate report for 01-05-2026 to 03-05-2026" → HTML with 380 CVEs, 176 IOCs
- `Menu 4`: "tao bao cao 01-05-2026 to 03-05-2026" → Vietnamese report generation

---

## 🏗️ System Architecture

### Directory Structure

```
ATI-AgenticThreatIntelligence/
├── main.py                      # CLI entry point (4 menus + direct queries)
├── config.py                    # Configuration (Ollama, API keys)
│
├── agents/                      # Multi-agent system (7 specialized agents)
│   └── base.py                 # Agent definitions + tool executor
│
├── tools/                       # Integration tools
│   ├── nvd_client.py           # NVD API for CVEs
│   ├── opencti_client.py       # OpenCTI GraphQL for IOC/Malware
│   ├── cmdb.py                 # Device inventory matching
│   ├── doc_store.py            # Knowledge Base management
│   ├── report_generator.py     # HTML report creation
│   ├── analyzer.py             # CVE aggregation & analysis
│   ├── mitre.py                # MITRE ATT&CK mapping
│   └── nist.py                 # NIST 800-53 controls
│
├── core/                        # LangGraph orchestration
│   ├── graph.py                # Workflow DAG + routing
│   ├── state.py                # State schema definition
│   └── ollama_llm.py           # Ollama wrapper
│
├── data/
│   ├── cmdb_devices.json       # 5 sample devices with software
│   └── docs/                   # Knowledge Base
│       ├── cves.json           # User-uploaded CVEs
│       ├── iocs.json           # User-uploaded IOCs
│       └── malwares.json       # User-uploaded malware families
│
├── reports/                     # Generated HTML reports (output)
└── README.md
```

### Agent System (7 Agents)

The system uses **LangGraph** to orchestrate 7 specialized agents:

```
┌─────────────────────────────────────────────────────────────┐
│                    agent_supervisor                          │
│        (Routes query to appropriate agent)                  │
└────────────┬─────────────────────────────────────────────────┘
             │
    ┌────────┼────────────┬──────────────┬───────────────┐
    ▼        ▼            ▼              ▼               ▼
┌────────┐ ┌────────────┐┌──────────┐ ┌────────┐ ┌──────────┐
│agent_ti│ │agent_ti_   ││agent_    │ │agent_  │ │agent_    │
│(CVE)   │ │extended    ││device    │ │matcher │ │reporter  │
│        │ │(IOC/APT)   ││(CMDB)    │ │(Match) │ │(Reports) │
└────────┘ └────────────┘└──────────┘ └────────┘ └──────────┘
    │           │             │           │          │
    │           │             │           │          │
    └───────────┴─────────────┴───────────┴──────────┘
                 │
                 ▼
            ┌──────────┐
            │   TOOLS  │ (NVD, OpenCTI, CMDB, KB, etc.)
            └──────────┘
```

**Agent Routing Logic**:
- **CVE-XXXX-XXXXX or CVE keywords** → `agent_ti`
- **IOC, Malware, APT, hash, domain, IP** → `agent_ti_extended`
- **Device query (SRV-001)** → `agent_device` or `agent_matcher`
- **Report/document** → `agent_reporter` or `agent_doc`

---

## 📖 Usage Guide

### Menu 1: CVE Scan

Find vulnerabilities by keyword and see which devices are affected.

```
Input: "log4j"
Output:
  CVE-2021-44228: RCE in Apache Log4j 2.0-2.14.1 (CVSS 10.0)
  CVE-2021-45046: Denial of Service (CVSS 9.8)
  ...
  
  Affected Devices:
  - SRV-002 (db-server-01): Ubuntu 20.04 with log4j 2.14.1
  - SRV-003 (app-server-01): CentOS 7.9 with Tomcat (vulnerable)
```

### Menu 2: Generate Report

Create security reports filtered by date range with:
- CVE summary (count, severity distribution)
- Device impact analysis
- IOC/Malware intelligence
- MITRE ATT&CK mappings
- Remediation guidance

```
Date Range: 01-05-2026 to 03-05-2026
Output: executive_summary_20260508_161039.html
  - 380 CVEs analyzed
  - 176 IOCs from OpenCTI
  - 4 devices with 38 CVE-device matches
  - Proper IOC type classification (SHA256, YARA, Domain, etc.)
```

### Menu 3: Upload Document

Add internal threat data (CVEs, IOCs, Malware) to the Knowledge Base.

**Supported formats**:
- **.json** - Structured CVE/IOC/Malware objects
- **.txt** - CVE IDs (one per line)
- **.csv** - Tabular threat data

```
File: internal_cves.json
Output:
  ✅ Saved: CVEs=15, IOCs=32, Malwares=8
  Total KB records: CVEs=35, IOCs=65, Malwares=23
```

### Menu 4: Free Query

Ask any cybersecurity question. The supervisor agent routes to the right specialist.

```
Examples:
  "Find CVE-2021-44228 details"
  → agent_ti fetches from NVD, returns severity, description, refs
  
  "What malware families target Windows?"
  → agent_ti_extended queries OpenCTI for malware + Windows targets
  
  "List devices with Spring Framework"
  → agent_device returns all devices with Spring installed
  
  "tao bao cao 01-05-2026 to 03-05-2026"
  → agent_reporter generates Vietnamese report for date range
```

---

## ✨ Features

### 1. Multi-Source Threat Intelligence

| Source | Type | Freshness | Integration |
|--------|------|-----------|-------------|
| **NVD** | CVEs | Real-time | REST API |
| **OpenCTI** | IOC/Malware/APT | Real-time | GraphQL API |
| **Knowledge Base** | Internal threats | User-controlled | JSON storage |
| **CMDB** | Devices | Static (sample) | JSON file |
| **MITRE ATT&CK** | Techniques | Hardcoded | Python dict |
| **NIST 800-53** | Controls | Hardcoded | Python dict |

### 2. Intelligent Risk Prioritization

Automatic severity classification based on:
- **CVSS Score** (National Vulnerability Database)
- **Affected Device Count** (CMDB correlation)
- **Software Criticality Level** (web-facing, data-critical, etc.)

Color-coded output:
```
🔴 CRITICAL: CVSS ≥ 9.0 (immediate action required)
🟠 HIGH:     CVSS 7.0-8.9 (urgent remediation)
🟡 MEDIUM:   CVSS 4.0-6.9 (scheduled patching)
🟢 LOW:      CVSS < 4.0 (monitor and plan)
```

### 3. Automatic Remediation Steps

Generates context-aware mitigation based on CVE type:

```
CVE Type: Remote Code Execution (RCE)
Remediation:
  1. RCE Detection - Scan with antivirus/EDR for backdoors
  2. Firewall Rules - Restrict inbound from untrusted sources
  3. Log Analysis - Search for exploitation indicators
  
CVE Type: SQL Injection
Remediation:
  1. Review SQL queries - Use parameterized statements
  2. Database audit - Check access logs for anomalies
  3. Input validation - Implement WAF rules
```

### 4. Comprehensive Report Generation

5 report types (all HTML format with dark security theme):

1. **executive_summary** - High-level risk overview
2. **vulnerability_assessment** - Detailed CVE analysis
3. **patch_advisory** - Remediation timelines
4. **threat_intel** - IOC and malware details
5. **incident_report** - Full incident response docs

Each report includes:
- Summary statistics and charts
- Detailed CVE listings with CVSS, severity, references
- Device impact matrix (which devices affected by which CVEs)
- MITRE ATT&CK technique mappings
- NIST SP 800-53 control recommendations
- Remediation steps prioritized by risk
- IOC indicators with confidence scores

### 5. Offline-First Design

✅ **No cloud LLM required** - Uses local Ollama  
✅ **No external API calls for LLM** - All reasoning happens locally  
✅ **Secure by default** - Data never leaves your infrastructure  
✅ Optional external APIs: NVD, OpenCTI (can be disabled)

### 6. Vietnamese Language Support

Full UI and output in Vietnamese:
- Menu labels and prompts
- Report titles and content
- Agent responses
- Error messages

---

## 📊 Data Sources

### NVD (National Vulnerability Database)

**What**: CVE vulnerability data  
**Endpoint**: https://services.nvd.nist.gov/rest/json/cves/1.0  
**Freshness**: Real-time (daily updates)  
**Usage**: Menu 1, Menu 2, agent_ti  
**Optional**: Can work offline using KB only

### OpenCTI (Open Cyber Threat Intelligence)

**What**: IOC, Malware families, APTs, Attack patterns  
**Protocol**: GraphQL API  
**Freshness**: Real-time (minutes)  
**Usage**: Menu 4 IOC queries, agent_ti_extended  

### Local Knowledge Base

**What**: User-uploaded CVEs, IOCs, Malware definitions  
**Format**: JSON (auto-generated from uploads)  
**Location**: `data/docs/`  
**Usage**: Menu 3 upload, fetched by agents as fallback source

### CMDB (Device Inventory)

**What**: 5 sample devices with installed software  
**Format**: JSON  
**Location**: `data/cmdb_devices.json`  
**Devices**:

1. **SRV-001** (web-server) - Apache 2.4.49, OpenSSL 1.0.2k, PHP 7.4.3
2. **SRV-002** (database) - MySQL 8.0.26, OpenSSH 8.2p1, log4j 2.14.1
3. **PC-001** (workstation) - Office 2019, Chrome 109, Adobe Acrobat
4. **FW-001** (firewall) - Cisco IOS 15.7
5. **SRV-003** (app-server) - Spring 5.3.18, Tomcat 9.0.58, OpenJDK 11

---

## ⚙️ Configuration

**File**: `config.py`

### Essential Settings

```python
# Ollama Local LLM
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL = "qwen2.5:7b"

# OpenCTI (Optional)
OPENCTI_URL = "http://localhost:8000"
OPENCTI_TOKEN = "your-token-here"

# NVD API (Optional)
NVD_API_KEY = ""  # Get from https://nvd.nist.gov/developers

# Output Directory
REPORTS_DIR = "./reports"
MAX_STEPS = 20
```

---

## 🔧 Troubleshooting

### Issue: "❌ Ollama connection failed"

**Fix**: Start Ollama service
```bash
ollama serve
```

### Issue: "NVD API rate limited"

**Fix**: Get free API key from https://nvd.nist.gov/developers/request-an-api-key

### Issue: "ImportError: No module named 'langgraph'"

**Fix**: Install dependencies
```bash
pip install -r requirements.txt
```

---

## 📞 Support

For issues:
- Verify Ollama is running: `python main.py --check`
- Check config.py settings
- Review agent execution logs
- Ensure data sources are accessible

---

**Version**: 1.0.0 | **Status**: ✅ Production Ready | **Updated**: 2026-05-08
Supervisor Agent (điều phối)
    ├── TI Agent        → NVD API / Mock data
    ├── Matcher Agent   → CMDB matching
    ├── Analyst Agent   → MITRE ATT&CK / NIST
    ├── Doc Agent       → ChromaDB / RAG
    └── Reporter Agent  → Tạo báo cáo MD/TXT
```

## Yêu cầu hệ thống

| Thành phần | Yêu cầu tối thiểu |
|---|---|
| RAM | 8 GB (khuyến nghị 16 GB) |
| GPU | Tuỳ chọn (CPU cũng chạy được) |
| Disk | 5-10 GB cho model |
| Python | 3.10+ |
| Ollama | v0.1.x trở lên |

## Cài đặt nhanh

```bash
# 1. Cài Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull model (chọn 1 trong các model sau)
ollama pull llama3.2        # 3B - nhẹ nhất, ~2GB RAM
ollama pull llama3.1        # 8B - cân bằng, ~5GB RAM  
ollama pull qwen2.5         # 7B - tốt tiếng Việt, ~4GB RAM
ollama pull mistral         # 7B - nhanh, ~4GB RAM

# 3. Cài dependencies Python
pip install -r requirements.txt

# 4. Cấu hình
cp .env.example .env
# Chỉnh sửa .env theo nhu cầu

# 5. Chạy
python main.py
```

## Cấu trúc thư mục

```
cybersec-ollama/
├── main.py              # Entry point - CLI interface
├── config.py            # Cấu hình toàn cục
├── requirements.txt     # Dependencies
├── .env.example         # Mẫu cấu hình
├── agents/
│   ├── supervisor.py    # Agent điều phối
│   ├── ti_agent.py      # Threat Intelligence Agent
│   ├── matcher.py       # CMDB Matcher Agent
│   ├── analyst.py       # Risk Analysis Agent
│   ├── doc_agent.py     # Document/RAG Agent
│   └── reporter.py      # Report Generator Agent
├── tools/
│   ├── nvd_client.py    # NVD API client
│   ├── opencti_client.py # OpenCTI client
│   ├── cmdb.py          # CMDB matching
│   ├── mitre.py         # MITRE ATT&CK lookup
│   └── nist.py          # NIST controls mapping
├── core/
│   ├── state.py         # LangGraph state schema
│   ├── graph.py         # Workflow graph builder
│   └── ollama_llm.py    # Ollama LLM wrapper
├── data/
│   └── cmdb_devices.json # Mock CMDB data
└── reports/             # Báo cáo được lưu tại đây
```

## Sử dụng

```bash
# Chế độ interactive (menu)
python main.py

# Câu lệnh trực tiếp
python main.py --query "Quét CVE Log4Shell và tìm thiết bị bị ảnh hưởng"

# Chạy test cases
python main.py --test
```

## Models được hỗ trợ

| Model | RAM | Chất lượng tiếng Việt | Tốc độ |
|---|---|---|---|
| llama3.2:3b | ~2GB | Tốt | Rất nhanh |
| llama3.1:8b | ~5GB | Tốt | Nhanh |
| qwen2.5:7b | ~4GB | Xuất sắc | Nhanh |
| mistral:7b | ~4GB | Khá | Rất nhanh |
| llama3.1:70b | ~40GB | Xuất sắc | Chậm |
