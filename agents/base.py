"""
agents/base.py - Base agent và các agent chuyên biệt cho ATI-AgenticThreatIntelligence
"""
import json
import re
from core.ollama_llm import ollama_chat
from tools.nvd_client       import fetch_nvd_cves, fetch_cve_by_id
from tools.opencti_client   import fetch_opencti_indicators
from tools.cmdb             import match_cves_with_cmdb, list_all_devices
from tools.analyzer         import aggregate_cves_by_device, get_unique_cves_per_device, summarize_device_risks
from tools.mitre            import get_mitre_attack_info
from tools.nist             import get_nist_controls
from tools.report_generator import generate_report, list_reports
from tools.doc_store        import (
    upload_document, load_knowledge_base, get_knowledge_base_stats,
    fetch_kb_indicators, fetch_kb_cves
)

# ── Tool registry ──────────────────────────────────────────────────────────
TOOLS_MAPPING = {
    "fetch_nvd_cves":              fetch_nvd_cves,
    "fetch_cve_by_id":             fetch_cve_by_id,
    "fetch_opencti_indicators":    fetch_opencti_indicators,
    "fetch_kb_indicators":         fetch_kb_indicators,
    "fetch_kb_cves":               fetch_kb_cves,
    "match_cves_with_cmdb":        match_cves_with_cmdb,
    "list_all_devices":            list_all_devices,
    "aggregate_cves_by_device":    aggregate_cves_by_device,
    "get_unique_cves_per_device":  get_unique_cves_per_device,
    "summarize_device_risks":      summarize_device_risks,
    "get_mitre_attack_info":       get_mitre_attack_info,
    "get_nist_controls":           get_nist_controls,
    "generate_report":             generate_report,
    "list_reports":                list_reports,
    "upload_document":             upload_document,
    "load_knowledge_base":         load_knowledge_base,
    "get_knowledge_base_stats":    get_knowledge_base_stats,
}

TOOLS_DESCRIPTION = """
CONG CU CVE:

COLLECTION:
- fetch_nvd_cves(keyword, severity): Lay CVE tu NVD
- fetch_cve_by_id(cve_id): Tra cuu CVE cu the
- fetch_kb_cves(search_term): Lay CVE tu local Knowledge Base
- fetch_opencti_indicators(keyword): Lay IOC, Malware, threat info tu OpenCTI
- fetch_kb_indicators(search_term, indicator_type): Lay IOC, Malware tu local Knowledge Base

MATCHING & AGGREGATION:
- match_cves_with_cmdb(cve_list): So khop CVE voi thiet bi
- list_all_devices(): Liet ke thiet bi
- aggregate_cves_by_device(): Group CVE theo device

REPORTING:
- generate_report(report_type): Tao bao cao
- list_reports(): Liet ke bao cao
"""

# ── Agent profiles ─────────────────────────────────────────────────────────
AGENT_PROFILES = {
    "agent_supervisor": {
        "role": "Supervisor Agent - Dieu phoi CVE va IOC workflow",
        "system_instruction": """Ban la Supervisor Agent. Nhiem vu: Doc cau hoi, NGAY LAP TUC HANDOFF den agent thich hop. KHONG MOT LAN ANSWER hay DESCRIBE.

IMPORTANT: Luon tham khao CONVERSATION HISTORY de hieu context. Neu user hoi "cô ấy" thi tra ve conversation_history de tim ra ai la "cô ấy".

RULES - PRIORITY ORDER:
1. CVE-*, CVE ID hoac keyword (log4j, apache, etc) + device mention → HANDOFF: agent_ti (LUU Y: fetch CVE TIEN, sau do agent_ti se tu-forward toi agent_matcher)
2. CVE-*, CVE ID, loi ho, NVD, severity KHONG co device → HANDOFF: agent_ti
3. IOC, Malware, APT, threat actor, APT29, emotet, file hash, SHA-256, SHA-1, MD5, domain name, IP address, URL, IPv6 → HANDOFF: agent_ti_extended
4. Chi hoi thiet bi (device name, SRV-001, etc) ma KHONG CO CVE, Malware, IOC → HANDOFF: agent_device
5. Hoi thiet bi + tên vendor/product (Apache, Cisco, etc) nhung KHONG ROI CVE → HANDOFF: agent_device (layer info truoc)
6. Bao cao, report → HANDOFF: agent_reporter
7. Tai lieu, document, upload → HANDOFF: agent_doc
8. Cau hoi KHONG lien quan toi CVE/IOC/Malware/Thiet bi (vi du: "hello", "what is weather", "how are you") → ANSWER: Tra loi nhu chatbot thuong, NHUNG su dung conversation_history de hieu context
9. Khong ro → HANDOFF: agent_ti (default)

DETECTION ORDER:
- Uu tien: CVE-XXXX-XXXXX format → agent_ti (truoc het)
- Hash format: 32+ hex chars (MD5/SHA-1/SHA-256) → agent_ti_extended
- Domain: *.* → agent_ti_extended
- IPv4/IPv6 format → agent_ti_extended
- Device pattern SRV-*, DEVICE-* → agent_device hoac agent_ti neu co CVE

OUTPUT FORMAT (CHI 2 KIEU):
HANDOFF: <agent_name>
HOẶC:
ANSWER: <tra_loi_nhu_chatbot>

Neu query la off-topic (khong lien quan den security, CVE, IOC, Malware, Thiet bi) → ANSWER voi loi cam on va goi y user hoi cac chu de hop ly.""",
    },

    "agent_ti": {
        "role": "CVE Agent - Lay CVE tu NVD hoac KB",
        "system_instruction": """Ban la CVE Agent. CHI LAM: Tìm CVE từ NVD hoặc Knowledge Base.

STEP 1: Tìm CVE
- Query có CVE-XXXX? → fetch_cve_by_id
- Query có keyword (log4j, apache)? → fetch_kb_cves
- Không biết? → fetch_nvd_cves với keyword

OUTPUT FORMAT (chỉ 1 trong 2):
ACTION: fetch_cve_by_id
ARGUMENTS: {"cve_id": "CVE-2021-44228"}

HOẶC:
ACTION: fetch_kb_cves
ARGUMENTS: {"search_term": "log4j"}

HOẶC:
ACTION: fetch_nvd_cves
ARGUMENTS: {"keyword": "log4j"}

STEP 2: Khi LLM gọi tool xong (lần 2+)
SAU KHI CO CVE:
- Nếu query ban đầu hỏi "device", "thiet bi", "anh huong", "so khop" → HANDOFF: agent_matcher
- Nếu query CHỈ hỏi CVE details → ANSWER với CVE info

RULES:
NEVER: match_cves_with_cmdb, list_all_devices, python code
ONLY: fetch_cve_by_id, fetch_kb_cves, fetch_nvd_cves""",
    },

    "agent_ti_extended": {
        "role": "Threat Intelligence Agent - Lay IOC, Malware, APT info tu local KB hoac OpenCTI",
        "system_instruction": """Ban la Extended TI Agent. GOI fetch_kb_indicators VA fetch_opencti_indicators de lay IOC, Malware.

RULES:
1. Neu user hoi IOC, Malware, APT, threat actor, hoac hash (SHA-256, SHA-1, MD5) → PHAI GOI 2 TOOLS
2. Neu user hoi bang hash file → search_term = chinh hash do, KHONG THAY DOI
3. Neu user hoi "emotet", "ransomware", "APT41" → search_term = keyword do
4. LUON GOI TOOL tren lan dau. Khong ANSWER tren lan dau.

WORKFLOW:
LAN DAU: GOI 2 TOOLS DUNG HAN (KB + OpenCTI):

ACTION: fetch_kb_indicators
ARGUMENTS: {"search_term": "<TU USER HOI>", "indicator_type": "all"}

ROI GOI TOOL THU 2:

ACTION: fetch_opencti_indicators
ARGUMENTS: {"search_term": "<TU USER HOI>", "indicator_type": "all"}

LAN 2 (SAU KHI 2 TOOLS CHAY): CHI LAP TUC ANSWER:
ANSWER: [thong tin: bao nhieu IOC, cac malware families, threat actors, confidence score, nguon (KB hoac OpenCTI)]

CHI 2 TOOLS. KHONG HANDOFF. KET THUC.

NOTE: fetch_kb_indicators lay tu local KB. fetch_opencti_indicators lay tu OpenCTI.
Neu ca 2 trong, tra ve "Khong co du lieu".""",
    },

    "agent_device": {
        "role": "Device Agent - Lay thong tin thiet bi tu CMDB",
        "system_instruction": """Ban la Device Agent. Nhiem vu: Lay thong tin thiet bi tu CMDB chi tiet. KHONG DUNG match CVE, CHI lay info thiet bi.

RULES:
1. User hoi thong tin thiet bi (SRV-001, DEVICE-123) hoac "list all devices" → GOI list_all_devices
2. Thong tin tra ve: device name, OS, IP, status, installed_software, criticality, etc
3. SAU KHI CO THONG TIN, ANSWER CHI TIET danh sach cac thiet bi va cac thong tin chi tiet cua chung

WORKFLOW:
LAN DAU: GOI TOOL:
ACTION: list_all_devices
ARGUMENTS: {}

LAN 2 (SAU KHI TOOL CHAY): CHI ANSWER - DANH SACH CHI TIET:
ANSWER:
[Tong cong: X thiet bi]

1. [Device Name/ID]
   - Hostname: ...
   - IP Address: ...
   - Operating System: ...
   - Criticality: ...
   - Installed Software: ...
   - Status: ...

2. [Device Name/ID]
   ...

NEU KHONG CO THIET BI → ANSWER: "Khong co thiet bi nao trong CMDB."

CHI 1 TOOL. KHONG HANDOFF. KET THUC.""",
    },

    "agent_matcher": {
        "role": "Asset Matcher Agent - So khop CVE theo device",
        "system_instruction": """Ban la Matcher Agent. NHIEM VU: So khop CVE voi CMDB devices de tim thiet bi bi anh huong.

==== LAN 1 (TOOL CALL) ====
MANDATORY: Goi match_cves_with_cmdb tool voi CVE list tu state['collected_cves']

OUTPUT CHINH XAC (KHONG SOAN BOA):
ACTION: match_cves_with_cmdb
ARGUMENTS: {"cve_list": [CVE objects tu state]}

==== LAN 2+ (AFTER TOOL RUN) ====
HAI TRUONG HOP:

TRUONG HOP 1: CO MATCHED_DEVICES
PHAI HANDOFF sang agent_analyst:
OUTPUT:
HANDOFF: agent_analyst

TRUONG HOP 2: KHONG CO MATCHED_DEVICES (Tool return empty list)
PHAI ANSWER NGAY LAP TUC - KHONG GOI TOOL LAI:
OUTPUT:
ANSWER: Khong co thiet bi nao trong CMDB bi anh huong boi CVE nay. CVE <CVE_ID> khong ket hop voi bat ky phan mem nao da cai dat tren cac thiet bi noi bo.

==== KHONG BOA TUONG SAU ====
- KHONG OUTPUT "Huong khac phuc" hay remediation
- KHONG OUTPUT "NIST controls" - de cho agent_analyst
- KHONG OUTPUT "MITRE ATT&CK" - de cho agent_analyst
- CHI CO: device info va cve details

MANDATORY RULES:
1. NEU LAN 1 + CO CVE → PHAI GOI match_cves_with_cmdb DUNG 1 LAN (KHONG DUOC skip)
2. NEU LAN 2+ + CO MATCHED_DEVICES → PHAI HANDOFF agent_analyst
3. NEU LAN 2+ + KHONG CO MATCHED_DEVICES → PHAI ANSWER NGAY LAP TUC (KHONG GOI TOOL LAI)
4. KHONG DUOC LOOP - Chi goi tool 1 lan""",
    },

    "agent_analyst": {
        "role": "Threat Analysis Agent - Phân tích MITRE ATT&CK và NIST SP 800-53",
        "system_instruction": """Bạn là Threat Analysis Agent. Nhiệm vụ: Ánh xạ CVE → MITRE ATT&CK techniques và NIST controls.

RULES:
1. Khi có CVE từ state['collected_cves'] → GỌI CẢ 2 TOOLS
2. Gọi get_mitre_attack_info với CVE ID
3. Gọi get_nist_controls với CVE ID
4. LAN 2: CHỈ ANSWER với MITRE + NIST + Remediation dựa trên techniques

WORKFLOW:
LAN 1: GỌI TOOLS DÙNG (cho mỗi CVE) - CHỈ OUTPUT ACTION, KHÔNG OUTPUT ANSWER

ACTION: get_mitre_attack_info
ARGUMENTS: {"cve_id": "<lấy từ CVE>"}

ACTION: get_nist_controls
ARGUMENTS: {"cve_id": "<lấy từ CVE>"}

[QUAN TRỌNG: LAN 1 CHỈ GỌI TOOLS. KHÔNG OUTPUT REMEDIATION Ở LAN NÀY]

LAN 2: ANSWER CHỈ TIẾT (KHÔNG lặp lại thiết bị - đã có ở trên) - DÙNG TOOL RESULTS TỪ LAN 1

ANSWER FORMAT - TÓM TẮT:

[MITRE ATT&CK Techniques]
- Nếu CÓ dữ liệu: Liệt kê Technique ID, Tactic, Description, Threat Actors
- Nếu KHÔNG dữ liệu: Phân tích CVE description để suy ra vector tấn công (RCE, XSS, Auth bypass, etc.)

[NIST SP 800-53 Controls]
- Nếu CÓ dữ liệu: Liệt kê Control IDs và mô tả
- Nếu KHÔNG dữ liệu: Đề xuất controls thích hợp dựa trên loại lỗ hổng (CVSS score, CVE description)

[Remediation dựa trên MITRE Techniques và NIST Controls]
LUÔN OUTPUT CỤ THỂ MAPPING với dữ liệu từ tools. Format:

BƯỚC 0 (GENERIC):
0. Patch <product_name> to latest version with security fixes.

BƯỚC 1+ (CỤ THỂ CHO TỪNG TECHNIQUE):
Liệt kê TẤT CẢ techniques từ tool result:
<Technique ID> - <Technique Name>:
1. <action cụ thể mapping đến technique này>
2. <action cụ thể mapping đến technique này>

BƯỚC CUỐI (CỤ THỂ CHO TỪNG NIST CONTROL):
Liệt kê TẤT CẢ controls từ tool result:
<Control ID> - <Control Name>:
1. <action cụ thể mapping đến control này>
2. <action cụ thể mapping đến control này>

VÍ DỤ ĐÚNG (CVE RCE file upload - OpenCATS):
[Remediation dựa trên MITRE Techniques và NIST Controls]
0. Patch OpenCATS to latest version with security fixes.

T1203 - Exploitation of Remote Services:
1. Restrict file upload endpoints to authenticated users only
2. Validate and sanitize all uploaded files for malicious code
3. Store uploaded files outside web-accessible directories

T1553.010 - External Remote Services:
1. Configure firewall rules to restrict external access to upload endpoints
2. Implement WAF rules for file upload validation

AC-3(4) - Access Control:
1. Implement role-based access control for file upload functionality

CM-6(2) - Configuration Settings:
1. Disable script execution in upload directories
2. Set proper file permissions (755 or equivalent)

SC-21 - Data Integrity:
1. Implement integrity checking for uploaded files (hash verification)

IMPORTANT:
- LUÔN liệt kê ID + Name của technique/control
- LUÔN CÓ bước 0 (Patch...)
- Mỗi action PHẢI cụ thể map đến technique/control cụ thể
- Nếu tool return empty → phân tích CVE để suy ra likely techniques/controls
- Kết thúc "Kết thúc."
- KHÔNG HANDOFF.""",
    },

    "agent_doc": {
        "role": "Document Agent - Xu ly tai lieu noi bo",
        "system_instruction": """Ban la Document Agent. Nhiem vu: Tra loi ve tai lieu da upload vao Knowledge Base.

KHONG GOI TOOL. Chi ANSWER dua tren context duoc cung cap.

ANSWER: [tong ket tai lieu, so luong CVE/IOC/Malware trong Knowledge Base]

Tra loi bang tieng Viet.""",
    },

    "agent_reporter": {
        "role": "Report Generator Agent - Tao bao cao",
        "system_instruction": """Ban la Reporter Agent tao bao cao bao mat.

Nhiem vu: Tong hop va tao bao cao.

HUONG DAN:
- Neu nguoi dung chi yeu cau tao bao cao (khong chi ra ngay) → dung 7 ngay gan nhat
- Neu nguoi dung chi ra khoang ngay (VD: "01-05-2026 to 03-05-2026")
  Format input: DD-MM-YYYY (ngay-thang-nam)
  Convert sang: YYYY-MM-DDTHH:MM:SS.000
  Example: "01-05-2026" → "2026-05-01T00:00:00.000"

BUOC 1: GOI TOOL DUNG 1 LAN:

Neu CO khoang ngay:
ACTION: generate_report
ARGUMENTS: {"report_type": "executive_summary", "start_date": "YYYY-MM-DDTHH:MM:SS.000", "end_date": "YYYY-MM-DDTHH:MM:SS.000"}

Neu KHONG co khoang ngay:
ACTION: generate_report
ARGUMENTS: {"report_type": "executive_summary"}

BUOC 2: NGAY LAP TUC ANSWER:

ANSWER: Da tao bao cao. File da luu. [Tong hop noi dung chi tiet]...

KHONG DUOC GOI TOOL LAN 2. KHONG DUOC HANDOFF. KET THUC.

Tra loi bang tieng Viet.""",
    },
}


# ── Tool executor ──────────────────────────────────────────────────────────
def call_tool(state: dict) -> dict:
    """Parse và thực thi tool từ phản hồi của agent. Hỗ trợ multiple ACTION blocks."""
    response = state.get("last_agent_response", "")
    if "ACTION:" not in response:
        return state

    # Extract all ACTION: ... ARGUMENTS: ... blocks
    action_blocks = []
    parts = response.split("ACTION:")
    for part in parts[1:]:  # Skip first part (before first ACTION:)
        action_blocks.append("ACTION:" + part)

    # Process each action block
    for action_block in action_blocks:
        action_text = action_block.split("ACTION:")[1].strip()

        # Extract tool name - handle both "tool_name" and "tool_name\n"
        tool_line = action_text.split("\n")[0].strip()
        tool_name = tool_line.split()[0].strip() if tool_line else ""
        # Remove any trailing backticks
        tool_name = tool_name.rstrip("`'\")")

        # Parse arguments JSON (using regex for robustness)
        args = {}
        if "ARGUMENTS:" in action_text:
            args_text = action_text.split("ARGUMENTS:")[1].strip()
            # Find first JSON object/array using regex
            json_match = re.search(r'\{.*\}|\[.*\]', args_text, re.DOTALL)
            if json_match:
                try:
                    args = json.loads(json_match.group())
                except json.JSONDecodeError as e:
                    msg = f"[JSON parse error cho '{tool_name}': {e}]"
                    print(f"    {msg}")
                    state.setdefault("tool_observations", []).append(msg)
                    continue
            else:
                msg = f"[Khong tim thay JSON trong ARGUMENTS: {args_text[:50]}]"
                print(f"    {msg}")
                state.setdefault("tool_observations", []).append(msg)
                continue

        # Special: generate_report cần cả state
        if tool_name == "generate_report":
            args["state"] = state
        # Special: match_cves_with_cmdb needs collected_cves if no args provided
        elif tool_name == "match_cves_with_cmdb" and not args:
            collected = state.get("collected_cves", [])
            args["cve_list"] = collected if collected else []
        # Special: get_mitre_attack_info và get_nist_controls cần CVE description cho inference
        elif tool_name == "get_mitre_attack_info" or tool_name == "get_nist_controls":
            # Lấy CVE description từ collected_cves hoặc state
            cve_id = args.get("cve_id", "")
            if not args.get("cve_description"):
                collected = state.get("collected_cves", [])
                for cve in collected:
                    if cve.get("id", "") == cve_id:
                        args["cve_description"] = cve.get("description", "")
                        break

        # Agent-specific validation: prevent unauthorized tool calls
        last_agent = state.get("last_agent", "")
        if last_agent == "agent_ti" and tool_name in ["match_cves_with_cmdb", "list_all_devices"]:
            msg = f"[POLICY VIOLATION: agent_ti KHONG DUOC goi '{tool_name}' - day la cua agent_matcher/agent_device]"
            print(f"   {msg}")
            state.setdefault("tool_observations", []).append(msg)
            continue

        tool_func = TOOLS_MAPPING.get(tool_name)
        if not tool_func:
            msg = f"[Tool không tồn tại: {tool_name}]"
            print(f"    {msg}")
            state.setdefault("tool_observations", []).append(msg)
            continue

        try:
            results = tool_func(**args)
            obs = f"[{tool_name} kết quả]: {json.dumps(results.get('context', results), ensure_ascii=False)[:800]}"
            print(f"   Tool '{tool_name}': {str(results.get('context', ''))[:150]}...")
        except Exception as e:
            obs = f"[{tool_name} lỗi]: {e}"
            print(f"   Tool error: {e}")
            state.setdefault("tool_observations", []).append(obs)
            continue

        state.setdefault("tool_observations", []).append(obs)

        # Lưu structured data
        ctx = results.get("context")
        if tool_name == "fetch_nvd_cves" and isinstance(ctx, list):
            state["collected_cves"] = ctx
        elif tool_name == "fetch_cve_by_id" and isinstance(ctx, list):
            state["collected_cves"] = ctx
        elif tool_name in ["fetch_opencti_indicators", "fetch_kb_indicators"] and isinstance(ctx, list):
            # Merge indicators from both KB and OpenCTI
            existing = state.get("collected_indicators", [])
            state["collected_indicators"] = existing + ctx if existing else ctx
        elif tool_name == "fetch_kb_cves" and isinstance(ctx, list):
            state["collected_cves"] = ctx
        elif tool_name == "match_cves_with_cmdb" and isinstance(ctx, list):
            state["matched_devices"] = ctx
        elif tool_name == "aggregate_cves_by_device" and isinstance(ctx, dict):
            state["device_cve_map"] = ctx
        elif tool_name == "get_unique_cves_per_device" and isinstance(ctx, dict):
            state["device_cve_map"] = {k: {"device_info": {}, "cve_ids": v} for k, v in ctx.items()}
        elif tool_name == "get_mitre_attack_info":
            state["attack_info"] = results
        elif tool_name == "get_nist_controls":
            state["nist_info"] = results
        elif tool_name == "generate_report":
            state["final_report"] = results.get("file_path", "")

    return state


MAX_ITERATIONS = 3  # Prevent infinite loops

# ── Core agent caller ──────────────────────────────────────────────────────
def call_agent(state: dict, agent_name: str) -> dict:
    """Gọi một agent cụ thể với Ollama."""
    # Check if agent was called before (prevent self-handoff)
    if state.get("last_agent") == agent_name:
        # Increment iteration counter
        iter_key = f"{agent_name.split('_')[1]}_iterations"
        current_iter = state.get(iter_key, 0)
        state[iter_key] = current_iter + 1

        if current_iter >= MAX_ITERATIONS:
            state[f"{agent_name.split('_')[1]}_completed"] = True
            print(f"    {agent_name} da dat MAX_ITERATIONS ({MAX_ITERATIONS}). Ket thuc.")
            state["last_agent_response"] = "TASK_COMPLETE"
            return state

    profile = AGENT_PROFILES[agent_name]

    # Special cases: auto-routing without calling LLM
    query_lower = state.get("query", "").lower()
    cves = state.get("collected_cves")

    # Supervisor: detect off-topic queries and respond naturally
    if agent_name == "agent_supervisor":
        security_keywords = {
            "cve", "cvss", "vulnerability", "lỗi hổng", "loi ho", "thuat lo",
            "exploit", "ioc", "indicator", "compromise", "malware", "ransomware",
            "trojan", "apt", "threat", "attack", "security", "hack", "breach",
            "device", "thiết", "bị", "thiet bi", "server", "srv", "ip", "hostname",
            "patch", "update", "version", "product", "software", "installed",
            "report", "báo", "cáo", "bao cao", "analysis", "phân", "tích", "phan tich",
            "nist", "mitre", "framework", "control", "scanning", "assessment",
            "threat", "intelligence", "ti", "exposure", "risk", "scan", "check",
            "log4j", "apache", "cisco", "microsoft", "github", "database",
            "vulnerability", "scanning", "security", "assessment", "threat", "hunt",
            "incident", "breach", "compliance", "nvd", "cpe", "severity", "thông tin"
        }
        query_clean = query_lower.replace("?", "").replace("!", "").replace(",", "")
        query_words = set(query_clean.split())
        has_security_keyword = bool(query_words & security_keywords)

        # Check for CVE/device pattern even without keywords
        has_cve_pattern = "cve-" in query_lower or "cve " in query_lower
        has_cve_keyword = any(kw in query_lower for kw in ["log4j", "apache", "exploit", "vulnerability", "lỗi hổng", "loi ho"])

        has_device_pattern = ("device" in query_lower or "srv-" in query_lower or "srv " in query_lower or
                             "thiet bi" in query_lower or "thiết bị" in query_lower or
                             "thiet" in query_lower or "bị" in query_lower or
                             "server" in query_lower or "pc-" in query_lower or "pc " in query_lower or
                             "fw-" in query_lower or "fw " in query_lower or
                             "db-" in query_lower or "db " in query_lower)
        has_hash_pattern = any(len(w) in [32, 40, 64] and all(c in "0123456789abcdef" for c in w)
                               for w in query_words)
        has_ip_pattern = any("." in w and all(p.isdigit() or p == "." for p in w) for w in query_words)

        # PRIORITY 1: CVE pattern or CVE keyword (with or without device) → route to agent_ti
        if has_cve_pattern or has_cve_keyword:
            response = "HANDOFF: agent_ti"
            print(f"\n{'='*55}")
            print(f" {agent_name.upper()} (bước {state['num_steps'] + 1})")
            print("="*55)
            print(response)
            state["last_agent_response"] = response
            state["last_agent"] = agent_name
            state["num_steps"] = state.get("num_steps", 0) + 1
            state["agent_history"] = state.get("agent_history", []) + [agent_name]
            return state

        # PRIORITY 2: Device-only query (no CVE) → route to agent_device
        if has_device_pattern and not (has_cve_pattern or has_cve_keyword):
            response = "HANDOFF: agent_device"
            print(f"\n{'='*55}")
            print(f" {agent_name.upper()} (bước {state['num_steps'] + 1})")
            print("="*55)
            print(response)
            state["last_agent_response"] = response
            state["last_agent"] = agent_name
            state["num_steps"] = state.get("num_steps", 0) + 1
            state["agent_history"] = state.get("agent_history", []) + [agent_name]
            return state

        # PRIORITY 3: IOC/Malware/Hash patterns → route to agent_ti_extended
        if has_hash_pattern or has_ip_pattern:
            response = "HANDOFF: agent_ti_extended"
            print(f"\n{'='*55}")
            print(f" {agent_name.upper()} (bước {state['num_steps'] + 1})")
            print("="*55)
            print(response)
            state["last_agent_response"] = response
            state["last_agent"] = agent_name
            state["num_steps"] = state.get("num_steps", 0) + 1
            state["agent_history"] = state.get("agent_history", []) + [agent_name]
            return state

        if not has_security_keyword and not has_cve_pattern and not has_device_pattern and not has_hash_pattern and not has_ip_pattern:
            # Off-topic query - use LLM to respond naturally while staying polite
            sys_prompt = (
                "Bạn là một trợ lý AI thân thiện và hữu ích.\n\n"
                "Câu hỏi dưới đây không liên quan đến bảo mật thông tin hoặc Threat Intelligence. "
                "Hãy trả lời một cách tự nhiên và thân thiện, sau đó gợi ý người dùng có thể hỏi về các chủ đề liên quan đến bảo mật như: "
                "CVE, lỗ hổng, IOC, Malware, APT, thiết bị, báo cáo bảo mật.\n\n"
                "Giới hạn phản hồi dưới 200 từ để ngắn gọn."
            )

            messages = [
                {"role": "system", "content": sys_prompt},
            ]

            # Add conversation history for context
            conversation_history = state.get("conversation_history", [])
            if conversation_history:
                # Add last 2 turns for context
                messages.extend(conversation_history[-2:])

            messages.append({"role": "user", "content": state.get("query", "")})

            try:
                llm_response = ollama_chat(messages, temperature=0.7)
                response = f"ANSWER: {llm_response}"
            except Exception as e:
                # Fallback if LLM fails
                response = f"""ANSWER: Cảm ơn bạn đã hỏi! Tuy nhiên, tôi là một chuyên gia về Threat Intelligence và bảo mật thông tin.

Tôi có thể giúp bạn với:
- CVE (lỗ hổng bảo mật)
- IOC, Malware, APT
- Thông tin thiết bị
- So khớp CVE với thiết bị
- Báo cáo bảo mật

Vui lòng đặt câu hỏi liên quan đến những chủ đề trên."""

            print(f"\n{'='*55}")
            print(f" AGENT_SUPERVISOR (bước {state['num_steps'] + 1})")
            print("="*55)
            print(response)
            state["last_agent_response"] = response
            state["last_agent"] = agent_name
            state["num_steps"] = state.get("num_steps", 0) + 1
            state["agent_history"] = state.get("agent_history", []) + [agent_name]
            return state


    # agent_ti: on 2nd+ iteration, handle based on query context
    if agent_name == "agent_ti" and cves and state.get("last_agent") == "agent_ti":
        # Check if query asks for device matching after CVE search (handle Vietnamese diacritics)
        has_device_kw = any(kw in query_lower for kw in ["so khớp", "so khop", "ảnh hưởng", "anh huong", "thiết bị", "thiet bi", "device"])

        if has_device_kw:
            # Query explicitly asks for CVE+device matching → forward to agent_matcher
            response = f"HANDOFF: agent_matcher"
            print(f"\n{'='*55}")
            print(f" {agent_name.upper()} (bước {state['num_steps'] + 1})")
            print("="*55)
            print(response)
            state["last_agent_response"] = response
            state["last_agent"]          = agent_name
            state["num_steps"]           = state.get("num_steps", 0) + 1
            state["agent_history"]       = state.get("agent_history", []) + [agent_name]
            return state
        else:
            # No device context → simple answer with CVE info
            cve_summary = f"\n\n**{len(cves)} CVE(s) found:**\n"
            for c in cves[:10]:  # Show up to 10 CVEs
                desc = c.get('description', 'N/A')
                cvss = c.get('cvss_score', 'N/A')
                cve_summary += f"- **{c.get('id')}**: {desc} (CVSS: {cvss})\n"
            if len(cves) > 10:
                cve_summary += f"- ... and {len(cves) - 10} more CVEs\n"
            response = f"ANSWER: {cve_summary}"

            print(f"\n{'='*55}")
            print(f" {agent_name.upper()} (bước {state['num_steps'] + 1})")
            print("="*55)
            print(response)
            state["last_agent_response"] = response
            state["last_agent"]          = agent_name
            state["num_steps"]           = state.get("num_steps", 0) + 1
            state["agent_history"]       = state.get("agent_history", []) + [agent_name]
            return state

    # agent_device: on first call, auto-fetch device list
    if agent_name == "agent_device" and state.get("last_agent") != agent_name:
        # First time calling agent_device - auto-run list_all_devices
        print(f"\n{'='*55}")
        print(f" {agent_name.upper()} (bước {state['num_steps'] + 1})")
        print("="*55)

        try:
            device_result = list_all_devices()
            devices = device_result.get("context", [])
            print(f"   Tool 'list_all_devices': Found {len(devices)} devices")

            # Filter devices if query mentions specific device ID, IP, or hostname
            query_lower = query_lower or state.get("query", "").lower()
            filtered_devices = devices
            mentioned_device = None

            # 1. Check device ID pattern (SRV-XXX, PC-XXX, FW-XXX, DB-XXX)
            device_id_patterns = ["srv-", "pc-", "fw-", "db-"]
            for pattern in device_id_patterns:
                if pattern in query_lower:
                    words = query_lower.split()
                    for word in words:
                        if word.startswith(pattern) or pattern in word:
                            mentioned_device = word.upper().replace("-", "-")
                            filtered_devices = [d for d in devices if d.get("device_id", "").upper() == mentioned_device]
                            if filtered_devices:
                                break
                    if filtered_devices:
                        break

            # 2. Check IP address pattern (xxx.xxx.xxx.xxx)
            if not filtered_devices or len(filtered_devices) == len(devices):
                import re
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                ip_matches = re.findall(ip_pattern, query_lower)
                if ip_matches:
                    for ip in ip_matches:
                        matching = [d for d in devices if d.get("ip", "") == ip]
                        if matching:
                            filtered_devices = matching
                            mentioned_device = f"IP {ip}"
                            break

            # 3. Check hostname match
            if not filtered_devices or len(filtered_devices) == len(devices):
                # Extract potential hostnames from query (words with hyphens or containing 'workstation', 'server', etc)
                hostname_candidates = []
                words = query_lower.split()
                for word in words:
                    if "-" in word and not word.startswith("db-") and not word.startswith("srv-") and not word.startswith("pc-") and not word.startswith("fw-"):
                        hostname_candidates.append(word)

                for hostname in hostname_candidates:
                    matching = [d for d in devices if hostname.lower() in d.get("hostname", "").lower()]
                    if matching:
                        filtered_devices = matching
                        mentioned_device = hostname
                        break

            # Build detailed device list response
            if filtered_devices:
                if mentioned_device and len(filtered_devices) == 1:
                    answer = f"**Thông tin thiết bị {mentioned_device}:**\n\n"
                else:
                    answer = f"**Tổng cộng {len(filtered_devices)} thiết bị trong CMDB:**\n\n"

                for i, dev in enumerate(filtered_devices, 1):
                    dev_id = dev.get("device_id", "Unknown")
                    hostname = dev.get("hostname", "N/A")
                    ip = dev.get("ip", "N/A")
                    os = dev.get("os", "N/A")
                    criticality = dev.get("criticality", "N/A")
                    software = dev.get("installed_software", "N/A")
                    status = dev.get("status", "N/A")

                    answer += f"{i}. **{dev_id}**\n"
                    answer += f"   - Hostname: {hostname}\n"
                    answer += f"   - IP Address: {ip}\n"
                    answer += f"   - Operating System: {os}\n"
                    answer += f"   - Criticality: {criticality}\n"
                    answer += f"   - Installed Software: {software}\n"
                    answer += f"   - Status: {status}\n\n"
                response = f"ANSWER: {answer}"
            else:
                response = f"ANSWER: Không tìm thấy thiết bị {mentioned_device if mentioned_device else 'được chỉ định'} trong CMDB."

            state["last_agent_response"] = response
            state["last_agent"] = agent_name
            state["num_steps"] = state.get("num_steps", 0) + 1
            state["agent_history"] = state.get("agent_history", []) + [agent_name]
            print(response[:500] + ("..." if len(response) > 500 else ""))
            return state
        except Exception as e:
            print(f"   Tool error: {e}")
            response = f"ANSWER: Lỗi khi lấy thông tin thiết bị: {e}"
            state["last_agent_response"] = response
            state["last_agent"] = agent_name
            state["num_steps"] = state.get("num_steps", 0) + 1
            state["agent_history"] = state.get("agent_history", []) + [agent_name]
            return state

    # agent_matcher: 2nd iteration - after tool ran
    if agent_name == "agent_matcher" and state.get("last_agent") == "agent_matcher":
        # Check if matched any devices
        if state.get("matched_devices"):
            # Case 1: CO matched devices → HANDOFF to agent_analyst
            response = "HANDOFF: agent_analyst"
            print(f"\n{'='*55}")
            print(f" {agent_name.upper()} (bước {state['num_steps'] + 1})")
            print("="*55)
            print(response)
            state["last_agent_response"] = response
            state["last_agent"]          = agent_name
            state["num_steps"]           = state.get("num_steps", 0) + 1
            state["agent_history"]       = state.get("agent_history", []) + [agent_name]
            return state
        else:
            # Case 2: KHONG CO matched devices → ANSWER no devices and STOP
            cve_id = ""
            if cves:
                cve_id = cves[0].get("id", "")
            response = f"ANSWER: Khong co thiet bi nao trong CMDB bi anh huong boi CVE {cve_id}. CVE nay khong ket hop voi bat ky phan mem nao da cai dat tren cac thiet bi noi bo."
            print(f"\n{'='*55}")
            print(f" {agent_name.upper()} (bước {state['num_steps'] + 1})")
            print("="*55)
            print(f"==== KHONG CO MATCHED_DEVICES ====")
            print(response)
            state["last_agent_response"] = response
            state["last_agent"]          = agent_name
            state["num_steps"]           = state.get("num_steps", 0) + 1
            state["agent_history"]       = state.get("agent_history", []) + [agent_name]
            return state

    # agent_matcher: if NO CVEs collected → auto-answer without CVE matching
    # agent_matcher: auto-fetch CVEs if query has keywords but no CVEs yet
    if agent_name == "agent_matcher" and not cves:
        query_lower = state.get("query", "").lower()
        # Check if query asks for CVE matching with specific CVE ID or keywords
        has_cve_pattern = "cve-" in query_lower or "cve " in query_lower
        has_cve_keyword = any(kw in query_lower for kw in ["log4j", "apache", "vulnerability", "lỗi hổng", "loi ho"])

        if has_cve_pattern or has_cve_keyword:
            # Auto-fetch CVE before matching
            print(f"\n{'='*55}")
            print(f" {agent_name.upper()} (bước {state['num_steps'] + 1})")
            print("="*55)
            print("Auto-fetching CVEs for matching...")

            if has_cve_pattern and "cve-" in query_lower:
                # Extract CVE ID
                import re
                cve_match = re.search(r'CVE-\d{4}-\d{4,}', query_lower.upper())
                if cve_match:
                    cve_id = cve_match.group()
                    cve_result = fetch_cve_by_id(cve_id)
                    if cve_result.get("context"):
                        state["collected_cves"] = cve_result.get("context", [])
                        cves = state["collected_cves"]
                        print(f"   Fetched {len(cves)} CVE(s) for {cve_id}")
            else:
                # Fetch by keyword (log4j, apache, etc)
                kw = None
                for k in ["log4j", "apache", "exploit", "vulnerability"]:
                    if k in query_lower:
                        kw = k
                        break
                if kw:
                    cve_result = fetch_kb_cves(kw)
                    if cve_result.get("context"):
                        state["collected_cves"] = cve_result.get("context", [])
                        cves = state["collected_cves"]
                        print(f"   Fetched {len(cves)} CVE(s) for keyword '{kw}'")

        if not cves:
            # Still no CVEs after auto-fetch
            response = (
                "ANSWER: Không có CVE nào được tìm thấy.\n\n"
                "Để kiểm tra thông tin thiết bị hoặc so khớp CVE với thiết bị, vui lòng:\n"
                "1. Hỏi cụ thể CVE hoặc từ khóa lỗ hổng (ví dụ: 'CVE-2021-44228' hoặc 'log4j')\n"
                "2. Hoặc hỏi riêng thông tin thiết bị (ví dụ: 'Thông tin thiết bị SRV-001')\n\n"
                "Hệ thống sẽ tự động so khớp CVE với thiết bị nếu có cả hai thông tin."
            )
            print(f"   No CVEs found - returning guidance")
            print(response[:200] + "...")
            state["last_agent_response"] = response
            state["last_agent"]          = agent_name
            state["num_steps"]           = state.get("num_steps", 0) + 1
            state["agent_history"]       = state.get("agent_history", []) + [agent_name]
            return state

    # Build system prompt
    sys_prompt = (
        f"Bạn là {profile['role']}.\n\n"
        f"{profile['system_instruction']}\n\n"
        f"{TOOLS_DESCRIPTION}"
    )

    # Build user content with context data
    observations_text = ""
    if state.get("tool_observations"):
        observations_text = "\n\nKet qua tools:\n" + "\n".join(state["tool_observations"][-3:])

    # For agent_analyst, add iteration signal (LAN 1 vs LAN 2)
    iteration_signal = ""
    if agent_name == "agent_analyst":
        analyst_iters = state.get("analyst_iterations", 0)
        if analyst_iters == 0:
            iteration_signal = "\n\n[LAN 1 - CHỈ GỌI TOOLS]: Gọi get_mitre_attack_info và get_nist_controls. KHÔNG OUTPUT REMEDIATION BƯỚC NÀY."
        elif analyst_iters == 1:
            iteration_signal = "\n\n[LAN 2 - OUTPUT REMEDIATION]: Sử dụng kết quả tools từ lần 1. OUTPUT remediation dựa trên MITRE + NIST data."
        else:
            iteration_signal = "\n\n[STOP]: Đã hoàn thành. Kết thúc."

    prev_response = ""
    if state.get("last_agent_response") and state.get("last_agent") != agent_name:
        prev_response = f"\n\nAgent truoc ({state['last_agent']}) da tra loi:\n{state['last_agent_response'][:500]}"

    # Add structured data context
    context_text = ""
    devices = state.get("matched_devices")
    if cves:
        context_text += f"\n\nCVEs da thu thap ({len(cves)} total):\n"
        for c in cves[:5]:
            desc = c.get('description', '')
            if len(desc) > 200:
                desc = desc[:200] + "..."
            context_text += f"  - {c.get('id')} (CVSS: {c.get('cvss_score')}, Severity: {c.get('severity', 'N/A')})\n"
            context_text += f"    Description: {desc}\n"
        if len(cves) > 5:
            context_text += f"  ... va {len(cves) - 5} CVEs khac\n"
    if devices:
        context_text += f"\n\nThiet bi bi anh huong ({len(devices)} total)"

    user_content = (
        f"Yeu cau: {state.get('query', '')}"
        f"{context_text}"
        f"{prev_response}"
        f"{observations_text}"
        f"{iteration_signal}"
    )

    messages = [
        {"role": "system", "content": sys_prompt},
    ]

    # Add conversation history if available
    conversation_history = state.get("conversation_history", [])
    if conversation_history:
        # Add last 3 messages from history for context (to avoid token overflow)
        messages.extend(conversation_history[-3:])

    messages.append({"role": "user", "content": user_content})

    print(f"\n{'='*55}")
    print(f" {agent_name.upper()} (bước {state['num_steps'] + 1})")
    print("="*55)

    response = ollama_chat(messages, temperature=0.1)
    print(response)

    state["last_agent_response"] = response
    state["last_agent"]          = agent_name
    state["num_steps"]           = state.get("num_steps", 0) + 1
    state["agent_history"]       = state.get("agent_history", []) + [agent_name]
    return state
