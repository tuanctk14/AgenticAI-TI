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
from tools.report_generator import generate_report, list_reports
from tools.doc_store        import (
    upload_document, load_knowledge_base, get_knowledge_base_stats,
    fetch_kb_indicators, fetch_kb_cves
)
from tools.cwe_mapper       import get_mitre_attack_info, get_nist_controls

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
    "generate_report":             generate_report,
    "list_reports":                list_reports,
    "upload_document":             upload_document,
    "load_knowledge_base":         load_knowledge_base,
    "get_knowledge_base_stats":    get_knowledge_base_stats,
    "get_mitre_attack_info":       get_mitre_attack_info,
    "get_nist_controls":           get_nist_controls,
}

# ── Tool Permission Matrix (Guardrails) ───────────────────────────────────
# Mỗi agent chỉ được gọi các tools trong danh sách của nó.
# Agent vẫn TỰ QUYẾT ĐỊNH gọi tool nào trong danh sách — code chỉ block tool ngoài danh sách.
# Đây là ROLE-BASED ACCESS CONTROL, không phải logic override.
TOOL_PERMISSIONS = {
    "agent_ti": [
        "fetch_cve_by_id", "fetch_nvd_cves", "fetch_kb_cves",
    ],
    "agent_ti_extended": [
        "fetch_kb_indicators", "fetch_opencti_indicators",
    ],
    "agent_device": [
        "list_all_devices",
    ],
    "agent_matcher": [
        "match_cves_with_cmdb",
    ],
    "agent_analyst": [
        "get_mitre_attack_info", "get_nist_controls",
    ],
    "agent_reporter": [
        "generate_report", "list_reports",
    ],
    "agent_doc": [
        "upload_document", "load_knowledge_base", "get_knowledge_base_stats",
    ],
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
1. CVE-*, CVE ID hoac keyword (log4j, apache, etc) + device mention → HANDOFF: agent_ti
2. CVE-*, CVE ID, loi ho, NVD, severity KHONG co device → HANDOFF: agent_ti
   (NOTE: agent_ti se tu-forward toi agent_analyst → agent_matcher)
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

OUTPUT FORMAT (chỉ 1 trong 3):
ACTION: fetch_cve_by_id
ARGUMENTS: {"cve_id": "CVE-2021-44228"}

HOẶC:
ACTION: fetch_kb_cves
ARGUMENTS: {"search_term": "log4j"}

HOẶC:
ACTION: fetch_nvd_cves
ARGUMENTS: {"keyword": "log4j"}

STEP 2: Khi tool chạy xong (lần 2+)
SAU KHI CÓ CVE:
  ⭐ LUÔN HANDOFF sang agent_analyst TRƯỚC
  ⭐ agent_analyst sẽ phân tích CWE → MITRE/NIST, sau đó forward sang agent_matcher

OUTPUT:
HANDOFF: agent_analyst

RULES:
- NEVER: match_cves_with_cmdb, list_all_devices, python code, agent_matcher handoff
- ONLY: fetch_cve_by_id, fetch_kb_cves, fetch_nvd_cves
- LUÔN HANDOFF agent_analyst sau khi có CVE (bất kể query hỏi gì)""",
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
ANSWER: Report tool results exactly:
- Từ Local KB: [list all KB results with entity_type, name, description, confidence]
- Từ OpenCTI: [list all OpenCTI results OR "Không có kết quả"]
- ONLY use actual tool data - NEVER invent or hallucinate data

CHI 2 TOOLS. KHONG HANDOFF. KET THUC.

NOTE: fetch_kb_indicators lay tu local KB. fetch_opencti_indicators lay tu OpenCTI.
IMPORTANT: Report EXACT tool results. If tool returns empty, say "Không có kết quả" for that source.""",
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
        "role": "Asset Matcher Agent - So khop CVE theo device va output ket qua cuoi cung",
        "system_instruction": """Ban la Matcher Agent. NHIEM VU: So khop CVE voi CMDB devices VÀ OUTPUT kết quả cuối cùng.

==== LẦN 1 (GỌI TOOL) ====
MANDATORY: Gọi match_cves_with_cmdb tool với CVE list từ state['collected_cves']

OUTPUT:
ACTION: match_cves_with_cmdb
ARGUMENTS: {"cve_list": [CVE objects từ state]}

==== LẦN 2+ (SAU KHI TOOL CHẠY) ====
⭐ LUÔN OUTPUT ANSWER với đầy đủ thông tin. CÓ 2 TRƯỜNG HỢP:

─── TRƯỜNG HỢP 1: CÓ THIẾT BỊ BỊ ẢNH HƯỞNG ───

ANSWER:

═══════════════════════════════════════════
 KẾT QUẢ QUÉT LỖ HỔNG
═══════════════════════════════════════════

[CVE DETAILS]
Với MỖI CVE tìm được:
- CVE ID, CVSS Score, Severity, Published, CWE IDs
- Description (full text)

[PHÂN TÍCH MITRE ATT&CK]
(Từ kết quả agent_analyst trước đó)
- Technique ID - Technique Name (Tactic)
- Mô tả attack vector

[NIST SP 800-53 CONTROLS]
(Từ kết quả agent_analyst)
- Control ID - Control Name
- Mô tả biện pháp kiểm soát

[THIẾT BỊ BỊ ẢNH HƯỞNG]
Với MỖI thiết bị match:
- Device: device_id (hostname)
- IP, OS, Department, Criticality
- Phần mềm bị ảnh hưởng: name version
- Risk Level, Match Type

[REMEDIATION]
Dựa trên MITRE + NIST:
0. Patch product to latest version
Per technique:
  T_ID - Technique Name:
  1. <hành động cụ thể>
Per NIST control:
  Control_ID - Control Name:
  1. <hành động cụ thể>

─── TRƯỜNG HỢP 2: KHÔNG CÓ THIẾT BỊ ───

ANSWER: (Giống Trường hợp 1, nhưng phần "[THIẾT BỊ BỊ ẢNH HƯỞNG]" thay bằng)

[MATCHING THIẾT BỊ]
Không có thiết bị nào trong CMDB bị ảnh hưởng. CVE không khớp phần mềm nội bộ.

(Vẫn output CVE details + MITRE + NIST + Remediation)

═══════════════════════════════════════════

MANDATORY RULES:
1. LẦN 1 + CÓ CVE → GỌI match_cves_with_cmdb ĐÚNG 1 LẦN
2. LẦN 2+ → LUÔN OUTPUT ANSWER ĐẦY ĐỦ (cả 2 trường hợp có/không thiết bị)
3. KHÔNG HANDOFF - agent_matcher là agent cuối cùng
4. PHẢI bao gồm kết quả MITRE/NIST từ agent_analyst
5. PHẢI bao gồm REMEDIATION trong MỌI trường hợp""",
    },

    "agent_analyst": {
        "role": "Threat Analysis Agent - Phân tích MITRE ATT&CK và NIST SP 800-53",
        "system_instruction": """Bạn là Threat Analysis Agent. Nhiệm vụ CHÍNH: Phân tích CVE để tìm attack vector và hướng khắc phục.

⭐ TOOLS ĐƯỢC PHÉP (CHỈ 2 TOOLS NÀY, KHÔNG CÓ TOOL NÀO KHÁC):
- get_mitre_attack_info: Lấy MITRE ATT&CK techniques cho CVE
- get_nist_controls: Lấy NIST SP 800-53 controls cho CVE

⭐ TUYỆT ĐỐI KHÔNG ĐƯỢC GỌI: match_cves_with_cmdb, list_all_devices, fetch_nvd_cves, hoặc bất kỳ tool nào khác.

WORKFLOW:

==== LẦN 1: GỌI TOOLS ====
Với mỗi CVE trong state['collected_cves'], gọi:

ACTION: get_mitre_attack_info
ARGUMENTS: {"cve_id": "<CVE_ID>"}

TIẾP TỤC GỌI:

ACTION: get_nist_controls
ARGUMENTS: {"cve_id": "<CVE_ID>"}

⭐ LẦN NÀY CHỈ GỌI TOOLS. KHÔNG OUTPUT ANSWER. KHÔNG HANDOFF.

==== LẦN 2: HANDOFF SANG MATCHING ====
Sau khi tools trả về kết quả MITRE + NIST:

OUTPUT CHÍNH XÁC:
HANDOFF: agent_matcher

KHÔNG ANSWER ở lần 2. agent_matcher sẽ nhận kết quả và output cuối cùng.

RULES:
1. LẦN 1: CHỈ GỌI 2 TOOLS TRÊN. Không làm gì khác.
2. LẦN 2: CHỈ HANDOFF: agent_matcher. Không làm gì khác.
3. KHÔNG BAO GIỜ gọi match_cves_with_cmdb hoặc list_all_devices.""",
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
            # Find first JSON object/array using regex - try multiple patterns
            json_match = re.search(r'\{.*\}|\[.*\]', args_text, re.DOTALL)
            if json_match:
                try:
                    args = json.loads(json_match.group())
                except json.JSONDecodeError as e:
                    # Fallback: try cleanup with balanced brace counting
                    raw_text = json_match.group()
                    # Find balanced braces/brackets
                    for i in range(len(raw_text) - 1, -1, -1):
                        test_json = raw_text[:i+1]
                        try:
                            args = json.loads(test_json)
                            break
                        except:
                            continue
                    else:
                        msg = f"[JSON parse error cho '{tool_name}': {str(e)[:100]}]"
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
        # Special: MITRE/NIST tools need CWE IDs from collected CVEs for better mapping
        elif tool_name in ["get_mitre_attack_info", "get_nist_controls"]:
            cve_id = args.get("cve_id", "")
            # If cve_id provided, extract CWE IDs from collected_cves for enhanced mapping
            if cve_id:
                collected = state.get("collected_cves", [])
                for cve in collected:
                    if cve.get("id") == cve_id:
                        cwe_ids = cve.get("cwe_ids", [])
                        if cwe_ids:
                            args["cwe_ids"] = cwe_ids
                        # Also provide CVE description for semantic analysis
                        cve_desc = cve.get("description", "")
                        if cve_desc:
                            args["cve_description"] = cve_desc
                        break

        # ── GUARDRAIL: Tool Permission Check (Role-Based Access Control) ──
        last_agent = state.get("last_agent", "")
        allowed_tools = TOOL_PERMISSIONS.get(last_agent, [])

        if allowed_tools and tool_name not in allowed_tools:
            msg = (
                f"[GUARDRAIL] {last_agent} không có quyền gọi '{tool_name}'. "
                f"Tools được phép: {', '.join(allowed_tools)}"
            )
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
        elif tool_name == "get_mitre_attack_info" and isinstance(results, dict):
            # NEW: Save MITRE attack info for agent_analyst
            state["attack_info"] = results
        elif tool_name == "get_nist_controls" and isinstance(results, dict):
            # NEW: Save NIST controls info for agent_analyst
            state["nist_info"] = results
        elif tool_name == "aggregate_cves_by_device" and isinstance(ctx, dict):
            state["device_cve_map"] = ctx
        elif tool_name == "get_unique_cves_per_device" and isinstance(ctx, dict):
            state["device_cve_map"] = {k: {"device_info": {}, "cve_ids": v} for k, v in ctx.items()}
        elif tool_name == "generate_report":
            state["final_report"] = results.get("file_path", "")

    return state


# ── Import comprehensive remediation framework ─────────────────────────────
from tools.remediation_framework import (
    MITRE_TECHNIQUE_REMEDIATION,
    NIST_CONTROL_REMEDIATION,
    get_mitre_remediation,
    get_nist_remediation,
)


def _build_full_analyst_output(cves: list, attack_info: dict, nist_info: dict, matched_devices: list, has_devices: bool) -> str:
    """
    Build comprehensive output for CVE analysis with MITRE/NIST and device matching.
    Used by agent_matcher to output final result.

    NEW FLOW: Always includes CVE + MITRE/NIST + Remediation + (devices if available)
    CWE fallback: If CVE-direct mapping empty, use CWE-to-MITRE/NIST mapping
    """
    from tools.cwe_mapper import CWEMapper
    lines = []

    # ════════════════════════════════════════════════════════════
    # SECTION 1: CVE DETAILS
    # ════════════════════════════════════════════════════════════
    lines.append("═" * 60)
    lines.append(" KẾT QUẢ QUÉT LỖ HỔNG")
    lines.append("═" * 60)
    lines.append("")
    lines.append(f"Tổng cộng: {len(cves) if cves else 0} CVE được tìm thấy")
    lines.append("")

    if cves:
        for i, cve in enumerate(cves, 1):
            cve_id = cve.get("id", "Unknown")
            cvss = cve.get("cvss_score", "N/A")
            severity = cve.get("severity", "UNKNOWN")
            desc = cve.get("description", "Không có mô tả")
            published = cve.get("published", "N/A")
            cwe_ids = cve.get("cwe_ids", [])
            references = cve.get("references", [])

            lines.append(f"{'─' * 50}")
            lines.append(f"  CVE #{i}: {cve_id}")
            lines.append(f"  CVSS: {cvss} | Severity: {severity}")
            lines.append(f"  Published: {published}")
            if cwe_ids:
                lines.append(f"  CWE: {', '.join(cwe_ids)}")
            lines.append(f"  Description: {desc}")
            if references:
                lines.append(f"  References:")
                for ref in references[:3]:
                    lines.append(f"    - {ref}")
                if len(references) > 3:
                    lines.append(f"    ... and {len(references) - 3} more references")
            lines.append("")

    # ════════════════════════════════════════════════════════════
    # SECTION 2: MITRE ATT&CK ANALYSIS
    # ════════════════════════════════════════════════════════════
    lines.append("═" * 60)
    lines.append(" PHÂN TÍCH MITRE ATT&CK")
    lines.append("═" * 60)
    lines.append("")

    # Try CVE-direct mapping first
    attack_ctx = {}
    if attack_info and isinstance(attack_info, dict):
        attack_ctx = attack_info.get("context", {})
    techniques = attack_ctx.get("techniques", [])

    # If no techniques found, try CWE mapping
    if not techniques and cves:
        try:
            mapper = CWEMapper()
            # Collect all CWE IDs from CVEs
            all_cwes = set()
            for cve in cves:
                cwe_ids = cve.get("cwe_ids", [])
                for cwe in cwe_ids:
                    cwe_num = cwe.replace("CWE-", "") if isinstance(cwe, str) else str(cwe)
                    all_cwes.add(cwe_num)

            # Map CWEs to MITRE techniques
            tech_ids_set = set()
            for cwe_num in all_cwes:
                from tools.cwe_mapper import CWE_TO_MITRE
                tech_ids = CWE_TO_MITRE.get(cwe_num, [])
                tech_ids_set.update(tech_ids)

            # Build technique objects from IDs
            if tech_ids_set:
                mitre_data = mapper.mitre_data.get("techniques", {})
                for tech_id in tech_ids_set:
                    tech_data = mitre_data.get(tech_id, {})
                    techniques.append({
                        "id": tech_id,
                        "name": tech_data.get("name", f"Technique {tech_id}"),
                        "tactic": tech_data.get("tactics", [""])[0] if tech_data.get("tactics") else ""
                    })
        except Exception as e:
            pass  # Fall back to "not found" message

    if techniques:
        for tech in techniques:
            tech_id = tech.get("id", "")
            tech_name = tech.get("name", "")
            tactic = tech.get("tactic", "")
            if tactic:
                lines.append(f"  {tech_id:<15} {tech_name:<40} {tactic}")
            else:
                lines.append(f"  • {tech_id}: {tech_name}")
    else:
        lines.append("  Không tìm thấy mapping MITRE ATT&CK trong database.")

    lines.append("")

    # Try CVE-direct NIST mapping
    nist_ctx = {}
    if nist_info and isinstance(nist_info, dict):
        nist_ctx = nist_info.get("context", {})
    controls = nist_ctx.get("controls", [])

    # If no controls found, try CWE mapping
    if not controls and cves:
        try:
            from tools.cwe_mapper import CWE_TO_NIST
            # Collect all CWE IDs from CVEs
            all_cwes = set()
            for cve in cves:
                cwe_ids = cve.get("cwe_ids", [])
                for cwe in cwe_ids:
                    cwe_num = cwe.replace("CWE-", "") if isinstance(cwe, str) else str(cwe)
                    all_cwes.add(cwe_num)

            # Map CWEs to NIST controls
            ctrl_ids_set = set()
            for cwe_num in all_cwes:
                ctrl_ids = CWE_TO_NIST.get(cwe_num, [])
                ctrl_ids_set.update(ctrl_ids)

            # Build control objects from IDs
            if ctrl_ids_set:
                mapper = CWEMapper()
                nist_data = mapper.nist_data.get("controls", {})
                for ctrl_id in ctrl_ids_set:
                    ctrl_data = nist_data.get(ctrl_id, {})
                    controls.append({
                        "id": ctrl_id,
                        "title": ctrl_data.get("title", f"Control {ctrl_id}")
                    })
        except Exception as e:
            pass  # Fall back to "not found" message

    # ════════════════════════════════════════════════════════════
    # SECTION 3: NIST SP 800-53 CONTROLS
    # ════════════════════════════════════════════════════════════
    lines.append("═" * 60)
    lines.append(" NIST SP 800-53 CONTROLS")
    lines.append("═" * 60)
    lines.append("")

    if controls:
        for ctrl in controls:
            ctrl_id = ctrl.get("id", "")
            ctrl_title = ctrl.get("title", "")
            if ctrl_id:
                lines.append(f"  {ctrl_id:<10} {ctrl_title}")
    else:
        lines.append("  Không tìm thấy mapping NIST controls trong database.")

    lines.append("")

    # ════════════════════════════════════════════════════════════
    # SECTION 4: REMEDIATION ACTIONS (per technique + control)
    # ════════════════════════════════════════════════════════════
    lines.append("═" * 60)
    lines.append(" HƯỚNG KHẮC PHỤC")
    lines.append("═" * 60)
    lines.append("")

    if techniques:
        lines.append(" Theo MITRE ATT&CK Techniques:")
        lines.append("")
        for tech in techniques:
            tech_id = tech.get("id", "")
            tech_name = tech.get("name", "")
            if tech_id:
                lines.append(f"  {tech_id} - {tech_name}:")
                # Get comprehensive remediation from framework
                remediation_data = get_mitre_remediation(tech_id)
                actions = remediation_data.get("actions", ["Thực hiện biện pháp kiểm soát phù hợp"])
                for i, action in enumerate(actions, 1):
                    lines.append(f"    {i}. {action}")
                lines.append("")

    if controls:
        lines.append(" Theo NIST SP 800-53 Controls:")
        lines.append("")
        for ctrl in controls:
            ctrl_id = ctrl.get("id", "")
            ctrl_title = ctrl.get("title", "")
            if ctrl_id:
                lines.append(f"  {ctrl_id} - {ctrl_title}:")
                # Get comprehensive remediation from framework
                remediation_data = get_nist_remediation(ctrl_id)
                actions = remediation_data.get("actions", ["Thực hiện biện pháp kiểm soát theo tiêu chuẩn"])
                for i, action in enumerate(actions, 1):
                    lines.append(f"    {i}. {action}")
                lines.append("")

    if not techniques and not controls:
        lines.append("  Hướng khắc phục chung:")
        lines.append("    1. Cập nhật phần mềm/thành phần lên phiên bản mới nhất")
        lines.append("    2. Áp dụng các biện pháp giảm nhẹ công bố bởi nhà cung cấp")
        lines.append("    3. Giám sát các chỉ báo tấn công được công bố")
        lines.append("")

    lines.append("═" * 60)
    lines.append("")

    # ════════════════════════════════════════════════════════════
    # SECTION 5: THIẾT BỊ BỊ ẢNH HƯỞNG
    # ════════════════════════════════════════════════════════════
    lines.append("═" * 60)
    lines.append(" THIẾT BỊ BỊ ẢNH HƯỞNG")
    lines.append("═" * 60)
    lines.append("")

    if has_devices and matched_devices:
        devices_affected = len({m.get("device_id") for m in matched_devices})
        lines.append(f"  Tổng: {len(matched_devices)} kết quả trên {devices_affected} thiết bị")
        lines.append("")

        for i, match in enumerate(matched_devices, 1):
            device_id = match.get("device_id", "")
            hostname = match.get("hostname", "")
            ip = match.get("ip", "")
            os_info = match.get("os", "")
            dept = match.get("department", "")
            # Get CVE affected software from CVE metadata (vendor/product), not from CMDB device
            if cves and len(cves) > 0:
                cve = cves[0]
                vendor = cve.get("vendor", "")
                product = cve.get("product", "")
                # Construct affected software name from vendor and product
                if vendor and product:
                    affected_sw = f"{vendor} {product}" if vendor.lower() not in product.lower() else product
                elif product:
                    affected_sw = product
                else:
                    affected_sw = match.get("affected_software", "Unknown")
            else:
                affected_sw = match.get("affected_software", "Unknown")
            device_version = match.get("device_version", "")
            risk = match.get("risk_level", "")

            lines.append(f"  [{i}] {device_id} ({hostname})")
            lines.append(f"      IP: {ip} | OS: {os_info}")
            lines.append(f"      Department: {dept}")
            lines.append(f"      Phần mềm bị ảnh hưởng: {affected_sw} (version: {device_version})")
            lines.append(f"      Risk Level: {risk}")

            # Show Multi-Source Intel metadata when MSI drove the match
            cve_src = match.get("cve_source", "")
            msi_conf = match.get("msi_confidence")
            if cve_src == "multi_source_intel" and msi_conf is not None:
                conf_pct = int(msi_conf * 100)
                lines.append(f"      Nguồn: Multi-Source Intel ({conf_pct}% confidence)")
                agreeing = match.get("msi_sources_agreeing", [])
                if agreeing:
                    lines.append(f"      Signals agreed: {', '.join(agreeing)}")
                breakdown = match.get("msi_source_breakdown", {})
                if breakdown:
                    lines.append("      Signal breakdown:")
                    for src_name, src_info in breakdown.items():
                        top = src_info.get("top_candidate")
                        if top:
                            vk, c = top
                            lines.append(f"        {src_name:<22}: {vk} ({c:.0%})")

            lines.append("")
    else:
        lines.append("  Không có thiết bị nào trong CMDB bị ảnh hưởng bởi CVE này.")
        lines.append("  Lý do: CVE không khớp với phần mềm đã cài đặt trên các thiết bị nội bộ.")
        lines.append("")
        lines.append("  Lưu ý: Thông tin MITRE ATT&CK và NIST controls ở trên vẫn có giá trị")
        lines.append("  để hỗ trợ phòng ngừa và chuẩn bị ứng phó nếu sản phẩm bị ảnh hưởng")
        lines.append("  được triển khai trong tương lai.")

    lines.append("")
    lines.append("═" * 60)

    return "\n".join(lines)


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
        has_ioc_pattern = query_lower.startswith(("ioc-", "mal-"))

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
        if has_hash_pattern or has_ip_pattern or has_ioc_pattern:
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


    # agent_ti: on 2nd+ iteration, ALWAYS handoff to agent_analyst for CWE analysis (NEW FLOW)
    if agent_name == "agent_ti" and cves and state.get("last_agent") == "agent_ti":
        # NEW FLOW: Always handoff to agent_analyst for MITRE/NIST analysis FIRST
        response = "HANDOFF: agent_analyst"
        print(f"\n{'='*55}")
        print(f" {agent_name.upper()} (bước {state['num_steps'] + 1})")
        print("="*55)
        print(f"  CVEs collected: {len(cves)}")
        print(f"  → HANDOFF: agent_analyst (phân tích MITRE/NIST trước matching)")
        print(response)
        state["last_agent_response"] = response
        state["last_agent"]          = agent_name
        state["num_steps"]           = state.get("num_steps", 0) + 1
        state["agent_history"]       = state.get("agent_history", []) + [agent_name]
        # Reset analyst iterations for new query
        state["analyst_iterations"]  = 0
        return state

    # agent_analyst: on 2nd iteration (after tools), ALWAYS handoff to agent_matcher
    if agent_name == "agent_analyst" and state.get("last_agent") == "agent_analyst":
        analyst_iters = state.get("analyst_iterations", 0)
        # If we've called tools once (iter 1), now handoff to matcher
        if analyst_iters >= 1:
            response = "HANDOFF: agent_matcher"
            print(f"\n{'='*55}")
            print(f" {agent_name.upper()} (bước {state['num_steps'] + 1})")
            print("="*55)
            print(f"  MITRE/NIST analysis complete (iterations: {analyst_iters})")
            print(f"  → HANDOFF: agent_matcher (thiết bị matching)")
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

    # agent_matcher: 1st iteration - ALWAYS call match_cves_with_cmdb (deterministic, no LLM hallucinate)
    if agent_name == "agent_matcher" and state.get("last_agent") != "agent_matcher":
        if cves:
            response = "ACTION: match_cves_with_cmdb\nARGUMENTS: {}"
            print(f"\n{'='*55}")
            print(f" {agent_name.upper()} (bước {state['num_steps'] + 1})")
            print("="*55)
            print(f"  Matching {len(cves)} CVEs với devices trong CMDB...")
            state["last_agent_response"] = response
            state["last_agent"]          = agent_name
            state["num_steps"]           = state.get("num_steps", 0) + 1
            state["agent_history"]       = state.get("agent_history", []) + [agent_name]
            state["matcher_iterations"]  = 1
            return state

    # agent_matcher: 2nd iteration - after tool ran (NEW FLOW: ALWAYS comprehensive output)
    if agent_name == "agent_matcher" and state.get("last_agent") == "agent_matcher":
        matched = state.get("matched_devices", [])
        attack_info = state.get("attack_info", {})
        nist_info = state.get("nist_info", {})
        has_devices = len(matched) > 0

        # NEW FLOW: Always output full analysis with CVE + MITRE/NIST + (devices if any)
        response = _build_full_analyst_output(cves, attack_info, nist_info, matched, has_devices)

        print(response)

        state["last_agent_response"] = f"ANSWER: {response}"
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

    # For agent_analyst, add iteration signal (LẦN 1 gọi tools vs LẦN 2 HANDOFF)
    iteration_signal = ""
    if agent_name == "agent_analyst":
        analyst_iters = state.get("analyst_iterations", 0)
        if analyst_iters == 0:
            iteration_signal = "\n\n[LẦN 1 - GỌI TOOLS]: Gọi get_mitre_attack_info và get_nist_controls. KHÔNG OUTPUT ANSWER."
        elif analyst_iters == 1:
            iteration_signal = "\n\n[LẦN 2 - HANDOFF]: Đã có kết quả MITRE/NIST. HANDOFF sang agent_matcher (KHÔNG ANSWER)."
        else:
            iteration_signal = "\n\n[STOP]: Hoàn tất."

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
        context_text += f"\n\nThiet bi bi anh huong ({len(devices)} total):\n"
        for device in devices:
            context_text += f"\n  Device: {device.get('device_id')} ({device.get('hostname')})\n"
            context_text += f"    Software: {device.get('affected_software')} {device.get('device_version', '')}\n"
            context_text += f"    CWE IDs: {device.get('cwe_ids', [])}\n"

            # MITRE data
            mitre_techs = device.get('mitre_techniques', [])
            if mitre_techs:
                context_text += f"    MITRE Techniques ({len(mitre_techs)}):\n"
                for t in mitre_techs:
                    tactics_str = ', '.join(t.get('tactics', []))
                    context_text += f"      - {t.get('id')}: {t.get('name')} (Tactic: {tactics_str})\n"
                    if t.get('description'):
                        desc = t.get('description')
                        if len(desc) > 100:
                            desc = desc[:100] + "..."
                        context_text += f"        Description: {desc}\n"
            else:
                context_text += f"    MITRE Techniques: None\n"

            # NIST data
            nist_ctrls = device.get('nist_controls', [])
            if nist_ctrls:
                context_text += f"    NIST Controls ({len(nist_ctrls)}):\n"
                for n in nist_ctrls:
                    context_text += f"      - {n.get('id')}: {n.get('name')} (Family: {n.get('family')})\n"
                    if n.get('description'):
                        desc = n.get('description')
                        if len(desc) > 100:
                            desc = desc[:100] + "..."
                        context_text += f"        Description: {desc}\n"
            else:
                context_text += f"    NIST Controls: None\n"

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

    # NEW: Special handling for agent_analyst iterations
    if agent_name == "agent_analyst":
        analyst_iters = state.get("analyst_iterations", 0)
        state["analyst_iterations"] = analyst_iters + 1

    state["last_agent_response"] = response
    state["last_agent"]          = agent_name
    state["num_steps"]           = state.get("num_steps", 0) + 1
    state["agent_history"]       = state.get("agent_history", []) + [agent_name]
    return state
