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

RULES:
1. CVE-*, CVE ID, loi ho, NVD, keyword, severity → HANDOFF: agent_ti
2. IOC, Malware, APT, threat actor, APT29, emotet, file hash, SHA-256, SHA-1, MD5, domain name, IP address, URL, IPv4, IPv6 → HANDOFF: agent_ti_extended
3. CMDB, thiet bi, device, so khop → HANDOFF: agent_matcher
4. Bao cao, report → HANDOFF: agent_reporter
5. Tai lieu, document, upload → HANDOFF: agent_doc
6. Chuoi hex dai 32+ ky tu (hash file), domain, IP → HANDOFF: agent_ti_extended (IOC)
7. Khong ro → HANDOFF: agent_ti (default CVE)

DETECTION:
- CVE format: CVE-XXXX-XXXXX
- Hash format: 32+ hex chars (MD5/SHA-1/SHA-256 hashes)
- Domain: contains . (dot) like example.com
- IP: XXX.XXX.XXX.XXX pattern
- If no clear format and multiple keywords, prioritize IOC keywords

OUTPUT: Chi HANDOFF, khong co gi khac.""",
    },

    "agent_ti": {
        "role": "CVE Agent - Lay CVE tu NVD hoac KB",
        "system_instruction": """Ban la CVE Agent. NHIEM VU DUNG: Lay CVE tu NVD hoac local Knowledge Base. KHONG DUOC GOI match_cves_with_cmdb.

RULES:
1. Neu user hoi CVE cu the (CVE-2023-22515, CVE-2021-44228) + so khop thiet bi → fetch_kb_cves TIEN ROI fetch_cve_by_id NEU KB trong
2. Neu user hoi CVE cu the + chi hoi chi tiet → fetch_kb_cves TIEN ROI fetch_cve_by_id NEU KB trong
3. Neu user hoi CVE theo keyword (log4j) + so khop thiet bi → fetch_kb_cves TIEN, NEU CO thi HANDOFF agent_matcher
4. Neu user hoi CVE theo keyword + chi hoi chi tiet → fetch_kb_cves TIEN, NEU CO thi ANSWER

ƯỘI TIÊN: Luôn thử fetch_kb_cves TRƯỚC (KB local). Nếu có kết quả → ANSWER/HANDOFF.
Nếu KB trống → fetch_nvd_cves (NVD online)

BAT DUNG GOI TOOL:
ACTION: fetch_kb_cves hoac fetch_nvd_cves hoac fetch_cve_by_id
ARGUMENTS: {...}

KHONG BAO GIO GOI: match_cves_with_cmdb, list_all_devices, aggregate_cves_by_device""",
    },

    "agent_ti_extended": {
        "role": "Threat Intelligence Agent - Lay IOC, Malware, APT info tu local KB hoac OpenCTI",
        "system_instruction": """Ban la Extended TI Agent. GOI fetch_kb_indicators de lay IOC, Malware tu local Knowledge Base.

RULES:
1. Neu user hoi IOC, Malware, APT, threat actor, hoac hash (SHA-256, SHA-1, MD5) → PHAI GOI TOOL
2. Neu user hoi bang hash file → search_term = chinh hash do, KHONG THAY DOI
3. Neu user hoi "emotet", "ransomware", "APT41" → search_term = keyword do
4. LUON GOI TOOL tren lan dau. Khong ANSWER tren lan dau.

LAN DAU BUOC BAT: PHAI GOI TOOL 1 LAN:
ACTION: fetch_kb_indicators
ARGUMENTS: {"search_term": "<TU USER HOI>", "indicator_type": "all"}

LAN 2 (SAU KHI TOOL CHAY): CHI LAP TUC ANSWER:
ANSWER: [thong tin: bao nhieu IOC, cac malware families, threat actors, confidence score]

CHI 1 TOOL. KHONG HANDOFF. KET THUC.

NOTE: fetch_kb_indicators lay du lieu tu local Knowledge Base (IOCs/Malwares da upload).
Neu KB trong, se lay 0 ket qua.""",
    },

    "agent_matcher": {
        "role": "Asset Matcher Agent - So khop va phan nhom CVE theo device",
        "system_instruction": """Ban la Matcher Agent. So khop CVE voi CMDB devices. GOI 1 TOOL DUNG.

IMPORTANT: match_cves_with_cmdb yeu cau CVE objects (dict voi 'id', 'description', 'cvss_score', etc), KHONG CHI CVE ID strings.

NEU LAN DAU: Goi match_cves_with_cmdb de match CVE voi device.
DUNG lay TOAN BO CVE list tu state (STATE KEY: collected_cves - day la list cac CVE dict)
ACTION: match_cves_with_cmdb
ARGUMENTS: {"cve_list": <lay tu state['collected_cves']>}

NEU LAN 2+: CHI ANSWER (KHONG GOI TOOL THEM):
ANSWER: [X device bi anh huong, Y CVE unique, chi tiet matching]

KET THUC NGAY. KHONG HANDOFF.""",
    },

    # agent_analyst REMOVED - focus on CVE only, no MITRE/NIST analysis

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

BUOC 1: GOI TOOL DUNG 1 LAN:

ACTION: generate_report
ARGUMENTS: {"report_type": "executive_summary"}

BUOC 2: NGAY LAP TUC ANSWER:

ANSWER: Da tao bao cao. File da luu. Tong hop noi dung...

KHONG DUOC GOI TOOL LAN 2. KHONG DUOC HANDOFF. KET THUC.

Tra loi bang tieng Viet.""",
    },
}


# ── Tool executor ──────────────────────────────────────────────────────────
def call_tool(state: dict) -> dict:
    """Parse và thực thi tool từ phản hồi của agent."""
    response = state.get("last_agent_response", "")
    if "ACTION:" not in response:
        return state

    action_text = response.split("ACTION:")[1].strip()
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
                print(f"  ⚠️  {msg}")
                state.setdefault("tool_observations", []).append(msg)
                return state
        else:
            msg = f"[Khong tim thay JSON trong ARGUMENTS: {args_text[:50]}]"
            print(f"  ⚠️  {msg}")
            state.setdefault("tool_observations", []).append(msg)
            return state

    # Special: generate_report cần cả state
    if tool_name == "generate_report":
        args["state"] = state
    # Special: match_cves_with_cmdb needs collected_cves if no args provided
    elif tool_name == "match_cves_with_cmdb" and not args:
        collected = state.get("collected_cves", [])
        args["cve_list"] = collected if collected else []

    tool_func = TOOLS_MAPPING.get(tool_name)
    if not tool_func:
        msg = f"[Tool không tồn tại: {tool_name}]"
        print(f"  ⚠️  {msg}")
        state.setdefault("tool_observations", []).append(msg)
        return state

    try:
        results = tool_func(**args)
        obs = f"[{tool_name} kết quả]: {json.dumps(results.get('context', results), ensure_ascii=False)[:800]}"
        print(f"  📦 Tool '{tool_name}': {str(results.get('context', ''))[:150]}...")
    except Exception as e:
        obs = f"[{tool_name} lỗi]: {e}"
        print(f"  ❌ Tool error: {e}")
        state.setdefault("tool_observations", []).append(obs)
        return state

    state.setdefault("tool_observations", []).append(obs)

    # Lưu structured data
    ctx = results.get("context")
    if tool_name == "fetch_nvd_cves" and isinstance(ctx, list):
        state["collected_cves"] = ctx
    elif tool_name == "fetch_cve_by_id" and isinstance(ctx, list):
        state["collected_cves"] = ctx
    elif tool_name in ["fetch_opencti_indicators", "fetch_kb_indicators"] and isinstance(ctx, list):
        state["collected_indicators"] = ctx
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
            print(f"  ⚠️  {agent_name} da dat MAX_ITERATIONS ({MAX_ITERATIONS}). Ket thuc.")
            state["last_agent_response"] = "TASK_COMPLETE"
            return state

    profile = AGENT_PROFILES[agent_name]

    # Special case: agent_ti with collected CVEs and device matching requested
    query_lower = state.get("query", "").lower()
    cves = state.get("collected_cves")
    if (agent_name == "agent_ti" and cves and
        ("so khop" in query_lower or "thiet bi" in query_lower or "device" in query_lower)):
        # Auto-handoff to agent_matcher for device matching
        response = "HANDOFF: agent_matcher\n\n[CVE collection complete, forwarding to device matcher]"
        print(f"\n{'='*55}")
        print(f"🤖 {agent_name.upper()} (bước {state['num_steps'] + 1})")
        print("="*55)
        print(response)
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

    prev_response = ""
    if state.get("last_agent_response") and state.get("last_agent") != agent_name:
        prev_response = f"\n\nAgent truoc ({state['last_agent']}) da tra loi:\n{state['last_agent_response'][:500]}"

    # Add structured data context
    context_text = ""
    devices = state.get("matched_devices")
    if cves:
        context_text += f"\n\nCVEs da thu thap ({len(cves)} total):\n"
        for c in cves[:5]:
            context_text += f"  - {c.get('id')}: {c.get('description', '')[:60]} (CVSS: {c.get('cvss_score')})\n"
        if len(cves) > 5:
            context_text += f"  ... va {len(cves) - 5} CVEs khac\n"
    if devices:
        context_text += f"\n\nThiet bi bi anh huong ({len(devices)} total)"

    user_content = (
        f"Yeu cau: {state.get('query', '')}"
        f"{context_text}"
        f"{prev_response}"
        f"{observations_text}"
    )

    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user",   "content": user_content},
    ]

    print(f"\n{'='*55}")
    print(f"🤖 {agent_name.upper()} (bước {state['num_steps'] + 1})")
    print("="*55)

    response = ollama_chat(messages, temperature=0.1)
    print(response[:600] + ("..." if len(response) > 600 else ""))

    state["last_agent_response"] = response
    state["last_agent"]          = agent_name
    state["num_steps"]           = state.get("num_steps", 0) + 1
    state["agent_history"]       = state.get("agent_history", []) + [agent_name]
    return state
