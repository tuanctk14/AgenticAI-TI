"""
main.py - Entry point cho ATI-AgenticThreatIntelligence System (Ollama Local Edition)
"""
import sys
import io
import argparse
import os
import webbrowser

# Fix Unicode encoding cho Windows (cp1252 → utf-8)
if sys.platform == "win32":
    try:
        import codecs
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except:
        pass

# Đảm bảo import đúng khi chạy từ bất kỳ thư mục nào
sys.path.insert(0, os.path.dirname(__file__))

from config import OLLAMA_MODEL, OLLAMA_BASE_URL, REPORTS_DIR
from core.ollama_llm import check_ollama_connection
from core.state      import init_state
from core.graph      import get_graph
from tools.nvd_client import fetch_nvd_cves
from tools.opencti_client import fetch_opencti_indicators
from tools.cmdb import match_cves_with_cmdb
from tools.report_generator import generate_report
from datetime import datetime, timedelta, timezone

# ── Banner ─────────────────────────────────────────────────────────────────
BANNER = """
   _   _____ ___
  / \ |_   _|_ _|
 / _ \  | |  | |
/ ___ \ | |  | |
/_/   \_|_|  |___|

    AgenticThreatIntelligence 
    Intelligent Threat Analysis System
    Ollama Local Edition | Offline Mode
"""

MENU = """
+--------------------------------------------------------------+
|                           MENU                               |
+--------------------------------------------------------------+
|  1. Quét CVE và tìm thiết bị ảnh hưởng                       |
|  2. Tạo báo cáo                                              |
|  3. Upload / xử lý tài liệu nội bộ                           |
|  4. Chat với ATI BOT                                         |
|  0. Thoát                                                    |
+--------------------------------------------------------------+
"""

PRESET_QUERIES = {
    "1": (
        "Hãy quét lỗ hổng (keyword: {}) từ NVD, "
        "so khớp với thiết bị nội bộ và cho biết thiết bị nào bị ảnh hưởng."
    ),
    "2": (
        "Thực hiện đánh giá CVE: lấy CVE severity HIGH từ NVD, "
        "so khớp với hệ thống nội bộ, tạo báo cáo executive_summary."
    ),
    "3": None,   # Upload document
    "4": None,   # Free query
}

TEST_CASES = [
    "Quét CVE Log4Shell từ NVD và tìm thiết bị bị ảnh hưởng trong CMDB.",
    "Lấy IoC từ OpenCTI liên quan đến ransomware.",
    "Phân tích Apache CVE-2021-41773 theo MITRE ATT&CK.",
]


# ── Core run ───────────────────────────────────────────────────────────────
def run_query(query: str, verbose: bool = True, chat_mode: bool = False) -> dict:
    """Chạy một câu hỏi qua hệ thống multi-agent."""
    graph = get_graph()
    state = init_state(query)

    if verbose and not chat_mode:
        print(f"\n Đang xử lý: {query[:80]}...")
        print("-" * 55)

    try:
        result = graph.invoke(state, config={"recursion_limit": 30})
    except Exception as e:
        print(f" Lỗi hệ thống: {e}")
        return {"error": str(e)}

    if verbose and not chat_mode:
        _print_summary(result)

    return result


def _get_remediation_steps(cve_description: str) -> list[str]:
    """Tạo remediation steps dựa trên loại lỗ hổng."""
    desc = cve_description.lower()
    steps = []

    # Priority based on CVSS (will be added by caller)
    # Priority added later in device loop

    # Specific remediation based on vulnerability type
    if "rce" in desc or "remote code execution" in desc:
        steps.extend([
            "- RCE Detection: Scan hệ thống bằng antivirus/EDR để phát hiện backdoor, shell scripts",
            "- Firewall rules: Kiểm tra và tightening inbound connections từ internet",
            "- Kiểm tra logs: Tìm kiếm dấu hiệu bị khai thác (suspicious activities, error patterns)"
        ])
    elif "sql" in desc:
        steps.extend([
            "- SQL Injection mitigation: Review và sanitize tất cả SQL queries, dùng parameterized statements",
            "- Database audit: Kiểm tra access logs của database, xóa suspicious accounts"
        ])
    elif "auth" in desc or "bypass" in desc:
        steps.extend([
            "- Credential reset: Reset tất cả passwords, invalidate sessions nếu cần",
            "- MFA enforcement: Enable Multi-Factor Authentication nếu chưa có",
            "- Kiểm tra logs: Tìm kiếm dấu hiệu truy cập bất hợp pháp (unauthorized access attempts)"
        ])
    elif "path traversal" in desc or "directory traversal" in desc:
        steps.extend([
            "- File access audit: Kiểm tra web server logs cho directory traversal attempts",
            "- Access control: Đảm bảo proper file permissions và không expose sensitive directories"
        ])
    elif "xss" in desc or "cross-site" in desc:
        steps.extend([
            "- Input validation: Implement proper input sanitization và output encoding",
            "- CSP headers: Thiết lập Content Security Policy headers"
        ])
    elif "csrf" in desc or "cross-site request" in desc:
        steps.extend([
            "- CSRF tokens: Implement CSRF protection tokens trên tất cả state-changing operations",
            "- SameSite cookies: Thiết lập SameSite attribute trên cookies"
        ])
    else:
        # Default remediation for unknown vulnerability types
        steps.extend([
            "- Kiểm tra logs: Tìm kiếm dấu hiệu bị khai thác (suspicious activities)",
            "- Network segmentation: Giới hạn truy cập từ bên ngoài nếu chưa có"
        ])

    return steps


def _print_chat_response(result: dict):
    """Extract và print response cho chat mode với full details."""
    last_response = result.get("last_agent_response", "")

    # Extract ANSWER text nếu có
    if "ANSWER:" in last_response:
        answer_text = last_response.split("ANSWER:")[1].strip()
        print(f"ATI: {answer_text}\n")
    elif last_response:
        print(f"ATI: {last_response}\n")

    # ── CVE Data - Show full details ────────────────────────────────────────
    cves = result.get("collected_cves") or []
    if cves:
        print("=" * 70)
        print(" CVE DETAILS - TẤT CẢ")
        print("=" * 70)
        print(f"Tổng cộng: {len(cves)} CVEs\n")
        for i, cve in enumerate(cves, 1):
            cve_id = cve.get("id", "Unknown")
            cvss = cve.get("cvss_score", "N/A")
            severity = cve.get("severity", "UNKNOWN")
            desc = cve.get("description", "No description")
            published = cve.get("published", "Unknown")
            references = cve.get("references", [])

            print(f"{i}. {cve_id}")
            print(f"   CVSS Score: {cvss}")
            print(f"   Severity: {severity}")
            print(f"   Published: {published}")
            print(f"   Description: {desc}")
            if references:
                print(f"   References:")
                for ref in references[:3]:
                    print(f"     - {ref}")
                if len(references) > 3:
                    print(f"     ... and {len(references) - 3} more references")
            print()

    # ── IOC/Malware Data - Show full details ─────────────────────────────────
    indicators = result.get("collected_indicators") or []
    if indicators:
        print("=" * 70)
        print(" THREAT INTELLIGENCE DETAILS - TẤT CẢ")
        print("=" * 70)
        print(f"Tổng cộng: {len(indicators)} Results\n")

        for i, ind in enumerate(indicators, 1):
            ioc_id = ind.get("id", "Unknown")
            name = ind.get("name", "Unknown")
            entity_type = ind.get("entity_type", "Unknown")
            score = ind.get("score", 0)

            print(f"{i}. [{entity_type}] {name}")
            print(f"   ID: {ioc_id}")
            print(f"   Score: {score}/100")

            conf = ind.get("confidence", 0)
            if conf:
                print(f"   Confidence: {conf}%")

            pattern = ind.get("pattern", "")[:80]
            if pattern:
                print(f"   Pattern: {pattern}...")

            malware_types = ind.get("malware_types", [])
            if malware_types:
                print(f"   Types: {', '.join(malware_types)}")

            aliases = ind.get("aliases", [])
            if aliases:
                aliases_str = ", ".join(aliases[:3])
                if len(aliases) > 3:
                    aliases_str += f", ... ({len(aliases)} total)"
                print(f"   Aliases: {aliases_str}")

            desc = ind.get("description", "")
            if desc:
                print(f"   Description: {desc[:150]}...")

            print()

    # If have device matches, print remediation info
    devices = result.get("matched_devices") or []
    if devices:
        print("\n" + "=" * 70)
        print(" HƯỚ­NG KHẮC PHỤC CHI TIẾT")
        print("=" * 70)

        device_dict = {}
        cves_dict = {}
        cves_collected = result.get("collected_cves") or []
        for cve in cves_collected:
            cves_dict[cve.get("id")] = cve

        for d in devices:
            dev_id = d["device_id"]
            if dev_id not in device_dict:
                device_dict[dev_id] = {
                    "hostname": d.get("hostname"),
                    "ip": d.get("ip"),
                    "os": d.get("os"),
                    "criticality": d.get("criticality"),
                    "affected_software": d.get("affected_software"),
                    "cves": []
                }
            device_dict[dev_id]["cves"].append({
                "cve_id": d.get("cve_id"),
                "risk_level": d.get("risk_level"),
                "cvss_score": d.get("cvss_score")
            })

        for dev_id, info in device_dict.items():
            hostname = info["hostname"]
            ip = info["ip"]
            os = info["os"]
            criticality = info["criticality"]
            cves = info["cves"]
            software = info.get("affected_software", "N/A")

            print(f"\n• Device: {dev_id}")
            print(f"  Hostname: {hostname}")
            print(f"  IP: {ip}")
            print(f"  OS: {os}")
            print(f"  Criticality: {criticality}")
            print(f"  Số CVEs: {len(cves)}")
            print(f"  CVEs cụ thể:")
            for cve in cves:
                print(f"    - {cve['cve_id']}: {cve['risk_level']} (CVSS: {cve['cvss_score']})")

            print(f"\n  Hướng khắc phục:")

            # Find highest risk CVE
            highest_risk_cve = max(cves, key=lambda x: float(x.get("cvss_score", 0)) if isinstance(x.get("cvss_score"), (int, float, str)) and str(x.get("cvss_score")).replace('.', '', 1).isdigit() else 0)
            cvss = highest_risk_cve.get("cvss_score", 0)
            try:
                cvss_float = float(cvss) if cvss and cvss != "N/A" else 0
            except (ValueError, TypeError):
                cvss_float = 0

            # Timeline priority
            if cvss_float >= 9.0:
                print(f"    -  Ưu tiên CRITICAL: Xử lý ngay trong 24 giờ")
            elif cvss_float >= 7.0:
                print(f"    -  Ưu tiên HIGH: Xử lý trong 72 giờ")
            else:
                print(f"    -  Ưu tiên MEDIUM: Lên lịch xử lý trong 2 tuần")

            # Update affected software
            print(f"    - Cập nhật phần mềm: Nâng cấp {software} lên phiên bản mới nhất")

            # Get remediation based on CVE description
            cve_description = ""
            highest_cve_id = highest_risk_cve.get("cve_id")
            if highest_cve_id in cves_dict:
                cve_description = cves_dict[highest_cve_id].get("description", "")

            remediation_steps = _get_remediation_steps(cve_description)
            for step in remediation_steps:
                print(f"    {step}")

        print("\n" + "=" * 70)


def _print_summary(result: dict):
    """In tóm tắt kết quả sau khi chạy xong - CHI TIẾT ĐẦY ĐỦ."""
    print("\n" + "="*70)
    print(" KẾT QUẢ CHI TIẾT ĐẦY ĐỦ")
    print("="*70)

    history = result.get("agent_history", [])
    print(f"Agents đã dùng: {' → '.join(history)}")
    print(f"Số bước: {result.get('num_steps', 0)}\n")

    # ── CVE Data - TẤT CẢ ────────────────────────────────────────────────────
    cves = result.get("collected_cves") or []
    if cves:
        print("=" * 70)
        print(" CVE DETAILS - TẤT CẢ")
        print("=" * 70)
        print(f"Tổng cộng: {len(cves)} CVEs\n")
        for i, cve in enumerate(cves, 1):
            cve_id = cve.get("id", "Unknown")
            cvss = cve.get("cvss_score", "N/A")
            severity = cve.get("severity", "UNKNOWN")
            desc = cve.get("description", "No description")
            published = cve.get("published", "Unknown")
            references = cve.get("references", [])

            print(f"{i}. {cve_id}")
            print(f"   CVSS Score: {cvss}")
            print(f"   Severity: {severity}")
            print(f"   Published: {published}")
            print(f"   Description: {desc}")
            if references:
                print(f"   References:")
                for ref in references[:3]:  # Show first 3 references
                    print(f"     - {ref}")
                if len(references) > 3:
                    print(f"     ... and {len(references) - 3} more references")
            print()

    # ── IOC/Malware Data - TẤT CẢ ──────────────────────────────────────────
    indicators = result.get("collected_indicators") or []
    if indicators:
        print("=" * 70)
        print(" THREAT INTELLIGENCE DETAILS - TẤT CẢ")
        print("=" * 70)
        print(f"Tổng cộng: {len(indicators)} Results (Indicators + Malware + Threat Actors + Patterns)\n")

        for i, ind in enumerate(indicators, 1):
            ioc_id = ind.get("id", "Unknown")
            name = ind.get("name", "Unknown")
            entity_type = ind.get("entity_type", "Unknown")
            score = ind.get("score", 0)

            print(f"{i}. [{entity_type}] {name}")
            print(f"   ID: {ioc_id}")
            print(f"   Score: {score}/100")

            # Display confidence for indicators
            conf = ind.get("confidence", 0)
            if conf:
                print(f"   Confidence: {conf}%")

            # Display indicator pattern
            pattern = ind.get("pattern", "")[:80]
            if pattern:
                print(f"   Pattern: {pattern}...")

            # Display malware types
            malware_types = ind.get("malware_types", [])
            if malware_types:
                print(f"   Types: {', '.join(malware_types)}")

            # Display aliases (for malware or threat actors)
            aliases = ind.get("aliases", [])
            if aliases:
                aliases_str = ", ".join(aliases[:3])  # Show first 3 aliases
                if len(aliases) > 3:
                    aliases_str += f", ... ({len(aliases)} total)"
                print(f"   Aliases: {aliases_str}")

            # Display indicator types
            indicator_types = ind.get("types", [])
            if indicator_types:
                print(f"   Indicator Types: {indicator_types}")

            # Display description
            desc = ind.get("description", "")
            if desc:
                print(f"   Description: {desc[:150]}...")

            print()

    # ── Device Data - TẤT CẢ CỤ THỂ ────────────────────────────────────────
    devices = result.get("matched_devices") or []
    if devices:
        print("=" * 70)
        print(" DEVICE IMPACT - CỤ THỂ")
        print("=" * 70)
        affected = len({d["device_id"] for d in devices})
        print(f"Tổng thiết bị bị ảnh hưởng: {affected}\n")

        device_dict = {}
        cves_dict = {}  # Store CVE objects for description lookup
        cves_collected = result.get("collected_cves") or []
        for cve in cves_collected:
            cves_dict[cve.get("id")] = cve

        for d in devices:
            dev_id = d["device_id"]
            if dev_id not in device_dict:
                device_dict[dev_id] = {
                    "hostname": d.get("hostname"),
                    "ip": d.get("ip"),
                    "os": d.get("os"),
                    "criticality": d.get("criticality"),
                    "affected_software": d.get("affected_software"),
                    "cves": []
                }
            device_dict[dev_id]["cves"].append({
                "cve_id": d.get("cve_id"),
                "risk_level": d.get("risk_level"),
                "cvss_score": d.get("cvss_score")
            })

        for dev_id, info in device_dict.items():
            hostname = info["hostname"]
            ip = info["ip"]
            os = info["os"]
            criticality = info["criticality"]
            cves = info["cves"]
            software = info.get("affected_software", "N/A")

            print(f"• Device: {dev_id}")
            print(f"  Hostname: {hostname}")
            print(f"  IP: {ip}")
            print(f"  OS: {os}")
            print(f"  Criticality: {criticality}")
            print(f"  Số CVEs: {len(cves)}")
            print(f"  CVEs cụ thể:")
            for cve in cves:
                print(f"    - {cve['cve_id']}: {cve['risk_level']} (CVSS: {cve['cvss_score']})")
            print()

            # Hướng khắc phục
            print(f"  Hướng khắc phục:")

            # Find highest risk CVE
            highest_risk_cve = max(cves, key=lambda x: float(x.get("cvss_score", 0)) if isinstance(x.get("cvss_score"), (int, float, str)) and str(x.get("cvss_score")).replace('.', '', 1).isdigit() else 0)
            cvss = highest_risk_cve.get("cvss_score", 0)
            try:
                cvss_float = float(cvss) if cvss and cvss != "N/A" else 0
            except (ValueError, TypeError):
                cvss_float = 0

            # Timeline priority
            if cvss_float >= 9.0:
                print(f"    -  Ưu tiên CRITICAL: Xử lý ngay trong 24 giờ")
            elif cvss_float >= 7.0:
                print(f"    -  Ưu tiên HIGH: Xử lý trong 72 giờ")
            else:
                print(f"    -  Ưu tiên MEDIUM: Lên lịch xử lý trong 2 tuần")

            # Update affected software
            print(f"    - Cập nhật phần mềm: Nâng cấp {software} lên phiên bản mới nhất")

            # Get remediation based on CVE description
            cve_description = ""
            highest_cve_id = highest_risk_cve.get("cve_id")
            if highest_cve_id in cves_dict:
                cve_description = cves_dict[highest_cve_id].get("description", "")

            remediation_steps = _get_remediation_steps(cve_description)
            for step in remediation_steps:
                print(f"    {step}")
            print()

    # ── Reports ──────────────────────────────────────────────────────────────
    report = result.get("final_report", "")
    if report:
        print("=" * 70)
        print(f" REPORT: {report}\n")

    print("=" * 70)


# ── Menu 2: Report pipeline helper functions ───────────────────────────────
def _ask_time_range() -> tuple[str, str, int]:
    """
    Hỏi người dùng khoảng thời gian cho báo cáo.
    Returns: (start_date_iso, end_date_iso, days_back)
    """
    print("\n=== CHỌN KHOẢNG THỜI GIAN ===")
    print("  [Enter]            = 7 ngày gần đây (mặc định)")
    print("  Số ngày (VD: 30)   = 30 ngày gần đây")
    print("  Ngày cụ thể        = 01-04-2026 to 07-05-2026  (định dạng DD-MM-YYYY)")

    user_input = input("\nNhập (để trống = 7 ngày): ").strip()

    end_dt = datetime.now(timezone.utc)
    start_dt = None
    days_back = 7

    if not user_input:
        # Default: 7 days
        start_dt = end_dt - timedelta(days=7)
        days_back = 7
    elif user_input.isdigit():
        # Input is number of days
        days_back = int(user_input)
        start_dt = end_dt - timedelta(days=days_back)
    else:
        # Try to parse date range: "DD-MM-YYYY to DD-MM-YYYY" hoặc "YYYY-MM-DD to YYYY-MM-DD"
        try:
            if " to " in user_input:
                date_parts = user_input.split(" to ")
                start_str = date_parts[0].strip()
                end_str = date_parts[1].strip()

                # Try DD-MM-YYYY format first
                try:
                    start_dt = datetime.strptime(start_str, "%d-%m-%Y")
                    end_dt = datetime.strptime(end_str, "%d-%m-%Y")
                except ValueError:
                    # Fall back to YYYY-MM-DD format
                    start_dt = datetime.fromisoformat(start_str)
                    end_dt = datetime.fromisoformat(end_str)

                # Make timezone aware
                start_dt = start_dt.replace(tzinfo=timezone.utc)
                end_dt = end_dt.replace(tzinfo=timezone.utc)
                days_back = (end_dt.date() - start_dt.date()).days
            else:
                # Try single date
                try:
                    start_dt = datetime.strptime(user_input.strip(), "%d-%m-%Y")
                except ValueError:
                    start_dt = datetime.fromisoformat(user_input.strip())
                start_dt = start_dt.replace(tzinfo=timezone.utc)
                end_dt = datetime.now(timezone.utc)
                days_back = (end_dt.date() - start_dt.date()).days
        except ValueError:
            print(" Format không hợp lệ (dùng DD-MM-YYYY hoặc YYYY-MM-DD), dùng 7 ngày mặc định")
            end_dt = datetime.now(timezone.utc)
            start_dt = end_dt - timedelta(days=7)
            days_back = 7

    # Convert to NVD API format: ISO 8601 with milliseconds
    # Set end_date to end of day (23:59:59) for proper range filtering
    end_dt = end_dt.replace(hour=23, minute=59, second=59)
    start_date = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_date = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

    # Display in DD-MM-YYYY format
    start_display = start_dt.strftime("%d-%m-%Y")
    end_display = end_dt.strftime("%d-%m-%Y")
    print(f"\n Khoảng thời gian: {start_display} → {end_display} ({days_back} ngày)")
    return start_date, end_date, days_back


def _run_report_pipeline(start_date: str, end_date: str, days_back: int) -> dict:
    """
    Chạy pipeline thu thập dữ liệu cho báo cáo (không qua LLM agent).
    Returns: state dict với dữ liệu thu thập
    """
    print("\n" + "="*55)
    print("THU THẬP DỮ LIỆU CHO BÁO CÁO")
    print("="*55)

    state = {
        "collected_cves": [],
        "collected_indicators": [],
        "matched_devices": [],
        "device_cve_map": {},
        "tool_observations": [],
    }

    # Bước 1: Lấy CVE từ KB + NVD (merge cả hai)
    print(f"\n  Lấy CVE...")
    from tools.doc_store import fetch_kb_cves, load_knowledge_base
    from datetime import datetime

    # Lấy từ KB
    kb_cves = fetch_kb_cves("").get("context", [])

    # Lọc CVE theo date range (uploaded_date)
    filtered_kb_cves = []
    start_dt_cmp = datetime.fromisoformat(start_date + '+00:00')
    end_dt_cmp = datetime.fromisoformat(end_date + '+00:00')

    for cve in kb_cves:
        uploaded = cve.get("uploaded_date", "")
        if uploaded:
            try:
                upload_dt = datetime.fromisoformat(uploaded.replace('Z', '+00:00'))
                if start_dt_cmp <= upload_dt <= end_dt_cmp:
                    filtered_kb_cves.append(cve)
            except:
                pass

    print(f"   KB:  {len(filtered_kb_cves)} CVEs")

    # Cũng lấy từ NVD (merge cả hai)
    nvd_result = fetch_nvd_cves(
        keyword="",
        severity="",
        days_back=days_back,
        start_date=start_date,
        end_date=end_date
    )
    nvd_cves = nvd_result.get("context", [])
    print(f"   NVD: {len(nvd_cves)} CVEs")

    # Merge KB + NVD (dedup by ID)
    kb_ids = {cve.get("id") for cve in filtered_kb_cves if cve.get("id")}
    for cve in nvd_cves:
        if cve.get("id") not in kb_ids:
            filtered_kb_cves.append(cve)

    state["collected_cves"] = filtered_kb_cves
    print(f"    Total: {len(state['collected_cves'])} CVEs collected")

    # Bước 2: Lấy IOC/Malware từ KB trước, sau đó OpenCTI
    print(f"\n  Lấy IOC/Malware...")

    # Lấy từ KB
    from tools.doc_store import fetch_kb_indicators
    kb_indicators = fetch_kb_indicators("", "all").get("context", [])

    # Lọc theo date range
    filtered_kb_indicators = []
    for ind in kb_indicators:
        uploaded = ind.get("uploaded_date", "")
        if uploaded:
            try:
                upload_dt = datetime.fromisoformat(uploaded.replace('Z', '+00:00'))
                if start_dt_cmp <= upload_dt <= end_dt_cmp:
                    filtered_kb_indicators.append(ind)
            except:
                pass

    print(f"   KB:  {len(filtered_kb_indicators)} indicators")

    # Cũng lấy từ OpenCTI
    ioc_result = fetch_opencti_indicators(search_term="", start_date=start_date, end_date=end_date, max_results=100)
    opencti_indicators = ioc_result.get("context", [])
    print(f"   OpenCTI: {len(opencti_indicators)} indicators")

    # Merge results (avoid duplicates by ID)
    state["collected_indicators"] = filtered_kb_indicators + opencti_indicators
    print(f"    Total: {len(state['collected_indicators'])} IOC/Malware collected")

    # Bước 3: So khớp CVE với thiết bị nội bộ
    if state["collected_cves"]:
        print(f"\n  So khớp CVE với thiết bị nội bộ...")
        match_result = match_cves_with_cmdb(cve_list=state["collected_cves"])
        state["matched_devices"] = match_result.get("context", [])
        print(f"    Tìm được {len(state['matched_devices'])} device-CVE matches")
    else:
        print(f"\n  Bỏ qua: không có CVE để match")

    # Tóm tắt
    print("\n" + "="*55)
    print(" TÓM TẮT DỮ LIỆU")
    print("="*55)
    print(f"CVEs:              {len(state['collected_cves'])}")
    print(f"IOCs/Malware:      {len(state['collected_indicators'])}")
    print(f"Device matches:    {len(state['matched_devices'])}")
    if state["matched_devices"]:
        affected_devices = len({d.get("device_id") for d in state["matched_devices"]})
        print(f"Devices affected:  {affected_devices}")

    return state


def _ask_and_export(state: dict, start_date: str, end_date: str):
    """
    Tạo báo cáo HTML.
    """
    print("\n" + "="*55)
    print(" XUẤT BÁO CÁO")
    print("="*55)

    # Tạo báo cáo với format DD-MM-YYYY
    start_fmt = f"{start_date[8:10]}-{start_date[5:7]}-{start_date[:4]}"
    end_fmt = f"{end_date[8:10]}-{end_date[5:7]}-{end_date[:4]}"
    date_range_display = f"{start_fmt} đến {end_fmt}"
    title = f"Threat Intelligence Report - {date_range_display}"

    result = generate_report(
        report_type="executive_summary",
        title=title,
        content="",
        state=state,
        export_format="html",
        start_date=start_date,
        end_date=end_date
    )

    file_path = result.get("file_path", "")
    if file_path:
        print(f"\n Báo cáo đã được lưu tại:")
        print(f"   {file_path}")

        # Auto-open report in default browser
        try:
            abs_path = os.path.abspath(file_path)
            webbrowser.open(f"file:///{abs_path}")
            print(f" Đang mở file trong trình duyệt...")
        except Exception as e:
            print(f"  Không thể tự động mở file: {e}")
            print(f" Vui lòng mở file bằng tay (double-click file)")


# ── Interactive menu ───────────────────────────────────────────────────────
def interactive_mode():
    print(BANNER)
    print(f"  Model: {OLLAMA_MODEL} @ {OLLAMA_BASE_URL}")
    print(f"  Báo cáo sẽ lưu tại: {os.path.abspath(REPORTS_DIR)}")

    # Kiểm tra kết nối Ollama
    print("\n Kiểm tra kết nối Ollama...")
    ok, msg = check_ollama_connection()
    if not ok:
        print(f"\n {msg}\n")
        sys.exit(1)
    print(f" Ollama sẵn sàng (model: {OLLAMA_MODEL})\n")

    while True:
        print(MENU)
        choice = input("Chọn (0-4): ").strip()

        if choice == "0":
            print("\nTạm biệt!\n")
            break

        elif choice == "1":
            # Menu 1: CVE scan
            keyword = input("\nNhập từ khóa CVE (ví dụ: log4j): ").strip()
            query = PRESET_QUERIES["1"].format(keyword) if keyword else PRESET_QUERIES["1"].format("CVE")
            run_query(query)

        elif choice == "2":
            # Menu 2: Interactive report generation with date range
            start_date, end_date, days_back = _ask_time_range()
            state = _run_report_pipeline(start_date, end_date, days_back)
            _ask_and_export(state, start_date, end_date)

        elif choice == "3":
            # Menu 3: Upload document
            print("\n UPLOAD DOCUMENT (CVE/IOC/Malware)")
            print("Hỗ trợ: .json, .txt (chứa CVE IDs), .csv")
            file_path = input("Nhập đường dẫn file: ").strip().strip('"')
            if file_path:
                from tools.doc_store import upload_document, get_knowledge_base_stats
                result = upload_document(file_path)
                if "error" in result:
                    print(f" {result['error']}")
                else:
                    saved = result.get("context", {})
                    print(f" Đã lưu: CVEs={saved.get('cves',0)}, IOCs={saved.get('iocs',0)}, Malwares={saved.get('malwares',0)}")
                stats = get_knowledge_base_stats()
                s = stats.get("context", {})

                # Display KB stats with upload dates
                print(f"\n[Knowledge Base Stats]")
                for cat in ["cves", "iocs", "malwares"]:
                    info = s.get(cat, {})
                    count = info.get("count", 0) if isinstance(info, dict) else info
                    latest = info.get("latest_upload") if isinstance(info, dict) else None
                    cat_name = {"cves": "CVEs", "iocs": "IOCs", "malwares": "Malwares"}.get(cat)
                    if latest:
                        print(f"   {cat_name:10s}: {count:3d} records | Last upload: {latest}")
                    else:
                        print(f"   {cat_name:10s}: {count:3d} records | Chua upload")

        elif choice == "4":
            # Menu 4: Free query - Interactive chat mode
            print("\n╔════════════════════════════════════════════════════════╗")
            print("║           CHAT MODE - ATI THREAT INTELLIGENCE          ║")
            print("║  (Gõ 'exit' hoặc 'quit' để quay lại menu chính)       ║")
            print("╚════════════════════════════════════════════════════════╝\n")

            while True:
                query = input("Bạn: ").strip()

                if query.lower() in ["exit", "quit", "thoát"]:
                    print("\nQuay lại menu chính...\n")
                    break

                if not query:
                    print("Vui lòng nhập câu hỏi.\n")
                    continue

                result = run_query(query, verbose=False, chat_mode=True)
                _print_chat_response(result)

        else:
            print("Lựa chọn không hợp lệ.")

        input("\n[Enter để tiếp tục]")


# ── CLI ────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="ATI-AgenticThreatIntelligence System — Ollama Local Edition"
    )
    parser.add_argument("--query", "-q", type=str, help="Chạy câu hỏi trực tiếp")
    parser.add_argument("--test",  "-t", action="store_true", help="Chạy test cases")
    parser.add_argument("--check", "-c", action="store_true", help="Kiểm tra kết nối Ollama")
    args = parser.parse_args()

    if args.check:
        ok, msg = check_ollama_connection()
        print("" if ok else "", msg)
        sys.exit(0 if ok else 1)

    if args.query:
        print(BANNER)
        ok, msg = check_ollama_connection()
        if not ok:
            print(f" {msg}")
            sys.exit(1)
        run_query(args.query)
        return

    if args.test:
        print(BANNER)
        ok, msg = check_ollama_connection()
        if not ok:
            print(f" {msg}")
            sys.exit(1)
        print("\n Chạy Test Cases\n" + "="*55)
        for i, q in enumerate(TEST_CASES, 1):
            print(f"\n[TEST {i}] {q}")
            run_query(q)
        return

    # Default: interactive
    interactive_mode()


if __name__ == "__main__":
    main()
