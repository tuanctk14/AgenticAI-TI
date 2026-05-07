"""
main.py - Entry point cho CyberSec Multi-Agent System (Ollama Local Edition)
"""
import sys
import io
import argparse
import os

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

# ── Banner ─────────────────────────────────────────────────────────────────
BANNER = """
  _____ _     _     _ _     _    _      _ _
 / ____| |   | |   | | |   | |  | |    | | |
| |    | |__ | |_  | | |__ | |  | | |  | | |
| |    | '_ \| __| | | '_ \| |  | | |__| | |
| |____| | | | |__ | | |_) | |__| |  __  |_|
 \_____|_| |_|\__| | |_.__/ \____/|_|  |_(_)
                _/ |
               |__/
      CyberSec Multi-Agent System - Ollama Local Edition
"""

MENU = """
+--------------------------------------------------------------+
|                    MENU CHINH                                |
+--------------------------------------------------------------+
|  1. Quet CVE va tim thiet bi bi anh huong                    |
|  2. Tao bao cao                                              |
|  3. Upload / xu ly tai lieu noi bo                           |
|  4. Liet ke thiet bi trong CMDB                              |
|  5. Cau hoi tu do (hoi bat ky)                               |
|  0. Thoat                                                    |
+--------------------------------------------------------------+
"""

PRESET_QUERIES = {
    "1": (
        "Hay quet lo hong (keyword: {}) tu NVD, "
        "so khop voi thiet bi noi bo va cho biet thiet bi nao bi anh huong."
    ),
    "2": (
        "Thuc hien danh gia CVE: lay CVE severity HIGH tu NVD, "
        "so khop voi he thong noi bo, tao bao cao executive_summary."
    ),
    "3": None,   # Upload document
    "4": "Liet ke toan bo thiet bi trong CMDB.",
    "5": None,   # Free query
}

TEST_CASES = [
    "Quét CVE Log4Shell từ NVD và tìm thiết bị bị ảnh hưởng trong CMDB.",
    "Lấy IoC từ OpenCTI liên quan đến ransomware.",
    "Phân tích Apache CVE-2021-41773 theo MITRE ATT&CK.",
]


# ── Core run ───────────────────────────────────────────────────────────────
def run_query(query: str, verbose: bool = True) -> dict:
    """Chạy một câu hỏi qua hệ thống multi-agent."""
    graph = get_graph()
    state = init_state(query)

    if verbose:
        print(f"\n🚀 Đang xử lý: {query[:80]}...")
        print("-" * 55)

    try:
        result = graph.invoke(state, config={"recursion_limit": 30})
    except Exception as e:
        print(f"❌ Lỗi hệ thống: {e}")
        return {"error": str(e)}

    if verbose:
        _print_summary(result)

    return result


def _print_summary(result: dict):
    """In tóm tắt kết quả sau khi chạy xong - CHI TIẾT ĐẦY ĐỦ."""
    print("\n" + "="*70)
    print("📊 KẾT QUẢ CHI TIẾT ĐẦY ĐỦ")
    print("="*70)

    history = result.get("agent_history", [])
    print(f"Agents đã dùng: {' → '.join(history)}")
    print(f"Số bước: {result.get('num_steps', 0)}\n")

    # ── CVE Data - TẤT CẢ ────────────────────────────────────────────────────
    cves = result.get("collected_cves") or []
    if cves:
        print("=" * 70)
        print("📋 CVE DETAILS - TẤT CẢ")
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
        print("🔍 THREAT INTELLIGENCE DETAILS - TẤT CẢ")
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
        print("💻 DEVICE IMPACT - CỤ THỂ")
        print("=" * 70)
        affected = len({d["device_id"] for d in devices})
        print(f"Tổng thiết bị bị ảnh hưởng: {affected}\n")

        device_dict = {}
        for d in devices:
            dev_id = d["device_id"]
            if dev_id not in device_dict:
                device_dict[dev_id] = {
                    "hostname": d.get("hostname"),
                    "ip": d.get("ip"),
                    "os": d.get("os"),
                    "criticality": d.get("criticality"),
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

    # ── Reports ──────────────────────────────────────────────────────────────
    report = result.get("final_report", "")
    if report:
        print("=" * 70)
        print(f"📄 REPORT: {report}\n")

    # ── Agent Response ────────────────────────────────────────────────────────
    last = result.get("last_agent_response", "")
    if last and last.strip():
        # Check if response contains ANSWER: or other meaningful content
        if "ANSWER:" in last:
            answer = last.split("ANSWER:")[1].strip()
        else:
            # Use entire response if no ANSWER: format
            answer = last.strip()

        # Only show if answer is not just generic text
        if answer and len(answer) > 20 and not answer.startswith("HANDOFF:"):
            print("=" * 70)
            print("💬 KẾT LUẬN TỪ AGENT:")
            print("=" * 70)
            print(answer)
            print()

    print("=" * 70)


# ── Interactive menu ───────────────────────────────────────────────────────
def interactive_mode():
    print(BANNER)
    print(f"  Model: {OLLAMA_MODEL} @ {OLLAMA_BASE_URL}")
    print(f"  Báo cáo sẽ lưu tại: {os.path.abspath(REPORTS_DIR)}")

    # Kiểm tra kết nối Ollama
    print("\n🔍 Kiểm tra kết nối Ollama...")
    ok, msg = check_ollama_connection()
    if not ok:
        print(f"\n❌ {msg}\n")
        sys.exit(1)
    print(f"✅ Ollama sẵn sàng (model: {OLLAMA_MODEL})\n")

    while True:
        print(MENU)
        choice = input("Chon (0-5): ").strip()

        if choice == "0":
            print("\nTam biet!\n")
            break

        elif choice == "1":
            # Menu 1: CVE scan
            keyword = input("\nNhap tu khoa CVE (vy du: log4j): ").strip()
            query = PRESET_QUERIES["1"].format(keyword) if keyword else PRESET_QUERIES["1"].format("CVE")
            run_query(query)

        elif choice == "2":
            # Menu 2: Report generation
            query = PRESET_QUERIES["2"]
            run_query(query)

        elif choice == "3":
            # Menu 3: Upload document flow
            print("\nNhap noi dung tai lieu (ket thuc bang dong chi co 'END'):")
            lines = []
            while True:
                line = input()
                if line.strip() == "END":
                    break
                lines.append(line)
            doc_content = "\n".join(lines)
            doc_name = input("Ten tai lieu: ").strip() or "Tai lieu noi bo"
            query = (
                f"Upload tai lieu '{doc_name}' vao he thong va tom tat noi dung:\n"
                f"{doc_content}"
            )
            run_query(query)

        elif choice == "4":
            # Menu 4: CMDB list
            query = PRESET_QUERIES["4"]
            run_query(query)

        elif choice == "5":
            # Menu 5: Free query (IOC/Malware/APT/CVE/Device/Report)
            query = input("\nNhap cau hoi (CVE, IOC, Malware, APT, device, ...): ").strip()
            if query:
                run_query(query)
            else:
                print("Cau hoi trong.")

        else:
            print("Lua chon khong hop le.")

        input("\n[Enter de tiep tuc]")


# ── CLI ────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="CyberSec Multi-Agent System — Ollama Local Edition"
    )
    parser.add_argument("--query", "-q", type=str, help="Chạy câu hỏi trực tiếp")
    parser.add_argument("--test",  "-t", action="store_true", help="Chạy test cases")
    parser.add_argument("--check", "-c", action="store_true", help="Kiểm tra kết nối Ollama")
    args = parser.parse_args()

    if args.check:
        ok, msg = check_ollama_connection()
        print("✅" if ok else "❌", msg)
        sys.exit(0 if ok else 1)

    if args.query:
        print(BANNER)
        ok, msg = check_ollama_connection()
        if not ok:
            print(f"❌ {msg}")
            sys.exit(1)
        run_query(args.query)
        return

    if args.test:
        print(BANNER)
        ok, msg = check_ollama_connection()
        if not ok:
            print(f"❌ {msg}")
            sys.exit(1)
        print("\n🧪 Chạy Test Cases\n" + "="*55)
        for i, q in enumerate(TEST_CASES, 1):
            print(f"\n[TEST {i}] {q}")
            run_query(q)
        return

    # Default: interactive
    interactive_mode()


if __name__ == "__main__":
    main()
