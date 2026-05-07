"""
tools/report_generator.py - Tạo và lưu báo cáo bảo mật (MD / TXT)
"""
import os
import json
from datetime import datetime
from config import REPORTS_DIR

# Lưu trong memory để tra cứu trong session
REPORTS_STORE: dict[str, dict] = {}


def generate_report(
    report_type: str = "vulnerability_assessment",
    title:       str = "",
    content:     str = "",
    state:       dict | None = None,
    export_format: str = "html",
) -> dict:
    """
    Tạo báo cáo bảo mật và lưu ra file.

    report_type: vulnerability_assessment | executive_summary | patch_advisory |
                 threat_intel | incident_report
    export_format: html (.html) - chỉ hỗ trợ HTML format
    """
    # Force HTML format
    export_format = "html"
    print(f"  [Report] Tạo: type='{report_type}', title='{title}', format='html'")

    ts    = datetime.now()
    rid   = ts.strftime("%Y%m%d_%H%M%S")
    ext   = ".html"
    fname = f"{report_type}_{rid}{ext}"
    fpath = os.path.join(REPORTS_DIR, fname)

    # ── Xây dựng nội dung báo cáo từ state nếu có ──────────────────────
    if state and not content:
        content = _build_report_from_state(report_type, title, state, ts)

    if not content:
        content = f"# {title or report_type.replace('_', ' ').title()}\n\nBáo cáo trống."

    # Đảm bảo có header
    if not content.startswith("#"):
        content = f"# {title or report_type.upper()}\n\n{content}"

    # Thêm footer
    footer = (
        f"\n\n---\n"
        f"*Tạo bởi CyberSec Multi-Agent System | {ts.strftime('%d/%m/%Y %H:%M:%S')}*\n"
        f"*Model: Ollama Local | Report ID: {rid}*\n"
    )
    full_content = content + footer

    # Convert sang HTML
    full_content = _markdown_to_html(full_content, title or report_type)

    # Lưu file
    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(full_content)

    # Lưu vào store
    REPORTS_STORE[rid] = {
        "type":    report_type,
        "title":   title,
        "content": full_content,
        "file":    fpath,
        "created": ts.isoformat(),
        "format":  export_format,
    }

    print(f"  [Report] ✅ Lưu tại: {fpath}")
    return {
        "context":   {"report_id": rid, "file": fpath, "type": report_type},
        "source":    "ReportGenerator",
        "report_id": rid,
        "file_path": fpath,
    }


def _build_report_from_state(
    report_type: str, title: str, state: dict, ts: datetime
) -> str:
    """Tự động tạo nội dung báo cáo từ state của hệ thống."""
    lines = []
    t = title or report_type.replace("_", " ").title()

    lines += [
        f"# {t}",
        f"\n**Ngay tao:** {ts.strftime('%d/%m/%Y %H:%M')}",
        f"**Loai bao cao:** {report_type}",
        f"**He thong:** CyberSec Multi-Agent (Ollama Local)",
        "\n---",
    ]

    # Dashboard cho executive_summary
    if report_type == "executive_summary":
        cves = state.get("collected_cves") or []
        indicators = state.get("collected_indicators") or []
        devices = state.get("matched_devices") or []
        device_cve_map = state.get("device_cve_map") or {}

        # Count IOC/Malware
        ioc_count = len([i for i in indicators if i.get("entity_type") == "Indicator"])
        malware_count = len([i for i in indicators if i.get("entity_type") == "Malware"])
        attack_pattern_count = len([i for i in indicators if i.get("entity_type") == "Attack Pattern"])

        # Tính Risk Score
        risk_score = 0
        if cves:
            scores = []
            for c in cves:
                score = c.get("cvss_score", 0) or 0
                if score and score != "N/A":
                    try:
                        scores.append(float(score))
                    except (ValueError, TypeError):
                        pass
            avg_cvss = sum(scores) / len(scores) if scores else 0.0
            risk_score = min(100, int(avg_cvss * 10))

        risk_level = (
            "CRITICAL (9-10)" if risk_score >= 90 else
            "HIGH (7-9)" if risk_score >= 70 else
            "MEDIUM (4-7)" if risk_score >= 40 else
            "LOW (0-4)"
        )

        unique_devices = len({d['device_id'] for d in devices}) if devices else len(device_cve_map)

        lines += [
            "\n## DASHBOARD",
            f"\n| Metric | Value |",
            f"|--------|-------|",
            f"| Risk Score | {risk_score}/100 |",
            f"| Risk Level | **{risk_level}** |",
            f"| Total CVEs | {len(cves)} |",
            f"| IOC (Indicators) | {ioc_count} |",
            f"| Malware Families | {malware_count} |",
            f"| Attack Patterns | {attack_pattern_count} |",
            f"| Affected Devices | {unique_devices} |",
            f"| Critical Matches | {len([d for d in devices if d.get('risk_level') == 'CRITICAL'])} |",
            "",
        ]


    # CVEs - hiển thị cho tất cả loại báo cáo
    cves: list = state.get("collected_cves") or []
    if cves:
        lines += [f"\n## DANH SACH CVE ({len(cves)} CVEs)", ""]
        lines.append("| # | CVE ID | CVSS | Mức Độ | Ngày Công Bố |")
        lines.append("|---|--------|------|--------|--------------|")
        for i, c in enumerate(cves, 1):
            lines.append(
                f"| {i} | **{c.get('id','N/A')}** | {c.get('cvss_score','N/A')} "
                f"| {c.get('severity','N/A')} | {c.get('published','N/A')} |"
            )
        lines.append("")

        # Thêm chi tiết CVEs CRITICAL
        critical_only = [c for c in cves if c.get("severity", "").upper() == "CRITICAL"]
        if critical_only:
            lines += ["\n### CVE Nghiêm Trọng Cần Ưu Tiên", ""]
            for c in critical_only[:5]:
                cve_id = c.get("id", "N/A")
                cvss = c.get("cvss_score", "N/A")
                severity = c.get("severity", "N/A")
                desc = c.get("description", "")
                # Cắt ngắn description nhưng đảm bảo không bị cắt giữa câu
                if desc and desc != "N/A":
                    # Chỉ lấy phần trước newline (loại bỏ "This issue affects..." part)
                    desc = desc.split('\n')[0]
                    # Cắt để tối đa 150 ký tự, tại whitespace cuối cùng
                    if len(desc) > 150:
                        desc = desc[:150].rsplit(" ", 1)[0]
                    lines.append(f"- **{cve_id}** (CVSS: {cvss}, {severity}): {desc}...")
                else:
                    lines.append(f"- **{cve_id}** (CVSS: {cvss}, {severity})")
            lines.append("")

    # IOC / Malware / Threat Intelligence
    indicators: list = state.get("collected_indicators") or []
    if indicators:
        lines += [f"\n## THREAT INTELLIGENCE ({len(indicators)} Kết Quả)", ""]

        # Chia theo entity type
        ioc_list = [i for i in indicators if i.get("entity_type") == "Indicator"]
        malware_list = [i for i in indicators if i.get("entity_type") == "Malware"]
        pattern_list = [i for i in indicators if i.get("entity_type") == "Attack Pattern"]

        # Indicators of Compromise
        if ioc_list:
            lines += ["\n### Indicators of Compromise (IOC)", ""]
            lines.append("| # | Loại | Tên/Pattern | Score | Confidence |")
            lines.append("|---|------|-------------|-------|------------|")
            for i, ioc in enumerate(ioc_list[:10], 1):
                name = ioc.get("name", "N/A")
                score = ioc.get("score", 0)
                conf = ioc.get("confidence", 0)
                lines.append(f"| {i} | IOC | {name} | {score} | {conf}% |")
            lines.append("")

        # Malware Families
        if malware_list:
            lines += ["\n### Malware Families", ""]
            lines.append("| # | Tên Malware | Loại | Bí Danh | Mô Tả |")
            lines.append("|---|-------------|------|--------|-------|")
            for i, mal in enumerate(malware_list[:10], 1):
                name = mal.get("name", "N/A")
                mal_types = ", ".join(mal.get("malware_types", [])[:2])
                aliases = ", ".join(mal.get("aliases", [])[:2])
                desc = mal.get("description", "N/A")[:60]
                lines.append(f"| {i} | {name} | {mal_types} | {aliases} | {desc}... |")
            lines.append("")

        # Attack Patterns
        if pattern_list:
            lines += ["\n### Attack Patterns (MITRE ATT&CK)", ""]
            lines.append("| # | Technique | Tên | Mô Tả |")
            lines.append("|---|-----------|-----|-------|")
            for i, pat in enumerate(pattern_list[:10], 1):
                name = pat.get("name", "N/A")
                pattern = pat.get("pattern", "N/A")[:30]
                desc = pat.get("description", "N/A")[:60]
                lines.append(f"| {i} | {pattern} | {name} | {desc}... |")
            lines.append("")

    # Matched devices with remediation
    devices: list = state.get("matched_devices") or []
    if devices:
        unique_device_ids = {d['device_id'] for d in devices}
        lines += [f"\n## THIET BI BI ANH HUONG ({len(unique_device_ids)} Thiết Bị)", ""]

        # Build CVE info lookup
        cves_dict = {c["id"]: c for c in cves}

        # Group devices with their CVEs
        device_map = {}
        for d in devices:
            dev_id = d["device_id"]
            if dev_id not in device_map:
                device_map[dev_id] = {
                    "hostname": d["hostname"],
                    "ip": d["ip"],
                    "os": d["os"],
                    "criticality": d["criticality"],
                    "cves": []
                }
            device_map[dev_id]["cves"].append(d)

        # Calculate risk level for each device
        device_risk = {}
        for dev_id, dev_info in device_map.items():
            risk_level = max([c.get("risk_level", "MEDIUM") for c in dev_info["cves"]],
                            key=lambda x: (x == "CRITICAL", x == "HIGH", x == "MEDIUM"))
            device_risk[dev_id] = risk_level

        # Sort devices by risk level (CRITICAL > HIGH > MEDIUM > LOW)
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_devices = sorted(device_map.items(),
                               key=lambda x: risk_order.get(device_risk[x[0]], 4))

        # Bảng tóm tắt thiết bị (hiển thị đầy đủ, không giới hạn)
        lines.append("| # | Thiết Bị | IP | OS | CVE Count | Mức Độ |")
        lines.append("|---|----------|----|----|-----------|--------|")
        for idx, (dev_id, dev_info) in enumerate(sorted_devices, 1):
            cve_count = len(dev_info["cves"])
            risk = device_risk[dev_id]
            lines.append(
                f"| {idx} | {dev_info['hostname']} | {dev_info['ip']} | {dev_info['os']} "
                f"| {cve_count} | **{risk}** |"
            )
        lines.append("")

        # Chi tiết từng thiết bị
        lines += ["\n### Chi Tiết Khắc Phục Từng Thiết Bị", ""]

        # Render each device in sorted order
        for dev_id, dev_info in sorted_devices:
            risk_level = device_risk[dev_id]
            lines.append(f"\n#### {dev_info['hostname']} ({dev_info['ip']}) - **{risk_level}**")
            lines.append(f"- **OS**: {dev_info['os']}")
            lines.append(f"- **Criticality**: {dev_info['criticality']}")
            lines.append("")

            # Danh sách CVEs ảnh hưởng
            lines.append("**CVEs Ảnh Hưởng:**")
            for cve_match in dev_info["cves"]:
                cve_id = cve_match["cve_id"]
                cvss = cve_match.get("cvss_score", "N/A")
                software = cve_match.get("affected_software", "N/A")
                lines.append(f"- **{cve_id}** (CVSS: {cvss}, Phần Mềm: {software})")

            lines.append("")
            lines.append("**Hướng khắc phục:**")

            # Add remediation steps for highest risk CVE
            highest_risk_cve = max(dev_info["cves"], key=lambda x: float(x.get("cvss_score", 0)) if isinstance(x.get("cvss_score"), (int, float, str)) and str(x.get("cvss_score")).replace('.', '', 1).isdigit() else 0)
            cve_id = highest_risk_cve["cve_id"]
            cve_info = cves_dict.get(cve_id, {})
            cvss = highest_risk_cve.get("cvss_score", 0)
            software = highest_risk_cve.get("affected_software", "unknown")
            desc = cve_info.get("description", "")

            try:
                cvss_float = float(cvss) if cvss and cvss != "N/A" else 0
            except (ValueError, TypeError):
                cvss_float = 0
            remediation = _get_remediation(cvss_float, software, desc)
            for step in remediation:
                # step đã có dấu - ở đầu nên không cần thêm
                if step.startswith("- "):
                    lines.append(step)
                else:
                    lines.append(f"- {step}")
            lines.append("")

    # MITRE ATT&CK
    attack: dict = state.get("attack_info") or {}
    if attack and attack.get("context"):
        ctx = attack["context"]
        lines += ["\n## MITRE ATT&CK Mapping", ""]
        for t_ in ctx.get("techniques", []):
            lines.append(f"- **{t_['id']} - {t_['name']}** ({t_['tactic']})")
            lines.append(f"  > {t_['description']}")
        actors = ctx.get("threat_actors", [])
        if actors:
            lines.append(f"\nThreat Actors: {', '.join(actors)}")

    # NIST Controls
    nist: dict = state.get("nist_info") or {}
    if nist and nist.get("context"):
        ctx = nist["context"]
        lines += ["\n## NIST SP 800-53 Controls", ""]
        lines.append(f"Uu tien: {ctx.get('priority','N/A')} | "
                     f"Thoi han: {ctx.get('timeframe','N/A')}")
        lines.append("")
        for ctrl in ctx.get("controls", []):
            lines.append(f"- **{ctrl['id']} - {ctrl['name']}**")
            lines.append(f"  → {ctrl['action']}")

    # Analyst summary
    last_response = state.get("last_agent_response", "")
    if last_response and "ANSWER:" in last_response:
        answer = last_response.split("ANSWER:")[1].strip()
        lines += ["\n## PHAN TICH & KHUYEN NGHI", "", answer]

    return "\n".join(lines)


def _get_remediation(cve_score: float, affected_software: str, description: str) -> list[str]:
    """Tạo danh sách hướng khắc phục dựa trên CVSS score và loại lỗ hổng."""
    steps = []

    # Bước 1: Timeline ưu tiên
    if cve_score >= 9.0:
        steps.append("⚡ **Ưu tiên CRITICAL**: Xử lý ngay trong 24 giờ")
    elif cve_score >= 7.0:
        steps.append("🔴 **Ưu tiên HIGH**: Xử lý trong 72 giờ")
    else:
        steps.append("🟡 **Ưu tiên MEDIUM**: Lên lịch xử lý trong 2 tuần")

    # Bước 2: Action cơ bản
    steps.append(f"- **Cập nhật phần mềm**: Nâng cấp {affected_software} lên phiên bản mới nhất")
    steps.append("- **Kiểm tra logs**: Tìm kiếm dấu hiệu bị khai thác (suspicious activities, error patterns)")
    steps.append("- **Network segmentation**: Giới hạn truy cập từ bên ngoài nếu chưa có")

    # Bước 3: Dựa vào loại lỗ hổng từ description
    desc_lower = description.lower()
    if "rce" in desc_lower or "remote code execution" in desc_lower:
        steps.append("- **RCE Detection**: Scan hệ thống bằng antivirus/EDR để phát hiện backdoor, shell scripts")
        steps.append("- **Firewall rules**: Kiểm tra và tightening inbound connections từ internet")
    elif "sql" in desc_lower:
        steps.append("- **SQL Injection mitigation**: Review và sanitize tất cả SQL queries, dùng parameterized statements")
        steps.append("- **Database audit**: Kiểm tra access logs của database, xóa suspicious accounts")
    elif "auth" in desc_lower or "bypass" in desc_lower:
        steps.append("- **Credential reset**: Reset tất cả passwords, invalidate sessions nếu cần")
        steps.append("- **MFA enforcement**: Enable Multi-Factor Authentication nếu chưa có")
    elif "path traversal" in desc_lower or "directory traversal" in desc_lower:
        steps.append("- **File access audit**: Kiểm tra web server logs cho directory traversal attempts")
        steps.append("- **Access control**: Đảm bảo proper file permissions và không expose sensitive directories")
    elif "xss" in desc_lower or "cross-site" in desc_lower:
        steps.append("- **Input validation**: Implement proper input sanitization và output encoding")
        steps.append("- **CSP headers**: Thiết lập Content Security Policy headers")

    return steps


def _markdown_to_html(markdown_text: str, title: str = "Report") -> str:
    """Convert Markdown sang HTML với dark security theme, không dùng thư viện ngoài."""
    import re

    html_lines = [
        '<!DOCTYPE html>',
        '<html lang="vi">',
        '<head>',
        '  <meta charset="UTF-8">',
        f'  <title>{title}</title>',
        '  <style>',
        '    body { background: #1a1a2e; color: #e0e0e0; font-family: "Courier New", monospace; margin: 20px; }',
        '    .container { max-width: 1000px; margin: 0 auto; }',
        '    h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }',
        '    h2 { color: #00d4ff; margin-top: 30px; }',
        '    h3 { color: #00a8cc; }',
        '    table { border-collapse: collapse; width: 100%; margin: 15px 0; }',
        '    th { background: #16213e; color: #00d4ff; padding: 10px; text-align: left; border: 1px solid #0f3460; }',
        '    td { padding: 8px; border: 1px solid #0f3460; }',
        '    tr:nth-child(even) { background: #0f3460; }',
        '    tr:hover { background: #1a4d6d; }',
        '    .critical { color: #ff4444; font-weight: bold; }',
        '    .high { color: #ff8800; font-weight: bold; }',
        '    .medium { color: #ffcc00; }',
        '    .low { color: #00cc00; }',
        '    code { background: #0f3460; padding: 2px 6px; border-radius: 3px; color: #00d4ff; }',
        '    pre { background: #0f3460; padding: 10px; border-radius: 5px; overflow-x: auto; }',
        '    a { color: #00d4ff; text-decoration: none; }',
        '    a:hover { text-decoration: underline; }',
        '    hr { border: none; border-top: 1px solid #0f3460; }',
        '    footer { margin-top: 40px; text-align: center; color: #666; border-top: 1px solid #0f3460; padding-top: 10px; }',
        '  </style>',
        '</head>',
        '<body>',
        '<div class="container">',
    ]

    lines = markdown_text.split('\n')
    in_table = False
    in_table_header = False
    in_code_block = False
    is_header_row = False
    in_list = False

    for i, line in enumerate(lines):
        line = line.rstrip()

        # Code blocks
        if line.startswith('```'):
            if in_code_block:
                html_lines.append('</pre>')
                in_code_block = False
            else:
                html_lines.append('<pre>')
                in_code_block = True
            continue

        if in_code_block:
            html_lines.append(line)
            continue

        # Tables
        if line.startswith('|'):
            if in_list:
                html_lines.append('</ul>')
                in_list = False
            if not in_table:
                html_lines.append('<table>')
                in_table = True
                is_header_row = True

            cells = [c.strip() for c in line.split('|')[1:-1]]

            if all(c.replace('-', '').replace(':', '') == '' for c in cells):
                html_lines.append('</thead>')
                html_lines.append('<tbody>')
                in_table_header = True
            else:
                if is_header_row and not in_table_header:
                    html_lines.append('<thead>')
                    row_html = '<tr>'
                    for cell in cells:
                        row_html += f'<th>{cell}</th>'
                    row_html += '</tr>'
                    html_lines.append(row_html)
                    is_header_row = False
                else:
                    row_html = '<tr>'
                    for cell in cells:
                        if cell.upper() == 'CRITICAL':
                            row_html += '<td class="critical">CRITICAL</td>'
                        elif cell.upper() == 'HIGH':
                            row_html += '<td class="high">HIGH</td>'
                        elif cell.upper() == 'MEDIUM':
                            row_html += '<td class="medium">MEDIUM</td>'
                        elif cell.upper() == 'LOW':
                            row_html += '<td class="low">LOW</td>'
                        else:
                            row_html += f'<td>{cell}</td>'
                    row_html += '</tr>'
                    html_lines.append(row_html)
        else:
            if in_table:
                html_lines.append('</tbody>')
                html_lines.append('</table>')
                in_table = False

            # Headers
            if line.startswith('#### '):
                if in_list:
                    html_lines.append('</ul>')
                    in_list = False
                html_lines.append(f'<h4>{line[5:].strip()}</h4>')
            elif line.startswith('### '):
                if in_list:
                    html_lines.append('</ul>')
                    in_list = False
                html_lines.append(f'<h3>{line[4:].strip()}</h3>')
            elif line.startswith('## '):
                if in_list:
                    html_lines.append('</ul>')
                    in_list = False
                html_lines.append(f'<h2>{line[3:].strip()}</h2>')
            elif line.startswith('# '):
                if in_list:
                    html_lines.append('</ul>')
                    in_list = False
                html_lines.append(f'<h1>{line[2:].strip()}</h1>')
            # Lists
            elif line.strip().startswith('- ') or line.strip().startswith('* '):
                list_text = line.strip()[2:].strip()

                if not in_list:
                    html_lines.append('<ul>')
                    in_list = True

                # Format list item text
                text = list_text
                text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
                text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
                text = re.sub(r'\[(.+?)\]\((.+?)\)', r'<a href="\2">\1</a>', text)
                html_lines.append(f'<li>{text}</li>')
            # Horizontal rule
            elif line.strip() in ('---', '***', '___'):
                if in_list:
                    html_lines.append('</ul>')
                    in_list = False
                html_lines.append('<hr/>')
            # Empty lines
            elif not line.strip():
                # Don't close list on empty line - just continue
                pass
            # Regular text
            else:
                if in_list:
                    html_lines.append('</ul>')
                    in_list = False
                if line.strip():
                    text = line
                    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
                    text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
                    text = re.sub(r'\[(.+?)\]\((.+?)\)', r'<a href="\2">\1</a>', text)
                    if text.strip():
                        html_lines.append(f'<p>{text}</p>')

    # Close any open tags
    if in_list:
        html_lines.append('</ul>')
    if in_table:
        if in_table_header:
            html_lines.append('</tbody>')
        html_lines.append('</table>')
    if in_code_block:
        html_lines.append('</pre>')

    html_lines += [
        '</div>',
        '<footer>',
        '<p>CyberSec Multi-Agent System | Ollama Local Edition</p>',
        '</footer>',
        '</body>',
        '</html>',
    ]

    return '\n'.join(html_lines)


def list_reports() -> dict:
    """Liệt kê tất cả báo cáo đã tạo trong session."""
    return {
        "context": [
            {
                "report_id": rid,
                "type":      r["type"],
                "title":     r["title"],
                "file":      r["file"],
                "created":   r["created"],
            }
            for rid, r in REPORTS_STORE.items()
        ],
        "source": "ReportStore",
        "total":  len(REPORTS_STORE),
    }
