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
    export_format: str = "markdown",
) -> dict:
    """
    Tạo báo cáo bảo mật và lưu ra file.

    report_type: vulnerability_assessment | executive_summary | patch_advisory |
                 threat_intel | incident_report
    export_format: markdown (.md) | html (.html)
    """
    print(f"  [Report] Tạo: type='{report_type}', title='{title}', format='{export_format}'")

    ts    = datetime.now()
    rid   = ts.strftime("%Y%m%d_%H%M%S")
    ext   = ".html" if export_format == "html" else ".md"
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

    # Convert sang HTML nếu cần
    if export_format == "html":
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
        devices = state.get("matched_devices") or []
        device_cve_map = state.get("device_cve_map") or {}

        # Tính Risk Score
        risk_score = 0
        if cves:
            avg_cvss = sum(float(c.get("cvss_score", 0) or 0) for c in cves) / len(cves)
            risk_score = min(100, int(avg_cvss * 10))

        risk_level = (
            "CRITICAL (9-10)" if risk_score >= 90 else
            "HIGH (7-9)" if risk_score >= 70 else
            "MEDIUM (4-7)" if risk_score >= 40 else
            "LOW (0-4)"
        )

        unique_devices = len({d['device_id'] for d in devices}) if devices else len(device_cve_map)

        lines += [
            "\n## EXECUTIVE DASHBOARD",
            f"\n| Metric | Value |",
            f"|--------|-------|",
            f"| Risk Score | {risk_score}/100 |",
            f"| Risk Level | **{risk_level}** |",
            f"| Total CVEs | {len(cves)} |",
            f"| Affected Devices | {unique_devices} |",
            f"| Critical Matches | {len([d for d in devices if d.get('risk_level') == 'CRITICAL'])} |",
            "",
        ]

        # Top Critical Actions by Device (not CVE)
        if device_cve_map:
            lines += [
                "\n## TOP CRITICAL DEVICES (Device-Level Risk)",
                "",
                "| Priority | Device | Hostname | CVE Count | Max Risk | Action |",
                "|----------|--------|----------|-----------|----------|--------|",
            ]

            # Sort devices by risk and CVE count
            sorted_devices = sorted(
                device_cve_map.items(),
                key=lambda x: (
                    len([r for r in x[1].get("risk_levels", {}).values() if r == "CRITICAL"]),
                    len(x[1].get("cve_ids", []))
                ),
                reverse=True
            )

            for i, (device_id, data) in enumerate(sorted_devices[:3], 1):
                risk_levels = data.get("risk_levels", {})
                max_risk = max(risk_levels.values()) if risk_levels else "LOW"
                hostname = data["device_info"].get("hostname", "N/A")
                cve_count = data.get("unique_cve_count", 0)

                lines.append(
                    f"| P{i} | {device_id} | {hostname} | {cve_count} "
                    f"| **{max_risk}** | Patch & Update |"
                )
            lines.append("")
        elif devices:
            critical_devices = [d for d in devices if d.get("criticality") == "CRITICAL"][:3]
            lines += [
                "\n## TOP 3 CRITICAL ACTIONS",
                "",
                "| Priority | Device | CVE | Action | Timeline |",
                "|----------|--------|-----|--------|----------|",
            ]
            for i, d in enumerate(critical_devices, 1):
                lines.append(
                    f"| P{i} | {d['hostname']} | {d['cve_id']} "
                    f"| Patch immediately | 24-48 hours |"
                )
            lines.append("")

    # CVEs
    cves: list = state.get("collected_cves") or []
    if cves and report_type != "executive_summary":
        lines += ["\n## CVE DA THU THAP", ""]
        lines.append("| CVE ID | CVSS | Severity | Published |")
        lines.append("|--------|------|----------|-----------|")
        for c in cves:
            lines.append(
                f"| {c.get('id','N/A')} | {c.get('cvss_score','N/A')} "
                f"| {c.get('severity','N/A')} | {c.get('published','N/A')} |"
            )
        lines.append(f"\nTong: {len(cves)} CVE")

    # Matched devices
    devices: list = state.get("matched_devices") or []
    if devices:
        lines += ["\n## THIET BI BI ANH HUONG", ""]
        lines.append("| Hostname | IP | Department | CVE | Risk | Software |")
        lines.append("|----------|----|------------|-----|------|---------|")
        for d in devices[:20]:  # Limit to 20 rows for readability
            lines.append(
                f"| {d['hostname']} | {d['ip']} | {d['department']} "
                f"| {d['cve_id']} | **{d['risk_level']}** | {d['affected_software']} |"
            )
        affected_count = len({d["device_id"] for d in devices})
        lines.append(f"\nTong: {len(devices)} matches tren {affected_count} thiet bi")

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
            if not in_table:
                html_lines.append('<table>')
                in_table = True
                is_header_row = True  # First row of table is header

            # Parse table row
            cells = [c.strip() for c in line.split('|')[1:-1]]

            # Check if separator row (dashes)
            if all(c.replace('-', '').replace(':', '') == '' for c in cells):
                # This is separator - start tbody after this
                html_lines.append('</thead>')
                html_lines.append('<tbody>')
                in_table_header = True
            else:
                # Regular data row
                if is_header_row and not in_table_header:
                    # First row before separator = header
                    html_lines.append('<thead>')
                    row_html = '<tr>'
                    for cell in cells:
                        row_html += f'<th>{cell}</th>'
                    row_html += '</tr>'
                    html_lines.append(row_html)
                    is_header_row = False
                else:
                    # Data row
                    row_html = '<tr>'
                    for cell in cells:
                        # Color-code severity levels
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
                html_lines.append(f'<h4>{line[5:].strip()}</h4>')
            elif line.startswith('### '):
                html_lines.append(f'<h3>{line[4:].strip()}</h3>')
            elif line.startswith('## '):
                html_lines.append(f'<h2>{line[3:].strip()}</h2>')
            elif line.startswith('# '):
                html_lines.append(f'<h1>{line[2:].strip()}</h1>')
            # Lists
            elif line.startswith('- '):
                if not html_lines[-1].startswith('<ul>'):
                    html_lines.append('<ul>')
                html_lines.append(f'<li>{line[2:].strip()}</li>')
            elif line.startswith('* '):
                if not html_lines[-1].startswith('<ul>'):
                    html_lines.append('<ul>')
                html_lines.append(f'<li>{line[2:].strip()}</li>')
            # Horizontal rule
            elif line.strip() in ('---', '***', '___'):
                html_lines.append('<hr/>')
            # Bold and italic
            elif line.strip():
                text = line
                # Bold **text**
                text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
                # Italic *text*
                text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
                # Inline code `text`
                text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
                # Links [text](url)
                text = re.sub(r'\[(.+?)\]\((.+?)\)', r'<a href="\2">\1</a>', text)

                if text.strip():
                    html_lines.append(f'<p>{text}</p>')

    # Close any open tags
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
