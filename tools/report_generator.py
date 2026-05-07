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
) -> dict:
    """
    Tạo báo cáo bảo mật và lưu ra file .md.

    report_type: vulnerability_assessment | executive_summary | patch_advisory |
                 threat_intel | incident_report
    """
    print(f"  [Report] Tạo: type='{report_type}', title='{title}'")

    ts    = datetime.now()
    rid   = ts.strftime("%Y%m%d_%H%M%S")
    fname = f"{report_type}_{rid}.md"
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
