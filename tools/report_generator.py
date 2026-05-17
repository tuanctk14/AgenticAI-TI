"""
tools/report_generator.py - Tạo và lưu báo cáo bảo mật (MD / TXT)
"""
import os
import json
import re
from datetime import datetime
from config import REPORTS_DIR
from tools.doc_store import load_knowledge_base
from tools.risk_scorer import RiskScorer
from tools.cve_relationship_integrator import format_relationships_for_report
from tools.kb_populator import KBPopulator

# Lưu trong memory để tra cứu trong session
REPORTS_STORE: dict[str, dict] = {}


def _extract_ioc_type_from_pattern(pattern: str, ioc_type: str = None) -> str:
    """
    Extract IOC type from STIX pattern or return provided type.
    Parses patterns like:
    - [file:hashes.'SHA-256' = 'xxx'] -> SHA256
    - [file:hashes.'MD5' = 'xxx'] -> MD5
    - [file:hashes.'SHA-1' = 'xxx'] -> SHA1
    - [network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = 'xxx'] -> IPv4
    - [ipv4-addr:value = 'xxx'] -> IPv4
    - [ipv6-addr:value = 'xxx'] -> IPv6
    - [domain-name:value = 'xxx'] -> Domain
    - [email-addr:value = 'xxx'] -> Email
    - [url:value = 'xxx'] -> URL
    """
    if not isinstance(pattern, str):
        return ioc_type or "INDICATOR"

    # If it's a Yara rule, return as-is
    if pattern.strip().startswith("rule "):
        return "YARA"

    # If already provided a type from KB, use it
    if ioc_type and ioc_type.upper() not in ["INDICATOR", "UNKNOWN"]:
        return ioc_type.upper()

    # Parse STIX pattern
    pattern_upper = pattern.upper()

    if "SHA-256" in pattern_upper or "SHA256" in pattern_upper:
        return "SHA256"
    elif "SHA-1" in pattern_upper or "SHA1" in pattern_upper:
        return "SHA1"
    elif "MD5" in pattern_upper:
        return "MD5"
    elif "IPV4-ADDR" in pattern_upper:
        return "IPv4"
    elif "IPV6-ADDR" in pattern_upper:
        return "IPv6"
    elif "DOMAIN-NAME" in pattern_upper:
        return "Domain"
    elif "EMAIL-ADDR" in pattern_upper or "EMAIL" in pattern_upper:
        return "Email"
    elif "URL" in pattern_upper:
        return "URL"
    elif "FILE" in pattern_upper:
        return "File"

    return ioc_type.upper() if ioc_type else "INDICATOR"


def generate_report(
    report_type: str = "vulnerability_assessment",
    title:       str = "",
    content:     str = "",
    state:       dict | None = None,
    export_format: str = "html",
    start_date:  str = "",
    end_date:    str = "",
) -> dict:
    """
    Tạo báo cáo bảo mật và lưu ra file.

    report_type: vulnerability_assessment | executive_summary | patch_advisory |
                 threat_intel | incident_report
    export_format: html (.html) - chỉ hỗ trợ HTML format
    start_date: ISO format "YYYY-MM-DDTHH:MM:SS.000" (optional, triggers pipeline)
    end_date: ISO format "YYYY-MM-DDTHH:MM:SS.000" (optional, triggers pipeline)
    """
    # Force HTML format
    export_format = "html"
    print(f"  [Report] Tạo: type='{report_type}', title='{title}', format='html'")

    ts    = datetime.now()
    rid   = ts.strftime("%Y%m%d_%H%M%S")
    ext   = ".html"
    fname = f"{report_type}_{rid}{ext}"
    fpath = os.path.join(REPORTS_DIR, fname)

    # ── Nếu có date range, chạy pipeline để collect data ──────────────────────
    # Check if state is empty (no collected data yet) or not provided
    has_collected_data = state and state.get("collected_cves")
    if start_date and end_date and not has_collected_data:
        from main import _run_report_pipeline

        # Ensure end_date has 23:59:59 for full day coverage
        if end_date and "T00:00:00" in end_date:
            end_date = end_date.replace("T00:00:00.000", "T23:59:59.000")

        days_back = 7  # Default fallback
        state = _run_report_pipeline(start_date, end_date, days_back)

        # Update title to show date range
        if not title:
            start_fmt = f"{start_date[8:10]}-{start_date[5:7]}-{start_date[:4]}"
            end_fmt = f"{end_date[8:10]}-{end_date[5:7]}-{end_date[:4]}"
            title = f"Security Report - {start_fmt} đến {end_fmt}"

    # ── Xây dựng nội dung báo cáo từ state nếu có ──────────────────────
    if state and not content:
        content = _build_report_from_state(report_type, title, state, ts, start_date, end_date)

    if not content:
        content = f"# {title or report_type.replace('_', ' ').title()}\n\nBáo cáo trống."

    # Đảm bảo có header
    if not content.startswith("#"):
        content = f"# {title or report_type.upper()}\n\n{content}"

    # Thêm footer
    footer = (
        f"\n\n---\n"
        f"Tạo bởi ATI-AgenticThreatIntelligence System | {ts.strftime('%d/%m/%Y %H:%M:%S')}\n"
        f"Model: Ollama Local | Report ID: {rid}\n"
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

    print(f"  [Report]  Lưu tại: {fpath}")
    return {
        "context":   {"report_id": rid, "file": fpath, "type": report_type},
        "source":    "ReportGenerator",
        "report_id": rid,
        "file_path": fpath,
    }


def _format_iocs_for_report(cve_id: str) -> str:
    """Format IOCs linked to CVE for report section."""
    try:
        populator = KBPopulator()
        iocs = populator.get_iocs_by_cve(cve_id)

        if not iocs:
            return ""

        lines = ["\n### Related IOCs and Infrastructure"]
        ioc_by_type = {}
        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            if ioc_type not in ioc_by_type:
                ioc_by_type[ioc_type] = []
            ioc_by_type[ioc_type].append(ioc)

        for ioc_type in sorted(ioc_by_type.keys()):
            type_label = ioc_type.upper()
            ioc_list = ioc_by_type[ioc_type]
            lines.append(f"\n**{type_label}:**")
            for ioc in ioc_list[:5]:  # Limit to 5 per type
                value = ioc.get("value", "Unknown")
                confidence = ioc.get("confidence", 0)
                rels = ioc.get("relationships", [])
                rel_sources = set(r.get("source") for r in rels if r.get("source"))
                rel_str = ", ".join(sorted(rel_sources)) if rel_sources else "unknown"
                lines.append(f"- `{value}` (confidence: {confidence}%, from: {rel_str})")

            if len(ioc_list) > 5:
                lines.append(f"- ... and {len(ioc_list) - 5} more {ioc_type}s")

        return "\n".join(lines)

    except Exception as e:
        return f""


def _build_report_from_state(
    report_type: str, title: str, state: dict, ts: datetime, start_date: str = "", end_date: str = ""
) -> str:
    """Tự động tạo nội dung báo cáo từ state của hệ thống."""
    lines = []
    t = title or report_type.replace("_", " ").title()

    # Format report type name
    report_type_display = "threat_intelligence_report" if report_type == "executive_summary" else report_type

    lines += [
        f"# {t}",
        f"\n**Ngày tạo:** {ts.strftime('%d/%m/%Y %H:%M')}",
        f"**Loại báo cáo:** {report_type_display}",
        f"**Hệ thống:** ATI-AgenticThreatIntelligence (Ollama Local)",
        "\n---",
    ]

    # Dashboard cho executive_summary
    if report_type == "executive_summary":
        cves = state.get("collected_cves") or []
        indicators = state.get("collected_indicators") or []
        devices = state.get("matched_devices") or []
        device_cve_map = state.get("device_cve_map") or {}

        # If no indicators collected AND no date range, load from KB
        # (date range means pipeline already did proper filtering)
        if not indicators and not start_date and not end_date:
            kb = load_knowledge_base("all")
            kb_iocs = kb.get("context", {}).get("iocs", [])
            kb_malwares = kb.get("context", {}).get("malwares", [])

            for ioc in kb_iocs:
                indicators.append({
                    "entity_type": "Indicator",
                    "id": ioc.get("id"),
                    "name": f"{ioc.get('type', 'unknown').upper()}: {ioc.get('value', '')}",
                    "type": ioc.get("type"),
                    "value": ioc.get("value"),
                    "threat_actor": ioc.get("threat_actor", ""),
                    "source": "KB",
                })
            for mal in kb_malwares:
                indicators.append({
                    "entity_type": "Malware",
                    "id": mal.get("id"),
                    "name": mal.get("malware_family", ""),
                    "type": mal.get("type"),
                    "threat_actor": mal.get("threat_actor", ""),
                    "source": "KB",
                })

        # If no CVEs collected AND no date range, load from KB
        if not cves and not start_date and not end_date:
            kb = load_knowledge_base("cves")
            cves = kb.get("context", {}).get("cves", [])

        # Count IOC/Malware
        ioc_count = len([i for i in indicators if i.get("entity_type") == "Indicator"])
        malware_count = len([i for i in indicators if i.get("entity_type") == "Malware"])
        attack_pattern_count = len([i for i in indicators if i.get("entity_type") == "Attack Pattern"])

        # Tính Risk Score (Enhanced with enrichment data)
        risk_score = 0
        if cves:
            scores = []
            for c in cves:
                # First try enrichment risk score (từ EPSS + KEV + exploit intel)
                enrichment = c.get("enrichment")
                if enrichment and enrichment.get("unified_risk_score"):
                    scores.append(enrichment.get("unified_risk_score"))
                else:
                    # Fallback to CVSS-based scoring
                    score = c.get("cvss_score", 0) or 0
                    if score and score != "N/A":
                        try:
                            cvss_val = float(score)
                            # CVSS to 0-100 scale
                            scores.append(min(100, cvss_val * 10))
                        except (ValueError, TypeError):
                            pass

            if scores:
                avg_score = sum(scores) / len(scores)
                risk_score = min(100, int(avg_score))
            else:
                risk_score = 0

        risk_level = (
            "CRITICAL (9-10)" if risk_score >= 90 else
            "HIGH (7-9)" if risk_score >= 70 else
            "MEDIUM (4-7)" if risk_score >= 40 else
            "LOW (0-4)"
        )

        unique_devices = len({d['device_id'] for d in devices}) if devices else len(device_cve_map)

        lines += [
            "\n## DASHBOARD",
            f"\n| Loại | Số lượng |",
            f"|--------|-------|",
            f"| CVEs | {len(cves)} |",
            f"| IOC (Indicators) | {ioc_count} |",
            f"| Malware Families | {malware_count} |",
            f"| Attack Patterns | {attack_pattern_count} |",
            f"| Affected Devices | {unique_devices} |",
            f"| Critical Matches | {len([d for d in devices if d.get('risk_level') == 'CRITICAL'])} |",
            "",
        ]


    # CVEs - hiển thị chỉ CRITICAL và HIGH (with enrichment data)
    cves: list = state.get("collected_cves") or []
    if cves:
        critical_high_cves = [c for c in cves if c.get("severity", "").upper() in ("CRITICAL", "HIGH")]
        if critical_high_cves:
            lines += [f"\n## DANH SÁCH CVE ({len(critical_high_cves)} CVEs CRITICAL/HIGH)", ""]
            lines.append("| STT | CVE ID | CVSS | EPSS | KEV | Exploit | Mức Độ |")
            lines.append("|---|--------|------|------|-----|---------|--------|")
            for i, c in enumerate(critical_high_cves, 1):
                cve_id = c.get('id','N/A')
                cvss = c.get('cvss_score','N/A')
                severity = c.get('severity','N/A')

                # Get enrichment data
                enrichment = c.get("enrichment", {})
                epss = ""
                kev = ""
                exploit = ""

                if enrichment:
                    # EPSS
                    epss_score = enrichment.get("epss_score")
                    if epss_score:
                        epss = f"{epss_score:.3f}"
                    else:
                        epss = "-"

                    # KEV
                    if enrichment.get("kev_listed"):
                        kev = "✓"
                    else:
                        kev = "-"

                    # Exploit (from Vulners)
                    exploit_indicators = []
                    exploit_count = enrichment.get("exploit_count", 0)
                    if enrichment.get("public_exploit"):
                        if exploit_count > 0:
                            exploit_indicators.append(f"{exploit_count}x")
                        else:
                            exploit_indicators.append("POC")
                    if enrichment.get("metasploit"):
                        exploit_indicators.append("MSF")
                    exploit = ",".join(exploit_indicators) if exploit_indicators else "-"
                else:
                    epss = "-"
                    kev = "-"
                    exploit = "-"

                lines.append(
                    f"| {i} | {cve_id} | {cvss} | {epss} | {kev} | {exploit} | {severity} |"
                )
            lines.append("")

        # Thêm chi tiết CVEs CRITICAL (with enrichment context)
        critical_only = [c for c in cves if c.get("severity", "").upper() == "CRITICAL"]
        if critical_only:
            lines += ["\n### CVE Nghiêm Trọng Cần Ưu Tiên", ""]
            for c in critical_only[:5]:
                cve_id = c.get("id", "N/A")
                cvss = c.get("cvss_score", "N/A")
                severity = c.get("severity", "N/A")
                desc = c.get("description", "")

                # Get enrichment context
                enrichment = c.get("enrichment", {})

                # Cắt ngắn description nhưng đảm bảo không bị cắt giữa câu
                if desc and desc != "N/A":
                    # Chỉ lấy phần trước newline (loại bỏ "This issue affects..." part)
                    desc = desc.split('\n')[0]
                    # Cắt để tối đa 150 ký tự, tại whitespace cuối cùng
                    if len(desc) > 150:
                        desc = desc[:150].rsplit(" ", 1)[0]
                else:
                    desc = ""

                # Build enrichment context line
                context_items = []
                if enrichment:
                    # EPSS threat level
                    epss_score = enrichment.get("epss_score")
                    if epss_score:
                        if epss_score > 0.9:
                            context_items.append("🔥 Critical EPSS")
                        elif epss_score > 0.7:
                            context_items.append("⚠ High EPSS")

                    # Exploitation indicators
                    if enrichment.get("kev_listed"):
                        context_items.append("🎯 KEV Listed (Active exploitation)")
                    exploit_count = enrichment.get("exploit_count", 0)
                    if enrichment.get("public_exploit"):
                        if exploit_count > 0:
                            context_items.append(f"📌 {exploit_count} Vulners exploits available")
                        else:
                            context_items.append("📌 Public exploit available")
                    if enrichment.get("metasploit"):
                        context_items.append("📌 Metasploit module exists")

                context_str = " | ".join(context_items) if context_items else ""

                # Display with enrichment context
                if context_str:
                    lines.append(f"- **{cve_id}** (CVSS: {cvss})")
                    lines.append(f"  - **Nguy hiểm**: {context_str}")
                    if desc:
                        lines.append(f"  - **Mô tả**: {desc}...")
                else:
                    if desc:
                        lines.append(f"- **{cve_id}** (CVSS: {cvss}, {severity}): {desc}...")
                    else:
                        lines.append(f"- **{cve_id}** (CVSS: {cvss}, {severity})")

                # Add relationship enrichment (malware/campaigns/actors) if available
                relationships = c.get("relationships")
                if relationships and relationships.get("total_relationships", 0) > 0:
                    relationship_markdown = format_relationships_for_report(c)
                    if relationship_markdown:
                        rel_lines = relationship_markdown.split("\n")
                        for rel_line in rel_lines:
                            if rel_line.strip():
                                lines.append(f"  {rel_line}")

                # Add IOC/Infrastructure section if available
                cve_id = c.get("id", "")
                if cve_id:
                    ioc_section = _format_iocs_for_report(cve_id)
                    if ioc_section:
                        ioc_lines = ioc_section.split("\n")
                        for ioc_line in ioc_lines:
                            if ioc_line.strip():
                                lines.append(f"  {ioc_line}")

            lines.append("")

    # IOC / Malware / Threat Intelligence
    indicators: list = state.get("collected_indicators") or []

    # Only load KB fallback if no date range was specified
    if not indicators and not start_date and not end_date:
        kb = load_knowledge_base("all")
        kb_iocs = kb.get("context", {}).get("iocs", [])
        kb_malwares = kb.get("context", {}).get("malwares", [])

        for ioc in kb_iocs:
            indicators.append({
                "entity_type": "Indicator",
                "id": ioc.get("id"),
                "name": f"{ioc.get('type', 'unknown').upper()}: {ioc.get('value', '')}",
                "type": ioc.get("type", "indicator"),
                "value": ioc.get("value", ""),
                "description": ioc.get("description", ""),
                "cvss_score": ioc.get("cvss_score", "N/A"),
                "threat_actor": ioc.get("threat_actor", ""),
                "score": ioc.get("cvss_score", 0) / 10 if ioc.get("cvss_score") else 0,
                "confidence": 80,
                "source": "KB",
            })
        for mal in kb_malwares:
            indicators.append({
                "entity_type": "Malware",
                "id": mal.get("id"),
                "name": mal.get("malware_family", ""),
                "type": mal.get("type", ""),
                "malware_types": [mal.get("type", "")],
                "description": mal.get("description", ""),
                "cvss_score": mal.get("cvss_score", "N/A"),
                "threat_actor": mal.get("threat_actor", ""),
                "aliases": [mal.get("id", "")],
                "source": "KB",
            })

    if indicators:
        lines += [f"\n## THREAT INTELLIGENCE ({len(indicators)} Kết Quả)", ""]

        # Chia theo entity type
        ioc_list = [i for i in indicators if i.get("entity_type") == "Indicator"]
        malware_list = [i for i in indicators if i.get("entity_type") == "Malware"]
        pattern_list = [i for i in indicators if i.get("entity_type") == "Attack Pattern"]

        # Indicators of Compromise
        if ioc_list:
            lines += ["\n### Indicators of Compromise (IOC)", ""]
            lines.append("| STT | Loại | Giá Trị/Pattern | CVSS | Threat Actor |")
            lines.append("|---|------|-----------------|------|--------------|")
            for i, ioc in enumerate(ioc_list[:10], 1):
                # Get actual type - use smart detection from pattern if from OpenCTI
                ioc_type_raw = ioc.get("type")
                pattern = ioc.get("pattern", "")

                # Use smart detection if KB doesn't have type info
                # Check: if type is None, empty, or "indicator"
                type_str = str(ioc_type_raw).upper() if ioc_type_raw else ""
                if (not ioc_type_raw or
                    type_str == "NONE" or
                    type_str == "INDICATOR" or
                    type_str == "UNKNOWN"):
                    # Parse from pattern
                    ioc_type = _extract_ioc_type_from_pattern(pattern, ioc_type_raw)
                else:
                    ioc_type = type_str.replace("\n", " ")[:20]

                # Get actual value/pattern - prefer value over pattern
                value = ioc.get("value", "").strip() if ioc.get("value") else ""

                if not value:
                    # Fallback to pattern but clean it (remove newlines)
                    if isinstance(pattern, str):
                        # Remove newlines from pattern
                        pattern_clean = pattern.replace("\n", " ").replace("\r", "")
                        # If still too long or looks like STIX/Yara, use name instead
                        if (len(pattern_clean) > 50 or
                            pattern_clean.startswith("[") or
                            pattern_clean.startswith("rule ")):
                            value = ioc.get("name", "N/A")[:50]
                        else:
                            value = pattern_clean[:50]
                    else:
                        value = "N/A"

                # Final truncate
                if len(str(value)) > 50:
                    value = str(value)[:47] + "..."

                # Ensure no newlines in final value
                value = str(value).replace("\n", " ").replace("\r", "")

                cvss = str(ioc.get("cvss_score", "N/A")).replace("\n", " ")
                threat_actor = str(ioc.get("threat_actor", "-")).replace("\n", " ")
                if threat_actor and threat_actor != "-":
                    threat_actor = threat_actor[:20]

                lines.append(f"| {i} | {ioc_type} | {value} | {cvss} | {threat_actor} |")
            lines.append("")

        # Malware Families
        if malware_list:
            lines += ["\n### Malware Families", ""]
            lines.append("| STT | Tên Malware | Loại | CVSS | Threat Actor |")
            lines.append("|---|-------------|------|------|--------------|")
            for i, mal in enumerate(malware_list[:10], 1):
                name = str(mal.get("name", "N/A")).replace("\n", " ")[:50]
                mal_type_val = mal.get("type")
                if not mal_type_val:
                    mal_type_val = ", ".join(mal.get("malware_types", ["unknown"]))
                mal_type = str(mal_type_val)[:20].replace("\n", " ")
                cvss = str(mal.get("cvss_score", "N/A")).replace("\n", " ")
                threat_actor = str(mal.get("threat_actor", "-")).replace("\n", " ")
                if threat_actor and threat_actor != "-":
                    threat_actor = threat_actor[:20]
                lines.append(f"| {i} | {name} | {mal_type} | {cvss} | {threat_actor} |")
            lines.append("")

        # Attack Patterns
        if pattern_list:
            lines += ["\n### Attack Patterns (MITRE ATT&CK)", ""]
            lines.append("| STT | Technique | Tên | Mô Tả |")
            lines.append("|---|-----------|-----|-------|")
            for i, pat in enumerate(pattern_list[:10], 1):
                name = str(pat.get("name", "N/A")).replace("\n", " ")[:50]
                pattern = pat.get("pattern", "N/A")
                # Clean pattern - remove newlines and multi-line content
                if isinstance(pattern, str):
                    if "\n" in pattern or len(pattern) > 40:
                        # Use name for Yara/long patterns
                        pattern = name[:30] if len(name) > 0 else "[YARA Rule]"
                    else:
                        pattern = pattern[:30]
                else:
                    pattern = str(pattern)[:30]
                pattern = pattern.replace("\n", " ").replace("\r", "")
                desc = str(pat.get("description", "N/A"))[:60].replace("\n", " ").replace("\r", "")
                lines.append(f"| {i} | {pattern} | {name} | {desc}... |")
            lines.append("")

    # Matched devices with remediation
    devices: list = state.get("matched_devices") or []
    if devices:
        unique_device_ids = {d['device_id'] for d in devices}
        lines += [f"\n## THIẾT BỊ ẢNH HƯỞNG ({len(unique_device_ids)} Thiết Bị)", ""]

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

        # Calculate risk level for each device using analyst-grade risk scoring
        device_risk = {}
        device_risk_scores = {}
        for dev_id, dev_info in device_map.items():
            # Determine asset context
            is_dc = dev_info.get("is_dc", False)
            is_production = dev_info.get("is_production", True)
            internet_exposed = dev_info.get("internet_exposed", False)

            # Calculate risk score based on CVEs
            risk_score, risk_level = RiskScorer.calculate_device_risk_score(
                cves=dev_info["cves"],
                device_criticality=dev_info.get("criticality", "MEDIUM"),
                internet_exposed=internet_exposed,
                is_dc=is_dc,
                is_production=is_production,
            )
            device_risk[dev_id] = risk_level
            device_risk_scores[dev_id] = risk_score

        # Sort devices by risk level (CRITICAL > HIGH > MEDIUM > LOW)
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_devices = sorted(device_map.items(),
                               key=lambda x: risk_order.get(device_risk[x[0]], 4))

        # Bảng tóm tắt thiết bị (hiển thị đầy đủ, không giới hạn)
        lines.append("| STT | Thiết Bị | IP | OS | CVE Count | Risk Score | Mức Độ |")
        lines.append("|---|----------|----|----|-----------|------------|--------|")
        for idx, (dev_id, dev_info) in enumerate(sorted_devices, 1):
            cve_count = len(dev_info["cves"])
            risk_level = device_risk[dev_id]
            risk_score = device_risk_scores[dev_id]
            lines.append(
                f"| {idx} | {dev_info['hostname']} | {dev_info['ip']} | {dev_info['os']} "
                f"| {cve_count} | {risk_score:.1f} | {risk_level} |"
            )
        lines.append("")

        # Chi tiết từng thiết bị
        lines += ["\n### Chi Tiết Khắc Phục Từng Thiết Bị", ""]

        # Render each device in sorted order
        for idx, (dev_id, dev_info) in enumerate(sorted_devices):
            risk_level = device_risk[dev_id]
            risk_score = device_risk_scores[dev_id]

            # Get risk level color
            risk_color = RiskScorer.get_risk_color(risk_level)
            timeline = RiskScorer.get_remediation_timeline(risk_level)

            # Add separator line between devices (except first one)
            if idx > 0:
                lines.append("\n---")

            # Device name and IP with colors, Risk Score with color beside
            lines.append(f"\n#### <span style='color: #66ddff'><b>{dev_info['hostname']}</b></span> | <span style='color: #66ddff'>{dev_info['ip']}</span> | <span style='color: {risk_color}'><b>{risk_level} ({risk_score:.1f})</b></span>")
            lines.append(f"- **OS**: {dev_info['os']}")
            lines.append("")

            # Danh sách CVEs ảnh hưởng (với enrichment data)
            lines.append("**CVEs Ảnh Hưởng:**")
            for cve_match in dev_info["cves"]:
                cve_id = cve_match["cve_id"]
                cvss = cve_match.get("cvss_score", "N/A")
                software = cve_match.get("affected_software", "N/A")

                # Get enrichment info từ cves_dict nếu có
                cve_full = cves_dict.get(cve_id, {})
                enrichment = cve_full.get("enrichment", {})

                # Build base info
                base_info = f"**{cve_id}** (CVSS: {cvss}"
                if software and software != "N/A":
                    base_info += f", Phần Mềm: {software}"
                base_info += ")"

                # Build enrichment details
                enrichment_details = []
                if enrichment:
                    # EPSS info
                    epss_score = enrichment.get("epss_score")
                    if epss_score:
                        enrichment_details.append(f"EPSS: {epss_score:.4f}")

                    # KEV info
                    if enrichment.get("kev_listed"):
                        enrichment_details.append("✓ KEV Listed")

                    # Exploit info (from Vulners)
                    exploit_count = enrichment.get("exploit_count", 0)
                    if enrichment.get("public_exploit"):
                        if exploit_count > 0:
                            enrichment_details.append(f"✓ {exploit_count} Exploits")
                        else:
                            enrichment_details.append("✓ Public Exploit")
                    if enrichment.get("metasploit"):
                        enrichment_details.append("✓ Metasploit")

                # Display CVE with consistent format
                if enrichment_details:
                    details_str = " | ".join(enrichment_details)
                    lines.append(f"- {base_info} | {details_str}")
                else:
                    lines.append(f"- {base_info}")

            lines.append("")

            # Add priority note based on calculated risk level
            lines.append(f"<span style='color: {risk_color}'><strong>Lưu ý {risk_level}</strong></span>: {timeline}")

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
        steps.append(" **Ưu tiên CRITICAL**: Xử lý ngay trong 24 giờ")
    elif cve_score >= 7.0:
        steps.append(" **Ưu tiên HIGH**: Xử lý trong 72 giờ")
    else:
        steps.append(" **Ưu tiên MEDIUM**: Lên lịch xử lý trong 2 tuần")

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
        '<p>ATI-AgenticThreatIntelligence System | Ollama Local Edition</p>',
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
