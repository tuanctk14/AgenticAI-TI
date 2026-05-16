"""
tools/nvd_client.py - Lấy CVE từ NVD API (với fallback mock)
"""
import requests
import asyncio
from config import NVD_API_KEY

# Dữ liệu mock dự phòng (hiện tại không dùng - chỉ lấy từ API thực)
MOCK_CVES = []

# Enrichment orchestrator (lazy-loaded)
_enrichment_orchestrator = None

def _get_orchestrator():
    """Lazy-load enrichment orchestrator"""
    global _enrichment_orchestrator
    if _enrichment_orchestrator is None:
        from tools.enrichment.orchestrator import EnrichmentOrchestrator
        _enrichment_orchestrator = EnrichmentOrchestrator()
    return _enrichment_orchestrator


def fetch_cve_by_id(cve_id: str, enrich: bool = True) -> dict:
    """
    Tra cứu một CVE cụ thể từ NVD API.
    Fallback sang mock data nếu không có internet.

    Args:
        cve_id: CVE ID (e.g., "CVE-2021-44228")
        enrich: If True, fetch enriched data from EPSS/KEV/Vulners
    """
    print(f"  [NVD] Looking up: CVE={cve_id}")

    base_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers  = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params   = {"cveId": cve_id}

    try:
        resp = requests.get(base_url, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()

        if data.get("vulnerabilities"):
            item = data["vulnerabilities"][0]
            cve = item["cve"]
            desc = (cve.get("descriptions") or [{"value": "N/A"}])[0]["value"]
            metrics = cve.get("metrics", {})
            score = "N/A"
            sev = "UNKNOWN"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    m = metrics[key][0]
                    score = m["cvssData"]["baseScore"]
                    sev = m["cvssData"].get("baseSeverity", sev)
                    break
            # Extract CWE from weaknesses
            cwe_ids = []
            weaknesses = cve.get("weaknesses", [])
            for weakness in weaknesses:
                descriptions = weakness.get("description", [])
                for desc_obj in descriptions:
                    value = desc_obj.get("value", "")
                    if value.startswith("CWE-"):
                        cwe_id = value.replace("CWE-", "")
                        if cwe_id not in cwe_ids:
                            cwe_ids.append(cwe_id)

            result = [{
                "id": cve["id"],
                "description": desc,  # Keep full description for NLP extraction
                "cvss_score": score,
                "cvss_vector": None,  # Will be set below if available
                "severity": sev,
                "published": cve.get("published", "N/A")[:10],
                "references": [r["url"] for r in cve.get("references", [])[:5]],
                "configurations": cve.get("configurations", []),
                "cwe_ids": cwe_ids,
            }]

            # Extract CVSS vector string for more detailed vulnerability analysis
            if "cvssMetricV31" in metrics:
                result[0]["cvss_vector"] = metrics["cvssMetricV31"][0]["cvssData"].get("vectorString")
            elif "cvssMetricV30" in metrics:
                result[0]["cvss_vector"] = metrics["cvssMetricV30"][0]["cvssData"].get("vectorString")

            # Enrich with EPSS/KEV/Vulners if requested
            if enrich:
                try:
                    orchestrator = _get_orchestrator()
                    unified = asyncio.run(orchestrator.enrich_cve(cve_id))
                    # Add enrichment data to CVE dict (flat structure)
                    enrichment = {
                        "epss_score": unified.epss.score if unified.epss and unified.epss.available else None,
                        "epss_percentile": unified.epss.percentile if unified.epss and unified.epss.available else None,
                        "kev_listed": unified.kev.listed if unified.kev else False,
                        "kev_source": unified.kev.source if unified.kev else None,
                        "public_exploit": unified.vulncheck.public_exploit_available if unified.vulncheck else False,
                        "metasploit": unified.vulncheck.metasploit_available if unified.vulncheck else False,
                        "exploit_count": unified.vulncheck.exploit_count if unified.vulncheck else 0,
                        "exploit_sources": unified.vulncheck.exploit_sources if unified.vulncheck else [],
                        "unified_risk_score": unified.unified_risk_score,
                        "enrichment_summary": unified.enrichment_summary,
                    }
                    result[0]["enrichment"] = enrichment
                except Exception as e:
                    print(f"  [Enrichment] Error enriching {cve_id}: {e}")
                    result[0]["enrichment"] = None

            print(f"  [NVD]  Found {cve_id}")
            return {"context": result, "source": "NVD-LIVE", "total": 1}

    except Exception as e:
        print(f"  [NVD]  API Error: {e}")
        print(f"  [NVD] Could not find CVE {cve_id}")
        return {"context": [], "source": "NVD-ERROR", "total": 0}


def fetch_nvd_cves(keyword: str = "", severity: str = "HIGH", days_back: int = 30, start_date: str = None, end_date: str = None) -> dict:
    """
    Truy vấn NVD API để lấy tất cả CVE mới nhất (với phân trang đầy đủ).

    Args:
        keyword: Từ khóa tìm kiếm CVE
        severity: Mức độ nghiêm trọng tối thiểu (CRITICAL/HIGH/MEDIUM/LOW)
        days_back: Số ngày quay lại (nếu start_date/end_date không được cung cấp)
        start_date: ISO format "YYYY-MM-DDTHH:MM:SS.000" (nếu None, tính từ days_back)
        end_date: ISO format "YYYY-MM-DDTHH:MM:SS.000" (nếu None, dùng ngày hiện tại)
    """
    from datetime import datetime, timedelta, timezone
    import time

    # Tính toán date range nếu không được cung cấp
    if start_date is None:
        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=days_back)
        start_date = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_date = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

    print(f"  [NVD] Tìm kiếm: keyword='{keyword}', severity='{severity}', date_range='{start_date}' to '{end_date}'")

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers  = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    PAGE_SIZE = 2000
    all_cves = []
    start_index = 0
    total_results = None

    try:
        while True:
            params = {
                "resultsPerPage": PAGE_SIZE,
                "startIndex": start_index,
                "pubStartDate": start_date,
                "pubEndDate": end_date,
            }
            if keyword:
                params["keywordSearch"] = keyword
            if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                params["cvssV3Severity"] = severity

            resp = requests.get(base_url, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            if total_results is None:
                total_results = data.get("totalResults", 0)
                print(f"  [NVD] Tổng: {total_results} CVE, đang lấy tất cả trang...")

            for item in data.get("vulnerabilities", []):
                cve = item["cve"]
                desc = (cve.get("descriptions") or [{"value": "N/A"}])[0]["value"]
                metrics = cve.get("metrics", {})
                score = "N/A"
                sev   = "UNKNOWN"
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics:
                        m = metrics[key][0]
                        score = m["cvssData"]["baseScore"]
                        sev   = m["cvssData"].get("baseSeverity", sev)
                        break

                # Extract CWE from weaknesses
                cwe_ids = []
                weaknesses = cve.get("weaknesses", [])
                for weakness in weaknesses:
                    descriptions = weakness.get("description", [])
                    for desc_obj in descriptions:
                        value = desc_obj.get("value", "")
                        if value.startswith("CWE-"):
                            cwe_id = value.replace("CWE-", "")
                            if cwe_id not in cwe_ids:
                                cwe_ids.append(cwe_id)

                cve_entry = {
                    "id":          cve["id"],
                    "description": desc,  # Keep full description for NLP extraction
                    "cvss_score":  score,
                    "cvss_vector": None,  # Will be set below if available
                    "severity":    sev,
                    "published":   cve.get("published", "N/A")[:10],
                    "references":  [r["url"] for r in cve.get("references", [])[:5]],
                    "configurations": cve.get("configurations", []),
                    "cwe_ids":     cwe_ids,
                }

                # Extract CVSS vector string
                if "cvssMetricV31" in metrics:
                    cve_entry["cvss_vector"] = metrics["cvssMetricV31"][0]["cvssData"].get("vectorString")
                elif "cvssMetricV30" in metrics:
                    cve_entry["cvss_vector"] = metrics["cvssMetricV30"][0]["cvssData"].get("vectorString")

                all_cves.append(cve_entry)

            start_index += PAGE_SIZE
            fetched = len(all_cves)

            if start_index >= total_results:
                break

            print(f"  [NVD] Đã lấy {fetched}/{total_results}...")
            time.sleep(0.6)

        print(f"  [NVD]  Lấy được {len(all_cves)} CVE từ NVD API (tổng: {total_results})")

        # Enrich CVEs with EPSS/KEV/Vulners data for reports
        if all_cves:
            print(f"  [Enrichment] Enriching {len(all_cves)} CVEs with threat intelligence (Vulners)...")
            from tools.enrichment.orchestrator import EnrichmentOrchestrator

            orchestrator = EnrichmentOrchestrator()
            enriched_cves = []

            for i, cve in enumerate(all_cves, 1):
                cve_id = cve.get("id", "")
                if cve_id:
                    try:
                        unified = asyncio.run(orchestrator.enrich_cve(cve_id))
                        # Add enrichment to CVE dict (flat structure for Vulners)
                        cve["enrichment"] = {
                            "epss_score": unified.epss.score if unified.epss and unified.epss.available else None,
                            "epss_percentile": unified.epss.percentile if unified.epss and unified.epss.available else None,
                            "kev_listed": unified.kev.listed if unified.kev else False,
                            "kev_source": unified.kev.source if unified.kev else None,
                            "public_exploit": unified.vulncheck.public_exploit_available if unified.vulncheck else False,
                            "metasploit": unified.vulncheck.metasploit_available if unified.vulncheck else False,
                            "exploit_count": unified.vulncheck.exploit_count if unified.vulncheck else 0,
                            "exploit_sources": unified.vulncheck.exploit_sources if unified.vulncheck else [],
                            "unified_risk_score": unified.unified_risk_score,
                            "enrichment_summary": unified.enrichment_summary,
                        }
                        enriched_cves.append(cve)
                    except Exception as e:
                        # If enrichment fails, keep CVE without enrichment
                        cve["enrichment"] = None
                        enriched_cves.append(cve)

                if i % 10 == 0:
                    print(f"    Enriched {i}/{len(all_cves)} CVEs...")

            all_cves = enriched_cves
            print(f"  [Enrichment] Enrichment completed")

        return {"context": all_cves, "source": "NVD-LIVE", "total": total_results}

    except Exception as e:
        print(f"  [NVD]  Lỗi API: {e}")
        print(f"  [NVD] Không thể lấy dữ liệu CVE từ NVD API")
        return {"context": [], "source": "NVD-ERROR", "total": 0}
