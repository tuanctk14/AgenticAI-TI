"""
tools/nvd_client.py - Lấy CVE từ NVD API (với mock fallback)
"""
import requests
from config import NVD_API_KEY

# ── Mock data dự phòng (hiện tại không dùng - chỉ lấy dữ liệu từ API thực) ──
MOCK_CVES = []


def fetch_cve_by_id(cve_id: str) -> dict:
    """
    Tra cứu một CVE cụ thể từ NVD API.
    Fallback sang mock data nếu không có internet.
    """
    print(f"  [NVD] Tra cuu: CVE={cve_id}")

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
            result = [{
                "id": cve["id"],
                "description": desc[:400],
                "cvss_score": score,
                "severity": sev,
                "published": cve.get("published", "N/A")[:10],
                "references": [r["url"] for r in cve.get("references", [])[:3]],
            }]
            print(f"  [NVD] ✅ Tim thay {cve_id}")
            return {"context": result, "source": "NVD-LIVE", "total": 1}

    except Exception as e:
        print(f"  [NVD] ❌ API lỗi: {e}")
        print(f"  [NVD] Không thể tìm CVE {cve_id}")
        return {"context": [], "source": "NVD-ERROR", "total": 0}


def fetch_nvd_cves(keyword: str = "", severity: str = "HIGH", days_back: int = 30, start_date: str = None, end_date: str = None) -> dict:
    """
    Truy vấn NVD API để lấy tất cả CVE mới nhất (full pagination).

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
                print(f"  [NVD] Tổng: {total_results} CVEs, fetching all pages...")

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
                all_cves.append({
                    "id":          cve["id"],
                    "description": desc[:400],
                    "cvss_score":  score,
                    "severity":    sev,
                    "published":   cve.get("published", "N/A")[:10],
                    "references":  [r["url"] for r in cve.get("references", [])[:2]],
                })

            start_index += PAGE_SIZE
            fetched = len(all_cves)

            if start_index >= total_results:
                break

            print(f"  [NVD] Đã lấy {fetched}/{total_results}...")
            time.sleep(0.6)

        print(f"  [NVD] ✅ Lấy được {len(all_cves)} CVE từ NVD API (tổng: {total_results})")
        return {"context": all_cves, "source": "NVD-LIVE", "total": total_results}

    except Exception as e:
        print(f"  [NVD] ❌ API lỗi: {e}")
        print(f"  [NVD] Không thể lấy dữ liệu CVE từ NVD API")
        return {"context": [], "source": "NVD-ERROR", "total": 0}
