"""
tools/nvd_client.py - Lấy CVE từ NVD API (với mock fallback)
"""
import requests
from config import NVD_API_KEY

# ── Mock data dự phòng khi không có internet ──────────────────────────────
MOCK_CVES = [
    {
        "id": "CVE-2021-44228",
        "description": "Apache Log4j2 JNDI injection vulnerability (Log4Shell). Cho phép thực thi mã từ xa.",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "published": "2021-12-10",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        "affected_products": ["log4j", "log4j2"]
    },
    {
        "id": "CVE-2021-41773",
        "description": "Apache HTTP Server 2.4.49 path traversal và thực thi mã từ xa.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "published": "2021-10-05",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
        "affected_products": ["apache", "apache http", "httpd"]
    },
    {
        "id": "CVE-2022-22965",
        "description": "Spring Framework RCE via Data Binding trên JDK 9+ (Spring4Shell).",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "published": "2022-04-01",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
        "affected_products": ["spring", "springframework"]
    },
    {
        "id": "CVE-2014-0160",
        "description": "OpenSSL Heartbleed - lỗ hổng đọc bộ nhớ từ xa qua TLS heartbeat extension.",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "published": "2014-04-07",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"],
        "affected_products": ["openssl"]
    },
    {
        "id": "CVE-2022-1388",
        "description": "F5 BIG-IP iControl REST authentication bypass dẫn đến thực thi lệnh tùy ý.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "published": "2022-05-05",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-1388"],
        "affected_products": ["f5", "bigip"]
    },
    {
        "id": "CVE-2023-44487",
        "description": "HTTP/2 Rapid Reset Attack - tấn công DoS khai thác cơ chế reset stream.",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "published": "2023-10-10",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
        "affected_products": ["apache", "nginx", "tomcat", "http"]
    },
]


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
        print(f"  [NVD] ⚠️  API loi ({e}) → dung mock data")

    # Fallback: tim trong mock data
    for cve_data in MOCK_CVES:
        if cve_data["id"].lower() == cve_id.lower():
            print(f"  [NVD] 📦 Mock: tim thay {cve_id}")
            return {"context": [cve_data], "source": "NVD-MOCK", "total": 1}

    print(f"  [NVD] ❌ Khong tim thay {cve_id}")
    return {"context": [], "source": "NVD-MOCK", "total": 0}


def fetch_nvd_cves(keyword: str = "", severity: str = "HIGH", days_back: int = 30) -> dict:
    """
    Truy vấn NVD API để lấy CVE mới nhất.
    Tự động fallback sang mock data nếu không có internet hoặc API key.
    """
    print(f"  [NVD] Tìm kiếm: keyword='{keyword}', severity='{severity}'")

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers  = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params   = {"resultsPerPage": 10, "startIndex": 0}
    if keyword:
        params["keywordSearch"] = keyword
    if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        params["cvssV3Severity"] = severity

    try:
        resp = requests.get(base_url, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()

        cves = []
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
            cves.append({
                "id":          cve["id"],
                "description": desc[:400],
                "cvss_score":  score,
                "severity":    sev,
                "published":   cve.get("published", "N/A")[:10],
                "references":  [r["url"] for r in cve.get("references", [])[:2]],
            })
        print(f"  [NVD] ✅ Lấy được {len(cves)} CVE từ NVD API")
        return {"context": cves, "source": "NVD-LIVE", "total": data.get("totalResults", 0)}

    except Exception as e:
        print(f"  [NVD] ⚠️  API lỗi ({e}) → dùng mock data")

    # ── Fallback: lọc mock data ────────────────────────────────────────────
    filtered = MOCK_CVES
    if keyword:
        kw = keyword.lower()
        filtered = [c for c in MOCK_CVES if
                    kw in c["description"].lower() or
                    any(kw in p for p in c["affected_products"])]
    if severity:
        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        min_sev = sev_order.get(severity.upper(), 3)
        filtered = [c for c in filtered if sev_order.get(c.get("severity", ""), 0) >= min_sev]

    print(f"  [NVD] 📦 Mock data: {len(filtered)} CVE")
    return {"context": filtered, "source": "NVD-MOCK", "total": len(filtered)}
