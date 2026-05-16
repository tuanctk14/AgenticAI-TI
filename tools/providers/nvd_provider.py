"""
tools/providers/nvd_provider.py - NVD provider implementation

Extracts logic from nvd_client.py and adapts to provider interface.
NVD is HARD-FAIL (required) - no fallback support.
"""

import requests
from datetime import datetime
from config import NVD_API_KEY
from .base import BaseProvider, ProviderResult


class NVDProvider(BaseProvider):
    """
    National Vulnerability Database (NVD) provider.

    REQUIRED source for:
    - CVSS scores
    - CWE mappings
    - CPE entries
    - Published/Modified dates
    - References
    - Configurations

    Hard-fail if not found or API error.
    """

    def __init__(self, api_key: str = None, timeout: int = 15):
        """Initialize NVD provider"""
        super().__init__(name="nvd", timeout=timeout)
        self.api_key = api_key or NVD_API_KEY
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def validate_connection(self) -> bool:
        """Validate NVD API is accessible"""
        try:
            response = requests.get(
                self.base_url,
                params={"cveName": "CVE-2021-44228"},
                headers={"apiKey": self.api_key} if self.api_key else {},
                timeout=5,
            )
            return response.status_code == 200
        except Exception:
            return False

    async def _fetch_impl(self, cve_id: str) -> ProviderResult:
        """Fetch CVE from NVD API"""
        try:
            return ProviderResult(
                success=True,
                data=self._fetch_sync(cve_id),
                fetched_at=datetime.utcnow(),
                source="nvd"
            )
        except Exception as e:
            return ProviderResult(
                success=False,
                error=str(e),
                source="nvd"
            )

    def _fetch_sync(self, cve_id: str) -> dict:
        """Synchronous NVD fetch (extracted from nvd_client.py)"""
        print(f"  [NVD] Looking up: CVE={cve_id}")

        headers = {"apiKey": self.api_key} if self.api_key else {}
        params = {"cveId": cve_id}

        response = requests.get(
            self.base_url,
            params=params,
            headers=headers,
            timeout=self.timeout
        )
        response.raise_for_status()
        data = response.json()

        if not data.get("vulnerabilities"):
            print(f"  [NVD] CVE not found: {cve_id}")
            return None

        item = data["vulnerabilities"][0]
        cve = item["cve"]

        # Extract description
        desc = (cve.get("descriptions") or [{"value": "N/A"}])[0]["value"]

        # Extract CVSS score
        metrics = cve.get("metrics", {})
        cvss_score = "N/A"
        cvss_severity = "UNKNOWN"
        cvss_vector = None

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                m = metrics[key][0]
                cvss_score = m["cvssData"]["baseScore"]
                cvss_severity = m["cvssData"].get("baseSeverity", cvss_severity)
                cvss_vector = m["cvssData"].get("vectorString")
                break

        # Extract CWE
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

        # Extract CPE and configurations
        configurations = cve.get("configurations", [])

        # Extract references
        references = [r["url"] for r in cve.get("references", [])[:5]]

        print(f"  [NVD]  Found {cve_id}")

        return {
            "id": cve["id"],
            "description": desc,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cvss_vector": cvss_vector,
            "published": cve.get("published", "N/A")[:10],
            "modified": cve.get("lastModified", "N/A")[:10],
            "cwe_ids": cwe_ids,
            "configurations": configurations,
            "references": references,
        }
