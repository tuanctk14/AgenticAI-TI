"""
tests/test_real_data_nvd.py - Real Data Testing with NVD API

Tests fetching and processing REAL CVE data from NVD API.
Validates system with production threat intelligence.
"""

import pytest
import httpx
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from core.threat_adapters import NVDAdapter
from core.threat_schema import Vulnerability, SeverityLevel


class NVDRealDataFetcher:
    """Fetch real CVE data from NVD API v2.0."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def fetch_recent_cves(self, limit: int = 5) -> list[Dict[str, Any]]:
        """Fetch recent CVEs from NVD API."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    self.BASE_URL,
                    params={
                        "resultsPerPage": limit,
                        "sortBy": "published",
                        "orderBy": "desc"
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    return data.get("vulnerabilities", [])
                else:
                    print(f"[NVD] API error: {response.status_code}")
                    return []
        except Exception as e:
            print(f"[NVD] Fetch error: {e}")
            return []

    async def fetch_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch specific CVE by ID."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    self.BASE_URL,
                    params={"cveId": cve_id}
                )

                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    return vulnerabilities[0] if vulnerabilities else None
        except Exception as e:
            print(f"[NVD] Fetch error for {cve_id}: {e}")
            return None

    async def fetch_cves_by_date_range(
        self,
        start_date: datetime,
        end_date: datetime,
        limit: int = 5
    ) -> list[Dict[str, Any]]:
        """Fetch CVEs published in date range."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    self.BASE_URL,
                    params={
                        "pubStartDate": start_date.isoformat() + "Z",
                        "pubEndDate": end_date.isoformat() + "Z",
                        "resultsPerPage": limit,
                        "sortBy": "published",
                        "orderBy": "desc"
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    return data.get("vulnerabilities", [])
        except Exception as e:
            print(f"[NVD] Date range fetch error: {e}")
            return []


class TestNVDRealData:
    """Test system with real NVD data."""

    @pytest.fixture
    async def fetcher(self):
        """Initialize NVD data fetcher."""
        return NVDRealDataFetcher()

    @pytest.fixture
    def adapter(self):
        """Initialize NVD adapter."""
        return NVDAdapter()

    @pytest.mark.asyncio
    async def test_fetch_recent_cves(self, fetcher):
        """Test fetching recent CVEs from NVD."""
        cves = await fetcher.fetch_recent_cves(limit=5)

        assert isinstance(cves, list), "Should return list of CVEs"
        assert len(cves) > 0, "Should return at least one CVE"

        # Verify structure
        first_cve = cves[0]
        assert "cve" in first_cve, "CVE object should have 'cve' field"
        assert "id" in first_cve["cve"], "CVE should have ID"

        print(f"\n[NVD] Fetched {len(cves)} recent CVEs")
        for cve in cves[:3]:
            cve_id = cve["cve"]["id"]
            print(f"  - {cve_id}")

    @pytest.mark.asyncio
    async def test_process_real_cve_data(self, fetcher, adapter):
        """Test processing real CVE data through adapter."""
        cves = await fetcher.fetch_recent_cves(limit=3)

        assert len(cves) > 0, "Should have fetched CVEs"

        vulnerabilities = []
        for cve_wrapper in cves:
            cve = cve_wrapper["cve"]

            # Extract metrics
            metrics = cve.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])

            # Build normalized data
            normalized_data = {
                "id": cve["id"],
                "description": cve.get("descriptions", [{}])[0].get("value", ""),
                "cwe_ids": self._extract_cwe_ids(cve),
                "references": self._extract_references(cve),
                "published": cve.get("published"),
                "modified": cve.get("lastModified"),
                "severity": self._extract_severity(cvss_v31),
                "cvss_score": self._extract_cvss_score(cvss_v31),
                "cvss_vector": self._extract_cvss_vector(cvss_v31),
            }

            # Normalize through adapter
            vuln = adapter.normalize_vulnerability(normalized_data)

            if vuln:
                vulnerabilities.append(vuln)
                print(f"\n[NVD] Processed: {vuln.id}")
                print(f"  Severity: {vuln.severity.value}")
                print(f"  CWEs: {vuln.cwe_ids}")
                print(f"  Description: {vuln.description[:80]}...")

        assert len(vulnerabilities) > 0, "Should process at least one CVE"
        assert all(isinstance(v, Vulnerability) for v in vulnerabilities)

    @pytest.mark.asyncio
    async def test_cve_severity_mapping(self, fetcher, adapter):
        """Test CVSS to severity mapping."""
        cves = await fetcher.fetch_recent_cves(limit=5)

        severities = {}
        for cve_wrapper in cves:
            cve = cve_wrapper["cve"]
            metrics = cve.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])

            severity = self._extract_severity(cvss_v31)
            severities[cve["id"]] = severity

            print(f"\n[NVD] CVE: {cve['id']}")
            print(f"  CVSS Score: {self._extract_cvss_score(cvss_v31)}")
            print(f"  Mapped Severity: {severity}")

        assert len(severities) > 0, "Should map severities"

    @pytest.mark.asyncio
    async def test_cve_cwe_extraction(self, fetcher):
        """Test CWE extraction from real CVEs."""
        cves = await fetcher.fetch_recent_cves(limit=3)

        cwe_counts = {}
        for cve_wrapper in cves:
            cve = cve_wrapper["cve"]
            cwe_ids = self._extract_cwe_ids(cve)

            if cwe_ids:
                for cwe in cwe_ids:
                    cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

                print(f"\n[NVD] {cve['id']} CWEs: {cwe_ids}")

        print(f"\n[NVD] Total unique CWEs: {len(cwe_counts)}")
        for cwe, count in sorted(cwe_counts.items(), key=lambda x: -x[1])[:5]:
            print(f"  {cwe}: {count} occurrences")

    @staticmethod
    def _extract_cwe_ids(cve: Dict[str, Any]) -> list[str]:
        """Extract CWE IDs from NVD CVE."""
        weaknesses = cve.get("weaknesses", [])
        cwe_ids = []
        for weakness in weaknesses:
            for cwe in weakness.get("cweId", []):
                cwe_id = cwe.get("id")
                if cwe_id and cwe_id not in cwe_ids:
                    cwe_ids.append(cwe_id)
        return cwe_ids

    @staticmethod
    def _extract_references(cve: Dict[str, Any]) -> list[str]:
        """Extract references from NVD CVE."""
        references = cve.get("references", [])
        return [ref.get("url", "") for ref in references if ref.get("url")]

    @staticmethod
    def _extract_severity(cvss_v31: list[Dict]) -> str:
        """Extract CVSS severity."""
        if not cvss_v31:
            return "UNKNOWN"

        score = cvss_v31[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
        return score

    @staticmethod
    def _extract_cvss_score(cvss_v31: list[Dict]) -> Optional[float]:
        """Extract CVSS score."""
        if not cvss_v31:
            return None

        return cvss_v31[0].get("cvssData", {}).get("baseScore")

    @staticmethod
    def _extract_cvss_vector(cvss_v31: list[Dict]) -> Optional[str]:
        """Extract CVSS vector."""
        if not cvss_v31:
            return None

        return cvss_v31[0].get("cvssData", {}).get("vectorString")


class TestNVDDataValidation:
    """Validate real NVD data quality."""

    @pytest.fixture
    async def fetcher(self):
        return NVDRealDataFetcher()

    @pytest.mark.asyncio
    async def test_cve_format_validation(self, fetcher):
        """Validate CVE ID format from real data."""
        cves = await fetcher.fetch_recent_cves(limit=5)

        for cve_wrapper in cves:
            cve_id = cve_wrapper["cve"]["id"]

            # Validate CVE format: CVE-YYYY-XXXXX
            parts = cve_id.split("-")
            assert len(parts) == 3, f"Invalid CVE format: {cve_id}"
            assert parts[0] == "CVE", f"Should start with CVE: {cve_id}"
            assert parts[1].isdigit(), f"Year should be numeric: {cve_id}"
            assert parts[2].isdigit(), f"ID should be numeric: {cve_id}"

            print(f"✓ Valid CVE format: {cve_id}")

    @pytest.mark.asyncio
    async def test_description_quality(self, fetcher):
        """Validate description quality."""
        cves = await fetcher.fetch_recent_cves(limit=5)

        for cve_wrapper in cves:
            cve = cve_wrapper["cve"]
            description = cve.get("descriptions", [{}])[0].get("value", "")

            assert len(description) > 10, "Description too short"
            assert isinstance(description, str), "Description should be string"

            print(f"✓ Description quality for {cve['id']}: {len(description)} chars")

    @pytest.mark.asyncio
    async def test_date_validity(self, fetcher):
        """Validate date fields."""
        cves = await fetcher.fetch_recent_cves(limit=5)

        for cve_wrapper in cves:
            cve = cve_wrapper["cve"]
            published = cve.get("published")
            modified = cve.get("lastModified")

            # Parse dates
            pub_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
            mod_date = datetime.fromisoformat(modified.replace("Z", "+00:00"))

            assert pub_date <= mod_date, f"Modified should be >= published for {cve['id']}"
            assert pub_date <= datetime.now(pub_date.tzinfo), "Published date should not be in future"

            print(f"✓ Valid dates for {cve['id']}: published={pub_date.date()}, modified={mod_date.date()}")

    @pytest.mark.asyncio
    async def test_metrics_presence(self, fetcher):
        """Validate presence of CVSS metrics."""
        cves = await fetcher.fetch_recent_cves(limit=5)

        for cve_wrapper in cves:
            cve = cve_wrapper["cve"]
            metrics = cve.get("metrics", {})

            # Check for CVSS v3.1 (most common)
            cvss_v31 = metrics.get("cvssMetricV31", [])

            if cvss_v31:
                score = cvss_v31[0].get("cvssData", {}).get("baseScore")
                severity = cvss_v31[0].get("cvssData", {}).get("baseSeverity")

                assert 0 <= score <= 10, f"Invalid CVSS score: {score}"
                assert severity in ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"], f"Invalid severity: {severity}"

                print(f"✓ Valid CVSS v3.1 for {cve['id']}: score={score}, severity={severity}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
