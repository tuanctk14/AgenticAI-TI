"""
tests/test_real_data_epss.py - Real Data Testing with EPSS API

Tests fetching and processing REAL EPSS data from FIRST API.
Validates exploit prediction scores with production data.
"""

import pytest
import httpx
from datetime import datetime
from typing import Optional, Dict, Any, List

from core.threat_adapters import EPSSAdapter
from core.threat_schema import Vulnerability, RiskContext, SeverityLevel


class EPSSRealDataFetcher:
    """Fetch real EPSS data from FIRST API."""

    BASE_URL = "https://api.first.org/data/v1/epss"

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def fetch_epss_by_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch EPSS data for specific CVE."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    self.BASE_URL,
                    params={"cve": cve_id}
                )

                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "OK" and data.get("data"):
                        return data["data"][0]
                return None
        except Exception as e:
            print(f"[EPSS] Fetch error for {cve_id}: {e}")
            return None

    async def fetch_epss_batch(self, cve_ids: List[str]) -> Dict[str, Optional[Dict[str, Any]]]:
        """Fetch EPSS for multiple CVEs."""
        results = {}
        for cve_id in cve_ids:
            results[cve_id] = await self.fetch_epss_by_cve(cve_id)
        return results


class TestEPSSRealData:
    """Test system with real EPSS data."""

    @pytest.fixture
    async def fetcher(self):
        """Initialize EPSS fetcher."""
        return EPSSRealDataFetcher()

    @pytest.fixture
    def adapter(self):
        """Initialize EPSS adapter."""
        return EPSSAdapter()

    @pytest.mark.asyncio
    async def test_fetch_epss_single_cve(self, fetcher):
        """Test fetching EPSS for single CVE."""
        # Use a recent high-profile CVE
        cve_id = "CVE-2024-3156"

        epss_data = await fetcher.fetch_epss_by_cve(cve_id)

        if epss_data:
            print(f"\n[EPSS] Data for {cve_id}:")
            print(f"  EPSS Score: {epss_data.get('epss')}")
            print(f"  Percentile: {epss_data.get('percentile')}")
            print(f"  Date: {epss_data.get('date')}")

            assert "epss" in epss_data, "Should have EPSS score"
            assert "percentile" in epss_data, "Should have percentile"
            assert 0 <= epss_data["epss"] <= 1.0, "EPSS should be 0-1"
            assert 0 <= epss_data["percentile"] <= 100, "Percentile should be 0-100"
        else:
            pytest.skip(f"EPSS data not available for {cve_id}")

    @pytest.mark.asyncio
    async def test_epss_enrichment(self, fetcher, adapter):
        """Test enriching vulnerability with EPSS data."""
        cve_id = "CVE-2024-3156"

        # Create base vulnerability
        vuln = Vulnerability(
            id=cve_id,
            description="Test vulnerability",
            severity=SeverityLevel.HIGH,
            risk_context=RiskContext(
                cvss_score=7.5,
                cvss_source="nvd"
            )
        )

        # Fetch EPSS data
        epss_data = await fetcher.fetch_epss_by_cve(cve_id)

        if epss_data:
            # Enrich with EPSS
            enriched = adapter.merge_epss_enrichment(vuln, epss_data)

            assert enriched.risk_context.epss_score is not None, "Should have EPSS score"
            assert enriched.risk_context.epss_percentile is not None, "Should have percentile"
            assert "epss" in enriched.risk_context.data_sources, "Should list EPSS as source"

            print(f"\n[EPSS] Enriched {enriched.id}:")
            print(f"  CVSS: {enriched.risk_context.cvss_score}")
            print(f"  EPSS: {enriched.risk_context.epss_score}")
            print(f"  EPSS Percentile: {enriched.risk_context.epss_percentile}")
            print(f"  Sources: {enriched.risk_context.data_sources}")
        else:
            pytest.skip(f"EPSS data not available for {cve_id}")

    @pytest.mark.asyncio
    async def test_epss_score_distribution(self, fetcher):
        """Test EPSS score distribution across multiple CVEs."""
        cve_ids = [
            "CVE-2024-3156",
            "CVE-2024-2961",
            "CVE-2024-2233",
            "CVE-2024-1709",
            "CVE-2024-1040",
        ]

        results = await fetcher.fetch_epss_batch(cve_ids)

        valid_scores = []
        for cve_id, epss_data in results.items():
            if epss_data:
                score = epss_data.get("epss")
                valid_scores.append(score)
                print(f"[EPSS] {cve_id}: {score:.4f} (percentile: {epss_data.get('percentile')})")

        if valid_scores:
            avg_score = sum(valid_scores) / len(valid_scores)
            max_score = max(valid_scores)
            min_score = min(valid_scores)

            print(f"\n[EPSS] Statistics:")
            print(f"  Samples: {len(valid_scores)}")
            print(f"  Average: {avg_score:.4f}")
            print(f"  Min: {min_score:.4f}")
            print(f"  Max: {max_score:.4f}")


class TestEPSSDataValidation:
    """Validate real EPSS data quality."""

    @pytest.fixture
    async def fetcher(self):
        return EPSSRealDataFetcher()

    @pytest.mark.asyncio
    async def test_epss_score_validity(self, fetcher):
        """Validate EPSS score ranges."""
        cve_ids = [
            "CVE-2024-3156",
            "CVE-2024-2961",
            "CVE-2024-2233",
        ]

        for cve_id in cve_ids:
            epss_data = await fetcher.fetch_epss_by_cve(cve_id)

            if epss_data:
                epss = epss_data.get("epss")
                percentile = epss_data.get("percentile")

                assert isinstance(epss, (int, float)), f"EPSS should be numeric for {cve_id}"
                assert 0 <= epss <= 1.0, f"EPSS out of range for {cve_id}: {epss}"
                assert isinstance(percentile, (int, float)), f"Percentile should be numeric for {cve_id}"
                assert 0 <= percentile <= 100, f"Percentile out of range for {cve_id}: {percentile}"

                print(f"✓ Valid EPSS data for {cve_id}: score={epss:.4f}, percentile={percentile}")

    @pytest.mark.asyncio
    async def test_epss_date_format(self, fetcher):
        """Validate EPSS date format."""
        cve_id = "CVE-2024-3156"

        epss_data = await fetcher.fetch_epss_by_cve(cve_id)

        if epss_data:
            date_str = epss_data.get("date")
            assert isinstance(date_str, str), "Date should be string"

            # Try to parse the date
            try:
                parsed_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                print(f"✓ Valid EPSS date for {cve_id}: {parsed_date.date()}")
            except ValueError:
                pytest.fail(f"Invalid date format in EPSS: {date_str}")

    @pytest.mark.asyncio
    async def test_epss_consistency(self, fetcher):
        """Test EPSS data consistency (same CVE returns same score)."""
        cve_id = "CVE-2024-3156"

        # Fetch twice
        data1 = await fetcher.fetch_epss_by_cve(cve_id)
        data2 = await fetcher.fetch_epss_by_cve(cve_id)

        if data1 and data2:
            # Scores should be identical (or very close due to rounding)
            score1 = data1.get("epss")
            score2 = data2.get("epss")

            assert abs(score1 - score2) < 0.0001, f"EPSS scores differ: {score1} vs {score2}"
            print(f"✓ Consistent EPSS data for {cve_id}: {score1}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
