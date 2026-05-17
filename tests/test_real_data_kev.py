"""
tests/test_real_data_kev.py - Real Data Testing with CISA KEV API

Tests fetching and processing REAL KEV data from CISA.
Validates known exploited vulnerabilities with production data.
"""

import pytest
import httpx
from datetime import datetime
from typing import Optional, Dict, Any, List

from core.threat_adapters import KEVAdapter
from core.threat_schema import Vulnerability, RiskContext, SeverityLevel


class KEVRealDataFetcher:
    """Fetch real KEV data from CISA API."""

    BASE_URL = "https://services.cisa.gov/json/cves_kev_v1.json"

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def fetch_all_kev(self) -> Optional[Dict[str, Any]]:
        """Fetch all known exploited vulnerabilities."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.BASE_URL)

                if response.status_code == 200:
                    return response.json()
                else:
                    print(f"[KEV] API error: {response.status_code}")
                    return None
        except Exception as e:
            print(f"[KEV] Fetch error: {e}")
            return None

    async def fetch_kev_by_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch KEV data for specific CVE."""
        kev_data = await self.fetch_all_kev()

        if kev_data:
            vulnerabilities = kev_data.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                if vuln.get("cveID") == cve_id:
                    return vuln

        return None

    async def fetch_recent_kev(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Fetch recently added known exploited vulnerabilities."""
        kev_data = await self.fetch_all_kev()

        if kev_data:
            vulnerabilities = kev_data.get("vulnerabilities", [])

            # Sort by dateAdded (descending)
            sorted_vulns = sorted(
                vulnerabilities,
                key=lambda x: x.get("dateAdded", ""),
                reverse=True
            )

            return sorted_vulns[:limit]

        return []


class TestKEVRealData:
    """Test system with real KEV data."""

    @pytest.fixture
    async def fetcher(self):
        """Initialize KEV fetcher."""
        return KEVRealDataFetcher()

    @pytest.fixture
    def adapter(self):
        """Initialize KEV adapter."""
        return KEVAdapter()

    @pytest.mark.asyncio
    async def test_fetch_all_kev(self, fetcher):
        """Test fetching all known exploited vulnerabilities."""
        kev_data = await fetcher.fetch_all_kev()

        assert kev_data is not None, "Should fetch KEV data"
        assert "vulnerabilities" in kev_data, "Should have vulnerabilities"

        vulns = kev_data["vulnerabilities"]
        assert len(vulns) > 0, "Should have at least one KEV entry"

        print(f"\n[KEV] Total known exploited vulnerabilities: {len(vulns)}")

        # Show first few
        for vuln in vulns[:5]:
            cve_id = vuln.get("cveID")
            date_added = vuln.get("dateAdded")
            product = vuln.get("product")
            print(f"  - {cve_id}: {product} (added: {date_added})")

    @pytest.mark.asyncio
    async def test_fetch_recent_kev(self, fetcher):
        """Test fetching recent KEV additions."""
        recent = await fetcher.fetch_recent_kev(limit=5)

        assert isinstance(recent, list), "Should return list"
        assert len(recent) > 0, "Should have recent KEV entries"

        print(f"\n[KEV] Recently added exploited vulnerabilities:")
        for vuln in recent:
            cve_id = vuln.get("cveID")
            date_added = vuln.get("dateAdded")
            product = vuln.get("product")
            vendor = vuln.get("vendor")
            print(f"  - {cve_id} ({vendor}/{product})")
            print(f"    Added: {date_added}")

    @pytest.mark.asyncio
    async def test_kev_enrichment(self, fetcher, adapter):
        """Test enriching vulnerability with KEV data."""
        recent = await fetcher.fetch_recent_kev(limit=1)

        if recent:
            kev_vuln = recent[0]
            cve_id = kev_vuln.get("cveID")

            # Create base vulnerability
            vuln = Vulnerability(
                id=cve_id,
                description=f"Exploit available: {kev_vuln.get('product')}",
                severity=SeverityLevel.HIGH,
                risk_context=RiskContext(
                    cvss_score=7.5,
                    cvss_source="nvd"
                )
            )

            # Enrich with KEV
            enriched = adapter.merge_kev_enrichment(vuln, kev_vuln)

            assert enriched.risk_context.kev_listed == True, "Should mark as KEV listed"
            assert enriched.risk_context.kev_added_date is not None, "Should have KEV add date"
            assert "kev" in enriched.risk_context.data_sources, "Should list KEV as source"

            print(f"\n[KEV] Enriched {enriched.id}:")
            print(f"  KEV Listed: {enriched.risk_context.kev_listed}")
            print(f"  KEV Added Date: {enriched.risk_context.kev_added_date}")
            print(f"  Product: {kev_vuln.get('product')}")
            print(f"  Vendor: {kev_vuln.get('vendor')}")

    @pytest.mark.asyncio
    async def test_kev_vendor_distribution(self, fetcher):
        """Test vendor distribution in KEV."""
        kev_data = await fetcher.fetch_all_kev()

        if kev_data:
            vulnerabilities = kev_data.get("vulnerabilities", [])
            vendors = {}

            for vuln in vulnerabilities:
                vendor = vuln.get("vendor", "Unknown")
                vendors[vendor] = vendors.get(vendor, 0) + 1

            # Top vendors
            top_vendors = sorted(vendors.items(), key=lambda x: -x[1])[:10]

            print(f"\n[KEV] Top vendors with exploited vulnerabilities:")
            for vendor, count in top_vendors:
                print(f"  {vendor}: {count} CVEs")

    @pytest.mark.asyncio
    async def test_kev_product_distribution(self, fetcher):
        """Test product distribution in KEV."""
        kev_data = await fetcher.fetch_all_kev()

        if kev_data:
            vulnerabilities = kev_data.get("vulnerabilities", [])
            products = {}

            for vuln in vulnerabilities:
                product = vuln.get("product", "Unknown")
                products[product] = products.get(product, 0) + 1

            # Top products
            top_products = sorted(products.items(), key=lambda x: -x[1])[:10]

            print(f"\n[KEV] Top products with exploited vulnerabilities:")
            for product, count in top_products:
                print(f"  {product}: {count} CVEs")


class TestKEVDataValidation:
    """Validate real KEV data quality."""

    @pytest.fixture
    async def fetcher(self):
        return KEVRealDataFetcher()

    @pytest.mark.asyncio
    async def test_kev_cve_format(self, fetcher):
        """Validate CVE ID format in KEV."""
        kev_data = await fetcher.fetch_all_kev()

        if kev_data:
            vulnerabilities = kev_data.get("vulnerabilities", [])

            for vuln in vulnerabilities[:10]:
                cve_id = vuln.get("cveID")

                # Validate format
                parts = cve_id.split("-")
                assert len(parts) == 3, f"Invalid CVE format: {cve_id}"
                assert parts[0] == "CVE", f"Should start with CVE: {cve_id}"
                assert parts[1].isdigit(), f"Year should be numeric: {cve_id}"
                assert parts[2].isdigit(), f"ID should be numeric: {cve_id}"

            print(f"✓ All CVE formats valid in KEV sample")

    @pytest.mark.asyncio
    async def test_kev_date_validity(self, fetcher):
        """Validate date fields in KEV."""
        kev_data = await fetcher.fetch_all_kev()

        if kev_data:
            vulnerabilities = kev_data.get("vulnerabilities", [])

            for vuln in vulnerabilities[:10]:
                date_added = vuln.get("dateAdded")
                cve_id = vuln.get("cveID")

                # Parse date
                try:
                    parsed_date = datetime.fromisoformat(date_added)
                    assert parsed_date <= datetime.now(), f"Date in future: {cve_id}"
                except ValueError:
                    pytest.fail(f"Invalid date format for {cve_id}: {date_added}")

            print(f"✓ All KEV dates valid")

    @pytest.mark.asyncio
    async def test_kev_required_fields(self, fetcher):
        """Validate required fields in KEV entries."""
        kev_data = await fetcher.fetch_all_kev()

        if kev_data:
            vulnerabilities = kev_data.get("vulnerabilities", [])

            required_fields = ["cveID", "vendor", "product", "dateAdded"]

            for vuln in vulnerabilities[:10]:
                for field in required_fields:
                    assert field in vuln, f"Missing required field '{field}' in {vuln.get('cveID')}"
                    assert vuln[field], f"Empty required field '{field}' in {vuln.get('cveID')}"

            print(f"✓ All KEV entries have required fields")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
