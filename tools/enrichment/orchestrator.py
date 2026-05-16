"""
tools/enrichment/orchestrator.py - Async multi-provider CVE enrichment orchestrator

Coordinates enrichment from multiple providers with:
- Fallback chains (NVD → VulnCheck, CISA → VulnCheck)
- Concurrent execution (EPSS, KEV, VulnCheck async)
- Cache integration
- Error isolation
"""

import asyncio
from typing import Dict, List, Optional
from datetime import datetime
from config import VULNERS_API_KEY

from .schema import UnifiedCVE, CVEMetadata, CVSSData, CWEData, CPEData, DataQuality, DataSource
from .cache import CacheProvider, SQLiteCacheProvider
from ..providers import BaseProvider, NVDProvider, EPSSProvider, KEVProvider, VulnersProvider


class EnrichmentOrchestrator:
    """
    Orchestrates CVE enrichment from multiple providers.

    Flow:
    1. Check cache (return if hit)
    2. Fetch NVD (required/hard-fail)
    3. Async fetch EPSS + KEV + Vulners enrichment (soft-fail)
    4. Merge data
    5. Calculate risk scores
    6. Cache result
    7. Return UnifiedCVE
    """

    def __init__(
        self,
        cache: Optional[CacheProvider] = None,
        nvd_api_key: str = None,
        vulners_api_key: str = None,
        cache_ttl: int = 86400,  # 24h default
    ):
        """
        Initialize orchestrator.

        Args:
            cache: CacheProvider instance (default: SQLite)
            nvd_api_key: NVD API key
            vulners_api_key: Vulners API key
            cache_ttl: Cache TTL in seconds (default 24h)
        """
        self.cache = cache or SQLiteCacheProvider()
        self.cache_ttl = cache_ttl

        # Initialize providers
        self.providers: Dict[str, BaseProvider] = {
            "nvd": NVDProvider(api_key=nvd_api_key),
            "epss": EPSSProvider(),
            "kev": KEVProvider(),
            "vulners": VulnersProvider(api_key=vulners_api_key),
        }

    async def enrich_cve(self, cve_id: str) -> UnifiedCVE:
        """
        Enrich a single CVE from multiple providers.

        Flow:
        1. Check cache (return if hit)
        2. Fetch NVD (required/hard-fail)
        3. Async fetch EPSS + KEV + Vulners enrichment (soft-fail)
        4. Merge data
        5. Calculate risk scores
        6. Cache result
        7. Return UnifiedCVE
        """
        # 1. Check cache
        cached = await self.cache.get(cve_id)
        if cached:
            cached.cache_hit = True
            return cached

        # 2. Fetch NVD (required/hard-fail)
        nvd_result = await self._fetch_from_provider("nvd", cve_id)
        if not nvd_result or not nvd_result.success:
            raise ValueError(f"NVD fetch failed for {cve_id} (required source): {nvd_result.error if nvd_result else 'No response'}")

        nvd_data = nvd_result.data

        # 3. Async fetch enrichment providers (soft-fail)
        epss_task = self._fetch_from_provider("epss", cve_id)
        kev_task = self._fetch_kev_with_fallback(cve_id)
        vulners_task = self._fetch_from_provider("vulners", cve_id)

        epss_result, kev_result, vulners_result = await asyncio.gather(
            epss_task, kev_task, vulners_task, return_exceptions=True
        )

        # Handle exceptions from gather
        epss_result = epss_result if isinstance(epss_result, type(nvd_result)) else None
        kev_result = kev_result if isinstance(kev_result, type(nvd_result)) else None
        vulners_result = vulners_result if isinstance(vulners_result, type(nvd_result)) else None

        # 4. Merge results into UnifiedCVE
        unified = self._merge_enrichment_results(
            cve_id, nvd_data, epss_result, kev_result, vulners_result
        )

        # 6. Cache result
        await self.cache.set(cve_id, unified, self.cache_ttl)

        return unified

    async def enrich_batch(self, cve_ids: List[str]) -> List[UnifiedCVE]:
        """
        Enrich multiple CVEs concurrently.

        Runs enrich_cve for each CVE in parallel using asyncio.gather.
        Returns list of UnifiedCVE objects in same order as input.
        """
        tasks = [self.enrich_cve(cve_id) for cve_id in cve_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions (hard-fails from NVD)
        enriched = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                raise result  # Propagate hard failures
            enriched.append(result)

        return enriched

    async def _fetch_from_provider(self, provider_name: str, cve_id: str):
        """Fetch from single provider with timeout isolation"""
        provider = self.providers.get(provider_name)
        if not provider or not provider.enabled:
            return None
        return await provider.fetch_with_timeout(cve_id)

    async def _fetch_kev_with_fallback(self, cve_id: str):
        """
        Fetch KEV from CISA official feed.

        Returns CISA KEV data or None if not listed.
        """
        kev_result = await self._fetch_from_provider("kev", cve_id)
        return kev_result

    def _merge_enrichment_results(
        self,
        cve_id: str,
        nvd_data: dict,
        epss_result,
        kev_result,
        vulners_result
    ) -> UnifiedCVE:
        """
        Merge results from all providers into UnifiedCVE object.

        Handles:
        - Source attribution (NVD, Vulners, CISA, FIRST)
        - Data quality tracking
        - Risk score calculation
        """
        from .schema import (
            UnifiedCVE, CVEMetadata, CVSSData, CWEData, CPEData,
            EPSSData, KEVData, VulnersData, DataQuality, DataSource
        )

        # Build metadata
        metadata = CVEMetadata(
            cve_id=cve_id,
            description=nvd_data.get("description", "N/A"),
            published_date=nvd_data.get("published", "N/A"),
            modified_date=nvd_data.get("modified", "N/A"),
            references=nvd_data.get("references", [])
        )

        # Build CVSS (from NVD only)
        cvss_score = nvd_data.get("cvss_score", "N/A")
        cvss = CVSSData(
            score=DataSource(
                value=cvss_score,
                source="nvd",
                confidence=1.0
            ),
            severity=nvd_data.get("severity", "UNKNOWN"),
            vector=nvd_data.get("cvss_vector")
        )

        # Build CWE (from NVD only)
        cwe_ids = nvd_data.get("cwe_ids", [])
        cwe = CWEData(
            ids=DataSource(
                value=cwe_ids,
                source="nvd",
                confidence=1.0
            )
        )

        # Build CPE (from NVD only)
        cpe_entries = nvd_data.get("configurations", [])
        cpe = CPEData(
            entries=DataSource(
                value=cpe_entries,
                source="nvd",
                confidence=1.0
            )
        )

        # Build EPSS
        epss = None
        if epss_result and epss_result.success:
            epss_data = epss_result.data
            epss = EPSSData(
                score=epss_data.get("score"),
                percentile=epss_data.get("percentile"),
                available=True
            )

        # Build KEV
        kev = None
        if kev_result and kev_result.success:
            kev_data = kev_result.data
            kev = KEVData(
                listed=kev_data.get("listed", False),
                date_added=kev_data.get("date_added"),
                due_date=kev_data.get("due_date"),
                known_ransomware_campaign_use=kev_data.get("known_ransomware_campaign_use", False),
                source=kev_data.get("source", "cisa")
            )

        # Build Vulners
        vulncheck = None
        if vulners_result and vulners_result.success:
            vulners_data = vulners_result.data
            vulncheck = VulnersData(
                public_exploit_available=vulners_data.get("public_exploit_available", False),
                metasploit_available=vulners_data.get("metasploit_available", False),
                exploit_count=vulners_data.get("exploit_count", 0),
                exploit_sources=vulners_data.get("exploit_sources", []),
                exploit_references=vulners_data.get("exploit_references", [])
            )

        # Build data quality
        data_quality = DataQuality(
            cvss_source="nvd",
            cwe_source="nvd",
            cpe_source="nvd",
            kev_source=kev.source if kev else "cisa",
            epss_available=epss is not None
        )

        # Calculate basic risk score (will be enhanced by risk_scorer)
        unified_risk_score = self._calculate_risk_score(cvss, epss, kev, vulncheck)

        # Build enrichment summary
        enrichment_summary = self._build_enrichment_summary(epss, kev, vulncheck)

        # Create UnifiedCVE
        unified = UnifiedCVE(
            cve_id=cve_id,
            metadata=metadata,
            cvss=cvss,
            cwe=cwe,
            cpe=cpe,
            epss=epss,
            kev=kev,
            vulncheck=vulncheck,
            data_quality=data_quality,
            unified_risk_score=unified_risk_score,
            enrichment_summary=enrichment_summary,
            cache_hit=False
        )

        return unified

    def _calculate_risk_score(self, cvss, epss, kev, vulncheck) -> float:
        """
        Calculate basic risk score combining enrichment factors.

        Formula:
        - CVSS: 35% weight
        - EPSS: 15% weight
        - KEV: 10% (bonus if listed + confirmed exploit)
        - Public Exploit: 10%
        - Ransomware: 5%
        """
        score = 0.0

        # CVSS component
        if cvss and cvss.score.value and cvss.score.value != "N/A":
            try:
                cvss_val = float(cvss.score.value)
                score += (cvss_val / 10.0) * 35
            except (ValueError, TypeError):
                pass

        # EPSS component
        if epss and epss.available and epss.score:
            score += epss.score * 15

        # KEV component (confirmed exploitation)
        if kev and kev.listed:
            score += 10
            # Bonus if ransomware campaign
            if kev.known_ransomware_campaign_use:
                score += 5

        # Exploit intelligence components (Vulners)
        if vulncheck:
            if vulncheck.public_exploit_available:
                score += 10
                # Bonus for exploit count
                if vulncheck.exploit_count > 0:
                    score += min(vulncheck.exploit_count / 5, 5)  # Max 5 points

        return min(score, 100.0)  # Cap at 100

    def _build_enrichment_summary(self, epss, kev, vulncheck) -> str:
        """
        Build human-readable enrichment summary.

        Example: "High EPSS (0.95) | KEV Listed | 3 Vulners Exploits"
        """
        parts = []

        if epss and epss.available and epss.score is not None:
            try:
                score_val = float(epss.score)
                severity = "Critical" if score_val > 0.9 else "High" if score_val > 0.7 else "Medium"
                parts.append(f"{severity} EPSS ({score_val:.2f})")
            except (ValueError, TypeError):
                pass

        if kev and kev.listed:
            parts.append("KEV Listed")

        if vulncheck:
            if vulncheck.public_exploit_available:
                if vulncheck.exploit_count > 0:
                    parts.append(f"{vulncheck.exploit_count} Vulners Exploits")
                else:
                    parts.append("Exploit Available")
            if vulncheck.metasploit_available:
                parts.append("Metasploit Module")

        return " | ".join(parts) if parts else "No enrichment data available"

    async def validate_providers(self) -> Dict[str, bool]:
        """
        Validate all enabled providers are accessible.

        Returns: {provider_name: is_accessible}
        """
        results = {}
        for name, provider in self.providers.items():
            if provider.enabled:
                results[name] = await provider.validate_connection()
        return results

    def set_provider_enabled(self, provider_name: str, enabled: bool):
        """Enable/disable provider"""
        if provider_name in self.providers:
            self.providers[provider_name].enabled = enabled

    async def get_cache_stats(self) -> dict:
        """Get cache statistics"""
        return await self.cache.get_stats()

    async def clear_cache_entry(self, cve_id: str) -> bool:
        """Clear single cache entry"""
        return await self.cache.clear(cve_id)

    async def cleanup_expired_cache(self) -> int:
        """Clean up expired cache entries"""
        return await self.cache.cleanup_expired()
