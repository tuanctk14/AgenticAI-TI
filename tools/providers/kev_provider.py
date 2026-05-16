"""
tools/providers/kev_provider.py - CISA KEV provider

Known Exploited Vulnerabilities
Primary: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Fallback: VulnCheck API
"""

import asyncio
import aiohttp
from datetime import datetime
from .base import BaseProvider, ProviderResult


class KEVProvider(BaseProvider):
    """
    CISA Known Exploited Vulnerabilities provider.

    Primary: CISA official JSON feed (cached locally)
    Fallback: VulnCheck API if CISA unavailable

    Returns: listed, date_added, due_date, known_ransomware_campaign_use, source
    """

    def __init__(self, timeout: int = 15):
        """Initialize KEV provider"""
        super().__init__(name="kev", timeout=timeout)
        self.cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self._kev_cache = None  # Cache CISA JSON locally
        self._cache_time = None

    async def validate_connection(self) -> bool:
        """Validate CISA KEV feed is accessible"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.cisa_url,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def _fetch_cisa_kev(self) -> dict:
        """
        Fetch CISA KEV JSON feed with local caching.

        Returns dict mapping CVE ID to KEV data or None if fetch fails.
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.cisa_url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        # Cache the full JSON
                        self._kev_cache = {item["cveID"]: item for item in data.get("vulnerabilities", [])}
                        self._cache_time = datetime.utcnow()
                        return self._kev_cache
                    else:
                        return None
        except Exception:
            return None

    async def _fetch_from_vulncheck(self, cve_id: str):
        """
        Fallback: Fetch KEV data from VulnCheck API.

        Note: VulnCheckProvider is a sibling, not imported to avoid circular dep.
        This is called via orchestrator's fallback chain.
        """
        # Placeholder - actual VulnCheck fallback is coordinated by orchestrator
        return None

    async def _fetch_impl(self, cve_id: str) -> ProviderResult:
        """
        Fetch KEV data for CVE.

        Primary: CISA JSON feed (with local caching)
        Fallback: VulnCheck (via orchestrator)
        Returns: {listed, date_added, due_date, known_ransomware_campaign_use, source}
        """
        # Load CISA KEV if not cached
        if self._kev_cache is None:
            await self._fetch_cisa_kev()

        # Look up CVE in cached KEV data
        if self._kev_cache and cve_id in self._kev_cache:
            item = self._kev_cache[cve_id]
            return ProviderResult(
                success=True,
                data={
                    "listed": True,
                    "date_added": item.get("dateAdded"),
                    "due_date": item.get("dueDate"),
                    "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse", False),
                    "source": "cisa"
                },
                fetched_at=datetime.utcnow(),
                source="kev"
            )
        else:
            # Not found in CISA KEV - fallback is orchestrator's responsibility
            return ProviderResult(
                success=False,
                error=f"CVE not found in CISA KEV feed (fallback to VulnCheck required)",
                source="kev"
            )
