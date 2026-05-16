"""
tools/providers/epss_provider.py - EPSS provider (stub for Phase 2)

FIRST Exploit Prediction Scoring System
API: https://api.first.org/data/v1/epss

Returns: score (0-1), percentile (0-100)
"""

import asyncio
import aiohttp
from datetime import datetime
from .base import BaseProvider, ProviderResult


class EPSSProvider(BaseProvider):
    """
    FIRST Exploit Prediction Scoring System provider.

    Provides probability that a CVE will be exploited.
    No fallback - if unavailable, mark as "Not Available".
    """

    def __init__(self, timeout: int = 10):
        """Initialize EPSS provider"""
        super().__init__(name="epss", timeout=timeout)
        self.api_url = "https://api.first.org/data/v1/epss"

    async def validate_connection(self) -> bool:
        """Validate FIRST API is accessible"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.api_url}?cve=CVE-2021-44228",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def _fetch_impl(self, cve_id: str) -> ProviderResult:
        """
        Fetch EPSS data for CVE.

        Calls FIRST EPSS API and extracts score/percentile.
        Returns: {score: float, percentile: float} or error
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.api_url}?cve={cve_id}",
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()

                        # FIRST API returns {"data": [{"cve": "CVE-...", "epss": 0.95, "percentile": 99}]}
                        if data.get("data") and len(data["data"]) > 0:
                            epss_data = data["data"][0]
                            return ProviderResult(
                                success=True,
                                data={
                                    "score": float(epss_data.get("epss", 0)),
                                    "percentile": float(epss_data.get("percentile", 0))
                                },
                                fetched_at=datetime.utcnow(),
                                source="epss"
                            )
                        else:
                            return ProviderResult(
                                success=False,
                                error=f"No EPSS data found for {cve_id}",
                                source="epss"
                            )
                    else:
                        return ProviderResult(
                            success=False,
                            error=f"FIRST API returned {resp.status}",
                            source="epss"
                        )
        except asyncio.TimeoutError:
            return ProviderResult(
                success=False,
                error=f"EPSS request timeout after {self.timeout}s",
                source="epss"
            )
        except Exception as e:
            return ProviderResult(
                success=False,
                error=f"EPSS fetch error: {str(e)}",
                source="epss"
            )
