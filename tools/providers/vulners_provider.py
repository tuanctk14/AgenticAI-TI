"""
tools/providers/vulners_provider.py - Vulners exploit intelligence provider

Vulners API: https://vulners.com/api/v3/
Capabilities:
- Exploit intelligence (public exploits, sources, references)
- Threat intelligence aggregation
"""

import asyncio
import aiohttp
from datetime import datetime
from config import VULNERS_API_KEY
from .base import BaseProvider, ProviderResult


class VulnersProvider(BaseProvider):
    """
    Vulners exploit intelligence provider.

    Role: Provide exploit intelligence
    - public_exploit_available (boolean)
    - metasploit_available (boolean)
    - exploit_count (number)
    - exploit_sources (list of source names)
    - exploit_references (list of URLs)
    """

    def __init__(self, api_key: str = None, timeout: int = 15):
        """Initialize Vulners provider"""
        super().__init__(name="vulners", timeout=timeout)
        self.api_key = api_key or VULNERS_API_KEY
        self.base_url = "https://vulners.com/api/v3"

    async def validate_connection(self) -> bool:
        """Validate Vulners API is accessible"""
        try:
            async with aiohttp.ClientSession() as session:
                # Test with a known CVE
                headers = {"X-API-Key": self.api_key}
                params = {"id": "CVE-2021-44228"}
                async with session.get(
                    f"{self.base_url}/search/id/",
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    return resp.status in (200, 400, 401)  # Any response = API accessible
        except Exception:
            return False

    async def _fetch_impl(self, cve_id: str) -> ProviderResult:
        """
        Fetch Vulners data for CVE.

        Returns: exploit intelligence (count, sources, references)
        """
        if not self.api_key:
            return ProviderResult(
                success=False,
                error="Vulners API key not configured",
                source="vulners"
            )

        try:
            async with aiohttp.ClientSession() as session:
                # Vulners API endpoint for CVE lookup
                # API key must be in X-API-Key header, not query param
                headers = {"X-API-Key": self.api_key}
                params = {"id": cve_id}

                async with session.get(
                    f"{self.base_url}/search/id/",
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()

                        # Vulners returns results with various types (exploit, metasploit, etc.)
                        results = data.get("data", {}).get("search", [])

                        if results:
                            # Count different types of exploits
                            exploit_count = len(results)
                            metasploit_available = any(
                                r.get("type") == "metasploit"
                                for r in results
                            )
                            public_exploit_available = exploit_count > 0

                            # Extract sources and references
                            exploit_sources = list(set(
                                r.get("source", "Unknown") for r in results
                            ))
                            exploit_references = [
                                r.get("href", "") for r in results if r.get("href")
                            ][:10]  # Limit to 10 references

                            result = {
                                "public_exploit_available": public_exploit_available,
                                "metasploit_available": metasploit_available,
                                "exploit_count": exploit_count,
                                "exploit_sources": exploit_sources,
                                "exploit_references": exploit_references,
                                "source": "vulners"
                            }

                            return ProviderResult(
                                success=True,
                                data=result,
                                fetched_at=datetime.now(),
                                source="vulners"
                            )
                        else:
                            # No exploits found (not an error)
                            result = {
                                "public_exploit_available": False,
                                "metasploit_available": False,
                                "exploit_count": 0,
                                "exploit_sources": [],
                                "exploit_references": [],
                                "source": "vulners"
                            }

                            return ProviderResult(
                                success=True,
                                data=result,
                                fetched_at=datetime.now(),
                                source="vulners"
                            )

                    elif resp.status == 400:
                        # Invalid CVE ID
                        return ProviderResult(
                            success=False,
                            error=f"Invalid CVE ID format: {cve_id}",
                            source="vulners"
                        )
                    elif resp.status == 401:
                        return ProviderResult(
                            success=False,
                            error="Vulners API authentication failed (invalid key)",
                            source="vulners"
                        )
                    else:
                        return ProviderResult(
                            success=False,
                            error=f"Vulners API returned {resp.status}",
                            source="vulners"
                        )

        except asyncio.TimeoutError:
            return ProviderResult(
                success=False,
                error=f"Vulners request timeout after {self.timeout}s",
                source="vulners"
            )
        except Exception as e:
            return ProviderResult(
                success=False,
                error=f"Vulners fetch error: {str(e)}",
                source="vulners"
            )
