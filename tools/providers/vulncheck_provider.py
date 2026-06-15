"""
tools/providers/vulncheck_provider.py - VulnCheck provider

VulnCheck API: https://api.vulncheck.com/
Capabilities:
- Exploit intelligence (public exploits, maturity, metasploit)
- Fallback data (CVSS, CWE, CPE when NVD missing)
- Ransomware activity tracking
"""

import asyncio
import aiohttp
from datetime import datetime
from config import VULNCHECK_API_KEY
from .base import BaseProvider, ProviderResult


class VulnCheckProvider(BaseProvider):
    """
    VulnCheck exploit intelligence provider.

    Dual role:
    1. PRIMARY: Provide exploit intelligence
       - public_exploit_available
       - metasploit_available
       - exploit_maturity
       - ransomware_activity
       - threat_actors
       - botnet_activity

    2. SECONDARY: Fallback for missing NVD data
       - CVSS (if NVD missing)
       - CWE (if NVD missing)
       - CPE (if NVD missing)
       - KEV data (if CISA missing)
    """

    def __init__(self, api_key: str = None, timeout: int = 15):
        """Initialize VulnCheck provider"""
        super().__init__(name="vulncheck", timeout=timeout)
        self.api_key = api_key or VULNCHECK_API_KEY
        self.base_url = "https://api.vulncheck.com/v3"

    async def validate_connection(self) -> bool:
        """Validate VulnCheck API is accessible"""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"API-Key": self.api_key} if self.api_key else {}
                async with session.get(
                    f"{self.base_url}/index",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    return resp.status in (200, 401, 403)  # Any response = API accessible
        except Exception:
            return False

    async def _fetch_impl(self, cve_id: str) -> ProviderResult:
        """
        Fetch VulnCheck data for CVE.

        Returns: exploit intelligence + fallback data (CVSS, CWE, CPE, KEV)
        """
        if not self.api_key:
            return ProviderResult(
                success=False,
                error="VulnCheck API key not configured",
                source="vulncheck"
            )

        try:
            async with aiohttp.ClientSession() as session:
                headers = {"API-Key": self.api_key}
                async with session.get(
                    f"{self.base_url}/index?cve={cve_id}",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()

                        # VulnCheck API returns data in a specific format
                        # Extract what we need: exploit intelligence + fallback data
                        if data.get("data") and len(data["data"]) > 0:
                            vc_data = data["data"][0]

                            result = {
                                # Exploit intelligence (primary role)
                                "public_exploit_available": vc_data.get("public_exploit", False),
                                "metasploit_available": vc_data.get("metasploit_available", False),
                                "exploit_maturity": vc_data.get("exploit_maturity", "UNPROVEN"),
                                "ransomware_activity": vc_data.get("ransomware_activity", False),
                                "threat_actors": vc_data.get("threat_actors", []),
                                "botnet_activity": vc_data.get("botnet_activity", False),

                                # Fallback data for NVD gaps (secondary role)
                                "fallback_cvss_score": vc_data.get("cvss_score"),
                                "fallback_cwe_ids": vc_data.get("cwe_ids", []),
                                "fallback_cpe_entries": vc_data.get("cpe", []),

                                # Fallback KEV data (if CISA not available)
                                "fallback_kev_listed": vc_data.get("known_exploited_vulnerability", False),
                                "fallback_kev_date_added": vc_data.get("date_exploited"),
                                "fallback_kev_due_date": vc_data.get("due_date"),

                                "source": "vulncheck"
                            }

                            return ProviderResult(
                                success=True,
                                data=result,
                                fetched_at=datetime.now(),
                                source="vulncheck"
                            )
                        else:
                            return ProviderResult(
                                success=False,
                                error=f"No VulnCheck data found for {cve_id}",
                                source="vulncheck"
                            )
                    elif resp.status == 401:
                        return ProviderResult(
                            success=False,
                            error="VulnCheck API authentication failed (invalid key)",
                            source="vulncheck"
                        )
                    elif resp.status == 403:
                        return ProviderResult(
                            success=False,
                            error="VulnCheck API access denied",
                            source="vulncheck"
                        )
                    else:
                        return ProviderResult(
                            success=False,
                            error=f"VulnCheck API returned {resp.status}",
                            source="vulncheck"
                        )
        except asyncio.TimeoutError:
            return ProviderResult(
                success=False,
                error=f"VulnCheck request timeout after {self.timeout}s",
                source="vulncheck"
            )
        except Exception as e:
            return ProviderResult(
                success=False,
                error=f"VulnCheck fetch error: {str(e)}",
                source="vulncheck"
            )
