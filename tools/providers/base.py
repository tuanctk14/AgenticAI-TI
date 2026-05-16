"""
tools/providers/base.py - Abstract provider interface for vulnerability intelligence

Defines contract for all enrichment providers:
- Async fetch operations
- Standardized error handling
- Timeout isolation
- Connection validation
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Optional, Any
from dataclasses import dataclass, asdict
import asyncio


@dataclass
class ProviderResult:
    """Standardized result from any provider"""
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    fetched_at: Optional[datetime] = None
    source: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dict, serializing datetime"""
        result = asdict(self)
        if self.fetched_at:
            result["fetched_at"] = self.fetched_at.isoformat()
        return result


class BaseProvider(ABC):
    """
    Abstract base for vulnerability intelligence providers.

    Responsibilities:
    - Fetch data from external source (API, file, etc.)
    - Handle errors gracefully (soft-fail for enrichment providers)
    - Provide standard interface for orchestrator
    - Support timeout isolation
    """

    def __init__(
        self,
        name: str,
        enabled: bool = True,
        timeout: int = 15,
    ):
        """
        Initialize provider.

        Args:
            name: Provider identifier (nvd, epss, kev, vulncheck, etc.)
            enabled: Whether provider is active
            timeout: Request timeout in seconds
        """
        self.name = name
        self.enabled = enabled
        self.timeout = timeout

    async def fetch(self, cve_id: str) -> ProviderResult:
        """
        Fetch vulnerability data for a CVE.

        Must be implemented by subclasses.
        Should return ProviderResult even on error (soft-fail).

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)

        Returns:
            ProviderResult with success/data/error
        """
        if not self.enabled:
            return ProviderResult(
                success=False,
                error=f"{self.name} provider is disabled",
                source=self.name
            )

        return await self._fetch_impl(cve_id)

    @abstractmethod
    async def _fetch_impl(self, cve_id: str) -> ProviderResult:
        """Implementation of fetch logic - override in subclass"""
        raise NotImplementedError

    async def validate_connection(self) -> bool:
        """
        Validate provider is accessible.

        Optional - override if provider needs connection check.
        Used during initialization to verify API keys, connectivity, etc.
        """
        return True

    async def fetch_with_timeout(self, cve_id: str) -> ProviderResult:
        """
        Fetch with timeout isolation.

        If provider times out, other providers continue.
        Timeout is provider-specific (configured in __init__).
        """
        try:
            result = await asyncio.wait_for(
                self.fetch(cve_id),
                timeout=self.timeout
            )
            return result
        except asyncio.TimeoutError:
            return ProviderResult(
                success=False,
                error=f"Timeout after {self.timeout}s",
                source=self.name
            )
        except Exception as e:
            return ProviderResult(
                success=False,
                error=str(e),
                source=self.name
            )
