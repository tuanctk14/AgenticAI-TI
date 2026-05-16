"""
tools/providers/ - Vulnerability intelligence provider abstraction layer

Modular provider system supporting:
- NVD (canonical CVE metadata)
- EPSS (exploitation probability)
- KEV (CISA Known Exploited Vulnerabilities)
- VulnCheck (exploit intelligence + data gap filling)
- Future: GreyNoise, Shodan, OpenCVE, Tenable, etc.

Each provider is independent and can fail without breaking pipeline.
"""

from .base import BaseProvider, ProviderResult
from .nvd_provider import NVDProvider
from .epss_provider import EPSSProvider
from .kev_provider import KEVProvider
from .vulncheck_provider import VulnCheckProvider

__all__ = [
    "BaseProvider",
    "ProviderResult",
    "NVDProvider",
    "EPSSProvider",
    "KEVProvider",
    "VulnCheckProvider",
]
