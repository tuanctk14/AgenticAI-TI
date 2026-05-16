"""
tools/enrichment/ - CVE enrichment orchestration and schema

Components:
- schema.py: Unified CVE data model
- cache.py: Caching abstraction (SQLite, Redis)
- orchestrator.py: Async multi-provider coordination
"""

from .schema import (
    UnifiedCVE,
    CVEMetadata,
    EPSSData,
    KEVData,
    VulnCheckData,
    DataQuality,
)
from .cache import CacheProvider, SQLiteCacheProvider
from .orchestrator import EnrichmentOrchestrator

__all__ = [
    "UnifiedCVE",
    "CVEMetadata",
    "EPSSData",
    "KEVData",
    "VulnCheckData",
    "DataQuality",
    "CacheProvider",
    "SQLiteCacheProvider",
    "EnrichmentOrchestrator",
]
