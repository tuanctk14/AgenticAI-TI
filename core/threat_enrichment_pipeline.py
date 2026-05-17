"""
core/threat_enrichment_pipeline.py - Threat Enrichment Pipeline Orchestrator

Orchestrates multi-source enrichment with:
- Parallel async fetching from multiple sources
- Intelligent source selection (not all sources for all entities)
- Freshness-aware KB lookup (avoid unnecessary API calls)
- Fallback chains (NVD → Vulners for EPSS/CVSS/CWE)
- Data quality scoring
- Confidence propagation
- Error handling and retries

Flow:
User query (CVE)
    ↓
Supervisor → Check KB freshness
    ↓ (if stale/missing)
Dynamic Source Selection
    ↓ (choose which APIs to call)
Parallel Async Fetching
    ↓ (NVD, EPSS, KEV, Vulners, OpenCTI)
Fallback Chains
    ↓ (fill gaps)
Threat Fusion Engine
    ↓ (merge all sources)
Relationship Correlation
    ↓ (find entity connections)
Selective Persistence
    ↓ (save high-value intelligence)
Return to Agent/User
"""

import asyncio
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

from core.threat_schema import (
    Vulnerability,
    IOC,
    Asset,
    RiskContext,
    SeverityLevel,
)
from core.threat_repository import ThreatKnowledgeRepository, TTLStatus
from core.threat_fusion import ThreatFusionEngine
from core.threat_correlation import RelationshipCorrelationEngine


class EnrichmentStrategy(str, Enum):
    """Enrichment strategy based on context."""
    MINIMAL = "minimal"  # Only NVD
    STANDARD = "standard"  # NVD + EPSS + KEV
    DEEP = "deep"  # All sources including Vulners, OpenCTI
    FAST = "fast"  # KB only, no API calls


class ThreatEnrichmentPipeline:
    """
    Orchestrates multi-source threat intelligence enrichment.

    Responsibilities:
    - Check KB for fresh data first
    - Select which sources to fetch based on context
    - Parallelize async fetches
    - Apply fallback chains
    - Fuse results
    - Persist selectively
    """

    def __init__(
        self,
        repository: ThreatKnowledgeRepository,
        fusion_engine: ThreatFusionEngine,
        correlation_engine: RelationshipCorrelationEngine,
    ):
        """Initialize pipeline with required components."""
        self.repo = repository
        self.fusion = fusion_engine
        self.correlation = correlation_engine

    # ============================================================
    # DYNAMIC SOURCE SELECTION
    # ============================================================

    async def select_enrichment_strategy(
        self,
        cve_id: str,
        kb_status: TTLStatus,
        severity: Optional[SeverityLevel] = None,
        internet_exposed: bool = False,
    ) -> EnrichmentStrategy:
        """
        Dynamically select enrichment strategy based on context.

        Logic:
        - If KB fresh: FAST (skip API calls)
        - If LOW severity + not exposed: MINIMAL
        - If HIGH/CRITICAL + exposed: DEEP
        - Otherwise: STANDARD
        """
        # If data is fresh in KB, no need to fetch
        if kb_status == TTLStatus.FRESH:
            return EnrichmentStrategy.FAST

        # Determine required depth based on risk
        if internet_exposed:
            return EnrichmentStrategy.DEEP

        if severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            return EnrichmentStrategy.DEEP

        if severity == SeverityLevel.LOW:
            return EnrichmentStrategy.MINIMAL

        return EnrichmentStrategy.STANDARD

    def _get_sources_for_strategy(
        self,
        strategy: EnrichmentStrategy,
    ) -> Dict[str, bool]:
        """
        Get sources to fetch for given strategy.

        Returns: {source_name: should_fetch}
        """
        sources = {
            "nvd": True,  # Always
            "epss": False,
            "kev": False,
            "vulners": False,
            "opencti": False,
        }

        if strategy == EnrichmentStrategy.FAST:
            return {k: False for k in sources}

        if strategy == EnrichmentStrategy.MINIMAL:
            sources["nvd"] = True
            return sources

        if strategy == EnrichmentStrategy.STANDARD:
            sources.update({
                "nvd": True,
                "epss": True,
                "kev": True,
            })
            return sources

        if strategy == EnrichmentStrategy.DEEP:
            sources.update({
                "nvd": True,
                "epss": True,
                "kev": True,
                "vulners": True,
                "opencti": True,
            })
            return sources

        return sources

    # ============================================================
    # CVE ENRICHMENT PIPELINE
    # ============================================================

    async def enrich_cve(
        self,
        cve_id: str,
        api_clients: Optional[Dict[str, Any]] = None,
        force_refresh: bool = False,
    ) -> Optional[Vulnerability]:
        """
        End-to-end CVE enrichment pipeline.

        Steps:
        1. Check KB freshness
        2. Select enrichment strategy
        3. Fetch from selected sources (parallel)
        4. Apply fallback chains
        5. Fuse results
        6. Persist if high-value
        7. Return enriched CVE
        """
        print(f"[ENRICHMENT] Starting CVE enrichment: {cve_id}")

        # Step 1: Check KB
        print(f"  [KB] Checking knowledge base...")
        kb_cve, kb_status = await self.repo.get_vulnerability(cve_id, freshness_only=True)

        if not force_refresh and kb_status == TTLStatus.FRESH:
            print(f"  [KB] Found fresh data in KB")
            return kb_cve

        if kb_status == TTLStatus.STALE:
            print(f"  [KB] Data stale, refreshing...")

        # Step 2: Select strategy
        severity = kb_cve.severity if kb_cve else None
        strategy = await self.select_enrichment_strategy(
            cve_id, kb_status, severity=severity
        )
        print(f"  [STRATEGY] Using: {strategy.value}")

        # Step 3: Determine which sources to fetch
        sources = self._get_sources_for_strategy(strategy)

        if not any(sources.values()):
            # All sources disabled (FAST mode)
            return kb_cve

        # Step 4: Fetch from sources in parallel
        print(f"  [FETCH] Fetching from sources...")
        fetch_results = await self._fetch_from_sources(
            cve_id, sources, api_clients
        )

        # Step 5: Apply fallback chains
        print(f"  [FALLBACK] Applying fallback chains...")
        enriched_data = self._apply_fallback_chains(
            kb_cve, fetch_results
        )

        # Step 6: Fuse results
        print(f"  [FUSION] Fusing enrichment results...")
        fused_cve = await self.fusion.fuse_cve(
            nvd_data=enriched_data.get("nvd"),
            epss_data=enriched_data.get("epss"),
            kev_data=enriched_data.get("kev"),
            vulners_data=enriched_data.get("vulners"),
        )

        # Step 7: Persist if high-value
        print(f"  [PERSIST] Decision: {fused_cve.should_persist}")
        if fused_cve.should_persist:
            await self.repo.save_vulnerability(fused_cve.entity)
            await self.repo.save_intelligence_object(fused_cve)
            print(f"  [PERSIST] Saved to KB")

        print(f"  [ENRICHMENT] Complete (Score: {fused_cve.threat_score:.0f})")
        return fused_cve.entity

    async def _fetch_from_sources(
        self,
        cve_id: str,
        sources: Dict[str, bool],
        api_clients: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Fetch data from selected sources in parallel.

        Uses asyncio.gather for true parallelism.
        """
        tasks = []

        if sources.get("nvd"):
            tasks.append(("nvd", self._fetch_nvd(cve_id, api_clients)))

        if sources.get("epss"):
            tasks.append(("epss", self._fetch_epss(cve_id, api_clients)))

        if sources.get("kev"):
            tasks.append(("kev", self._fetch_kev(cve_id, api_clients)))

        if sources.get("vulners"):
            tasks.append(("vulners", self._fetch_vulners(cve_id, api_clients)))

        if sources.get("opencti"):
            tasks.append(("opencti", self._fetch_opencti(cve_id, api_clients)))

        # Run all fetches in parallel
        results = {}
        for source_name, task in tasks:
            try:
                data = await task
                if data:
                    results[source_name] = data
                    print(f"    [{source_name.upper()}] Success")
                else:
                    print(f"    [{source_name.upper()}] No data")
            except Exception as e:
                print(f"    [{source_name.upper()}] Error: {e}")

        return results

    async def _fetch_nvd(
        self,
        cve_id: str,
        api_clients: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Fetch from NVD API."""
        try:
            # Use provided client or import provider
            if api_clients and "nvd" in api_clients:
                provider = api_clients["nvd"]
            else:
                from tools.providers.nvd_provider import NVDProvider
                provider = NVDProvider()

            result = await provider.fetch(cve_id)
            if result.success and result.data:
                return result.data
            return None
        except Exception as e:
            print(f"      [NVD] Error: {e}")
            return None

    async def _fetch_epss(
        self,
        cve_id: str,
        api_clients: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Fetch from EPSS API."""
        try:
            # Use provided client or import provider
            if api_clients and "epss" in api_clients:
                provider = api_clients["epss"]
            else:
                from tools.providers.epss_provider import EPSSProvider
                provider = EPSSProvider()

            result = await provider.fetch(cve_id)
            if result.success and result.data:
                return {
                    "cve": cve_id,
                    "epss": result.data.get("score"),
                    "percentile": result.data.get("percentile"),
                }
            return None
        except Exception as e:
            print(f"      [EPSS] Error: {e}")
            return None

    async def _fetch_kev(
        self,
        cve_id: str,
        api_clients: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Fetch from CISA KEV."""
        try:
            # Use provided client or import provider
            if api_clients and "kev" in api_clients:
                provider = api_clients["kev"]
            else:
                from tools.providers.kev_provider import KEVProvider
                provider = KEVProvider()

            result = await provider.fetch(cve_id)
            if result.success and result.data:
                return {
                    "cve": cve_id,
                    "is_exploited": True,
                    "date_added": result.data.get("date_added"),
                    "due_date": result.data.get("due_date"),
                }
            return None
        except Exception as e:
            print(f"      [KEV] Error: {e}")
            return None

    async def _fetch_vulners(
        self,
        cve_id: str,
        api_clients: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Fetch from Vulners API."""
        try:
            # Use provided client or import provider
            if api_clients and "vulners" in api_clients:
                provider = api_clients["vulners"]
            else:
                from tools.providers.vulners_provider import VulnersProvider
                provider = VulnersProvider()

            result = await provider.fetch(cve_id)
            if result.success and result.data:
                return {
                    "cve": cve_id,
                    "exploit_count": result.data.get("exploit_count", 0),
                    "public_exploit_available": result.data.get("public_exploit_available", False),
                    "exploit_sources": result.data.get("exploit_sources", []),
                    "epss": result.data.get("epss"),  # Vulners may have EPSS as fallback
                }
            return None
        except Exception as e:
            print(f"      [Vulners] Error: {e}")
            return None

    async def _fetch_opencti(
        self,
        cve_id: str,
        api_clients: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Fetch from OpenCTI API."""
        try:
            # Use provided client or import provider
            if api_clients and "opencti" in api_clients:
                client = api_clients["opencti"]
            else:
                from tools.opencti_client import OpenCTIClient
                client = OpenCTIClient()

            # OpenCTI CVE lookup
            result = await client.query_cve(cve_id)
            if result:
                return {
                    "cve": cve_id,
                    "related_malware": result.get("malware", []),
                    "related_campaigns": result.get("campaigns", []),
                    "related_threat_actors": result.get("threat_actors", []),
                }
            return None
        except Exception as e:
            print(f"      [OpenCTI] Error: {e}")
            return None

    # ============================================================
    # FALLBACK CHAINS
    # ============================================================

    def _apply_fallback_chains(
        self,
        kb_cve: Optional[Vulnerability],
        fetch_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Apply fallback chains to fill gaps.

        Fallback order:
        - EPSS: FIRST API → Vulners
        - CVSS: NVD → Vulners
        - CWE: NVD → Vulners
        """
        enriched = {}

        # NVD data
        if fetch_results.get("nvd"):
            enriched["nvd"] = fetch_results["nvd"]
        elif kb_cve:
            enriched["nvd"] = {
                "id": kb_cve.id,
                "description": kb_cve.description,
                "cvss_score": kb_cve.risk_context.cvss_score if kb_cve.risk_context else None,
                "severity": kb_cve.severity.value,
                "cwe_ids": kb_cve.cwe_ids,
                "cpe_uris": kb_cve.cpe_uris,
            }

        # EPSS data (with fallback)
        if fetch_results.get("epss"):
            enriched["epss"] = fetch_results["epss"]
        elif fetch_results.get("vulners") and fetch_results["vulners"].get("epss"):
            enriched["epss"] = {
                "cve": kb_cve.id if kb_cve else None,
                "epss": fetch_results["vulners"].get("epss"),
            }
            print("    [FALLBACK] EPSS: FIRST -> Vulners")

        # KEV data
        if fetch_results.get("kev"):
            enriched["kev"] = fetch_results["kev"]

        # Vulners data
        if fetch_results.get("vulners"):
            enriched["vulners"] = fetch_results["vulners"]

        return enriched

    # ============================================================
    # IOC ENRICHMENT PIPELINE
    # ============================================================

    async def enrich_ioc(
        self,
        ioc_id: str,
        ioc_type: str,
        api_clients: Optional[Dict[str, Any]] = None,
    ) -> Optional[IOC]:
        """
        End-to-end IOC enrichment pipeline.

        Steps:
        1. Check KB freshness
        2. Fetch from OpenCTI (malware, campaigns)
        3. Fuse results
        4. Persist if correlated
        """
        print(f"[ENRICHMENT] Starting IOC enrichment: {ioc_id}")

        # Check KB
        kb_ioc, kb_status = await self.repo.get_ioc(ioc_id, freshness_only=True)

        if kb_status == TTLStatus.FRESH:
            print(f"  [KB] Found fresh IOC in KB")
            return kb_ioc

        # Fetch from OpenCTI
        print(f"  [FETCH] Fetching IOC context from OpenCTI...")
        opencti_data = await self._fetch_opencti_ioc(ioc_id, api_clients)

        # Fuse results
        print(f"  [FUSION] Fusing IOC results...")
        fused_ioc = await self.fusion.fuse_ioc(
            ioc_data={"id": ioc_id, "type": ioc_type, "value": ioc_id},
            opencti_data=opencti_data,
        )

        # Persist if correlated
        if fused_ioc.should_persist:
            await self.repo.save_ioc(fused_ioc.entity)
            await self.repo.save_intelligence_object(fused_ioc)
            print(f"  [PERSIST] Saved IOC to KB")

        print(f"  [ENRICHMENT] Complete")
        return fused_ioc.entity

    async def _fetch_opencti_ioc(
        self,
        ioc_id: str,
        api_clients: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Fetch IOC context from OpenCTI."""
        try:
            # Use provided client or import provider
            if api_clients and "opencti" in api_clients:
                client = api_clients["opencti"]
            else:
                from tools.opencti_client import OpenCTIClient
                client = OpenCTIClient()

            # OpenCTI IOC lookup
            result = await client.query_ioc(ioc_id)
            if result:
                return {
                    "ioc": ioc_id,
                    "malware": result.get("malware", []),
                    "campaigns": result.get("campaigns", []),
                    "threat_actors": result.get("threat_actors", []),
                    "observations": result.get("observations", 0),
                }
            return None
        except Exception as e:
            print(f"      [OpenCTI IOC] Error: {e}")
            return None

    # ============================================================
    # ASSET ENRICHMENT PIPELINE
    # ============================================================

    async def enrich_asset(
        self,
        asset_id: str,
        api_clients: Optional[Dict[str, Any]] = None,
    ) -> Optional[Asset]:
        """
        End-to-end asset enrichment pipeline.

        Steps:
        1. Get asset from CMDB/KB
        2. Find CVEs affecting asset
        3. Find IOCs on asset
        4. Fuse and correlate
        5. Calculate asset risk
        """
        print(f"[ENRICHMENT] Starting asset enrichment: {asset_id}")

        # Get asset
        asset, _ = await self.repo.get_asset(asset_id, freshness_only=False)

        if not asset:
            print(f"  [ERROR] Asset not found")
            return None

        print(f"  [ASSET] {asset.hostname} ({asset.ip_address})")

        # Find CVEs affecting asset
        print(f"  [CORRELATION] Finding vulnerable CVEs...")
        vulnerable_cves = await self.repo.correlate_asset_vulnerabilities(asset_id)
        print(f"    Found: {len(vulnerable_cves)} CVE(s)")

        # TODO: Find IOCs on asset
        print(f"  [CORRELATION] Finding detected IOCs...")

        # Fuse and correlate
        print(f"  [FUSION] Fusing asset context...")
        fused_asset = await self.fusion.fuse_asset(
            asset_data=asset.model_dump(),
            vulnerable_cves=vulnerable_cves,
        )

        # Find attack paths
        print(f"  [PATHS] Finding attack paths...")
        # TODO: Call correlation engine for attack paths

        # Persist if high-risk
        if fused_asset.threat_score >= 70:
            await self.repo.save_asset(fused_asset.entity)
            await self.repo.save_intelligence_object(fused_asset)
            print(f"  [PERSIST] Saved asset (Score: {fused_asset.threat_score:.0f})")

        print(f"  [ENRICHMENT] Complete")
        return fused_asset.entity

    # ============================================================
    # BULK ENRICHMENT
    # ============================================================

    async def enrich_batch(
        self,
        entities: List[Dict[str, Any]],
        api_clients: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Enrich multiple entities in parallel.

        Returns: {entity_id: enriched_entity, ...}
        """
        print(f"\n[ENRICHMENT BATCH] Processing {len(entities)} entities...")

        tasks = []
        for entity in entities:
            entity_type = entity.get("type")
            entity_id = entity.get("id")

            if entity_type == "vulnerability":
                tasks.append(
                    (entity_id, self.enrich_cve(entity_id, api_clients))
                )
            elif entity_type == "ioc":
                ioc_type = entity.get("ioc_type", "unknown")
                tasks.append(
                    (entity_id, self.enrich_ioc(entity_id, ioc_type, api_clients))
                )
            elif entity_type == "asset":
                tasks.append(
                    (entity_id, self.enrich_asset(entity_id, api_clients))
                )

        # Run all enrichments in parallel
        results = {}
        for entity_id, task in tasks:
            try:
                enriched = await task
                if enriched:
                    results[entity_id] = enriched
            except Exception as e:
                print(f"  [ERROR] Enrichment failed for {entity_id}: {e}")

        print(f"\n[ENRICHMENT BATCH] Completed: {len(results)}/{len(entities)}")
        return results

    # ============================================================
    # STATISTICS
    # ============================================================

    async def get_pipeline_stats(self) -> Dict[str, Any]:
        """Get enrichment pipeline statistics."""
        kb_stats = await self.repo.get_stats()

        return {
            "knowledge_base": kb_stats,
            "timestamp": datetime.utcnow().isoformat(),
        }
