"""
core/graph_intelligence_layer.py - Graph Intelligence Layer

Implements advanced graph analytics for threat intelligence:
- SPARQL-like query interface (find_attack_paths_to, find_assets_affected_by)
- Community detection (identify threat actor infrastructure clusters)
- Threat actor profiling (build profiles from tactics, techniques, procedures)
- Advanced analytics (trend analysis, risk scoring, anomaly detection)
- Transitive reasoning (multi-hop relationship inference)

Foundation for Phase 5 Neo4j migration with zero agent code changes.
"""

from typing import Optional, List, Dict, Set, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta

from core.threat_schema import (
    Vulnerability,
    IOC,
    Asset,
    Relationship,
    RelationshipType,
    EntityType,
)
from core.threat_repository import ThreatKnowledgeRepository


class QueryType(str, Enum):
    """Types of SPARQL-like queries."""
    FIND_ATTACK_PATHS = "find_attack_paths"
    FIND_AFFECTED_ASSETS = "find_affected_assets"
    FIND_THREAT_PATHS = "find_threat_paths"
    FIND_REACHABLE = "find_reachable"
    FIND_CRITICAL_PATHS = "find_critical_paths"
    FIND_COMMUNITIES = "find_communities"


@dataclass
class QueryResult:
    """Result of a SPARQL-like query."""
    query_type: QueryType
    entities: List[str]  # Entity IDs matching query
    relationships: List[Tuple[str, str, str]]  # (source, type, target)
    paths: List[List[str]]  # Paths through graph
    execution_time_ms: float
    result_count: int


@dataclass
class ThreatCommunity:
    """Community of related threat infrastructure."""
    community_id: str
    members: List[str]  # Entity IDs (IOCs, assets, campaigns)
    size: int
    density: float  # 0-1, how interconnected
    centrality: Dict[str, float]  # {entity_id: score}
    threat_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    attributed_actors: List[str]  # Known threat actor names
    confidence: float  # 0-1


@dataclass
class ThreatActorProfile:
    """Profile of a threat actor."""
    actor_id: str
    name: str
    aliases: List[str]
    attributed_campaigns: List[str]
    preferred_exploits: List[str]  # CVE IDs
    preferred_targets: List[str]  # Asset types/sectors
    tactics: List[str]  # MITRE ATT&CK tactics
    techniques: List[str]  # MITRE ATT&CK techniques
    known_iocs: List[str]  # Associated IOCs
    first_seen: datetime
    last_seen: datetime
    activity_trend: str  # INCREASING, STABLE, DECREASING
    risk_score: float  # 0-100


@dataclass
class AnomalyAlert:
    """Detected anomaly in the threat graph."""
    anomaly_type: str  # NEW_ATTACK_PATTERN, SUDDEN_SPIKE, etc.
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float  # 0-1
    description: str
    affected_entities: List[str]
    recommended_actions: List[str]
    detected_at: datetime


class GraphIntelligenceLayer:
    """
    Implements advanced graph intelligence capabilities.

    Key methods:
    - SPARQL-like queries (find_attack_paths_to, find_assets_affected_by)
    - Community detection (identify infrastructure clusters)
    - Threat actor profiling (build actor profiles from TTPs)
    - Trend analysis (vulnerability, exploit, campaign trends)
    - Anomaly detection (unusual patterns in graph)
    - Risk scoring (comprehensive threat assessment)
    """

    def __init__(self, repository: ThreatKnowledgeRepository):
        """Initialize graph intelligence layer."""
        self.repo = repository
        self._query_cache = {}

    # ============================================================
    # SPARQL-LIKE QUERY INTERFACE
    # ============================================================

    async def find_attack_paths_to(
        self,
        target_asset: str,
        min_severity: str = "MEDIUM",
        max_depth: int = 4,
    ) -> QueryResult:
        """
        Find all attack paths to target asset.

        SPARQL equivalent:
        SELECT paths WHERE
          ?exposed rdf:type Asset ;
            vulnerable_to ?cve ;
            reachable_to* ?target .
          ?target rdf:type Asset ;
            vulnerable_to ?cve .
          ?cve cvss_score >= min_severity .

        Args:
            target_asset: Target asset ID
            min_severity: Minimum CVSS severity (LOW, MEDIUM, HIGH, CRITICAL)
            max_depth: Maximum hops in path

        Returns:
            QueryResult with all attack paths to target
        """
        print(f"[QUERY] Finding attack paths to {target_asset}...")

        start_time = datetime.utcnow()
        paths = []
        entities = set()
        relationships = []

        # Find all exposed assets
        exposed_assets = await self._find_exposed_assets()

        # For each exposed asset, find paths to target
        for exposed_id in exposed_assets:
            asset_paths = await self._find_paths_between(
                exposed_id, target_asset, max_depth
            )
            for path in asset_paths:
                # Filter by severity
                if await self._path_has_min_severity(path, min_severity):
                    paths.append(path)
                    entities.update(path)

        execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

        return QueryResult(
            query_type=QueryType.FIND_ATTACK_PATHS,
            entities=list(entities),
            relationships=relationships,
            paths=paths,
            execution_time_ms=execution_time,
            result_count=len(paths),
        )

    async def find_assets_affected_by(
        self,
        campaign_id: str,
    ) -> QueryResult:
        """
        Find all assets affected by campaign.

        SPARQL equivalent:
        SELECT assets WHERE
          ?campaign exploits ?cve .
          ?asset vulnerable_to ?cve .

        Args:
            campaign_id: Campaign identifier

        Returns:
            QueryResult with affected assets
        """
        print(f"[QUERY] Finding assets affected by campaign {campaign_id}...")

        start_time = datetime.utcnow()
        affected_assets = []
        entities = set()

        # TODO: Implement campaign -> CVE -> asset traversal
        # For now, return empty result

        execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

        return QueryResult(
            query_type=QueryType.FIND_AFFECTED_ASSETS,
            entities=list(entities),
            relationships=[],
            paths=[],
            execution_time_ms=execution_time,
            result_count=len(affected_assets),
        )

    async def find_reachable(
        self,
        source_asset: str,
        max_depth: int = 3,
    ) -> QueryResult:
        """
        Find all assets reachable from source asset.

        SPARQL equivalent:
        SELECT reachable_assets WHERE
          ?source reachable_to* ?target .

        Args:
            source_asset: Starting asset ID
            max_depth: Maximum hops

        Returns:
            QueryResult with reachable assets
        """
        print(f"[QUERY] Finding reachable assets from {source_asset}...")

        start_time = datetime.utcnow()
        reachable = await self._find_reachable_assets(source_asset, max_depth)

        execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

        return QueryResult(
            query_type=QueryType.FIND_REACHABLE,
            entities=reachable,
            relationships=[],
            paths=[],
            execution_time_ms=execution_time,
            result_count=len(reachable),
        )

    async def find_critical_paths(
        self,
        min_risk_score: float = 80.0,
    ) -> QueryResult:
        """
        Find paths with critical risk score.

        SPARQL equivalent:
        SELECT paths WHERE
          ?source reachable_to* ?target .
          ?target vulnerable_to ?cve .
          ?cve cvss_score >= 80 .

        Args:
            min_risk_score: Minimum risk score (0-100)

        Returns:
            QueryResult with critical paths
        """
        print(f"[QUERY] Finding critical paths (min_score={min_risk_score})...")

        start_time = datetime.utcnow()
        critical_paths = []

        # TODO: Implement critical path search

        execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

        return QueryResult(
            query_type=QueryType.FIND_CRITICAL_PATHS,
            entities=[],
            relationships=[],
            paths=critical_paths,
            execution_time_ms=execution_time,
            result_count=len(critical_paths),
        )

    # ============================================================
    # QUERY HELPERS
    # ============================================================

    async def _find_exposed_assets(self) -> List[str]:
        """Find all internet-exposed assets."""
        # TODO: Query repository for internet_facing=True
        return []

    async def _find_paths_between(
        self,
        source: str,
        target: str,
        max_depth: int,
    ) -> List[List[str]]:
        """Find all paths between source and target using BFS."""
        paths = []
        visited = set()
        queue = [(source, [source])]

        while queue:
            current, path = queue.pop(0)

            if current == target:
                paths.append(path)
                continue

            if current in visited or len(path) >= max_depth:
                continue

            visited.add(current)

            # Find next entities in path
            rels = await self.repo.get_relationships(current)
            for rel in rels:
                if rel.target_id not in visited:
                    queue.append((rel.target_id, path + [rel.target_id]))

        return paths

    async def _path_has_min_severity(
        self,
        path: List[str],
        min_severity: str,
    ) -> bool:
        """Check if path contains CVE with min severity."""
        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        min_level = severity_order.get(min_severity, 0)

        for entity_id in path:
            if entity_id.startswith("CVE-"):
                cve, _ = await self.repo.get_vulnerability(entity_id)
                if cve and cve.severity:
                    entity_level = severity_order.get(cve.severity.value, 0)
                    if entity_level >= min_level:
                        return True
        return False

    async def _find_reachable_assets(
        self,
        asset_id: str,
        max_depth: int,
        visited: Optional[Set[str]] = None,
    ) -> List[str]:
        """BFS to find all reachable assets."""
        if visited is None:
            visited = set()

        if asset_id in visited or max_depth <= 0:
            return []

        visited.add(asset_id)
        reachable = [asset_id]

        rels = await self.repo.get_relationships(asset_id)
        for rel in rels:
            if rel.relationship_type == RelationshipType.REACHABLE_TO:
                further = await self._find_reachable_assets(
                    rel.target_id, max_depth - 1, visited
                )
                reachable.extend(further)

        return reachable

    # ============================================================
    # COMMUNITY DETECTION
    # ============================================================

    async def detect_communities(
        self,
        min_community_size: int = 3,
    ) -> List[ThreatCommunity]:
        """
        Detect communities of related entities using clustering.

        Communities represent:
        - Threat actor infrastructure (linked IOCs, C2 servers from OpenCTI)
        - Vulnerability clusters (shared vendor, shared technique from NVD)
        - Campaign ecosystems (related campaigns, shared targets from MITRE)

        Args:
            min_community_size: Minimum entities per community

        Returns:
            List of ThreatCommunity objects
        """
        print(f"[COMMUNITY] Detecting communities (min_size={min_community_size})...")

        communities = []

        # 1. Query KB for all relationships
        stats = await self.repo.get_stats()
        if stats.get("relationships", 0) < min_community_size:
            print(f"  [INFO] Insufficient relationships for community detection")
            return communities

        # 2. Build adjacency representation from repository relationships
        # For each relationship type, identify clusters:
        # - IOC-Malware links -> threat actor infrastructure
        # - CVE-CVE links -> vulnerability clusters
        # - Campaign-CVE links -> campaign ecosystems

        # 3. Apply basic community detection:
        # For now, use simple connected component analysis
        # TODO: Replace with Louvain algorithm for better modularity

        print(f"  [COMMUNITIES] Found {len(communities)} communities")
        return communities

    def _calculate_modularity(
        self,
        adjacency_matrix: List[List[int]],
        communities: List[List[str]],
    ) -> float:
        """Calculate modularity score for community partition."""
        # TODO: Implement modularity calculation
        # Q = (1/2m) * sum((A_ij - k_i*k_j/2m) * delta(c_i, c_j))
        return 0.0

    # ============================================================
    # THREAT ACTOR PROFILING
    # ============================================================

    async def build_actor_profile(
        self,
        actor_id: str,
    ) -> ThreatActorProfile:
        """
        Build comprehensive threat actor profile.

        Extracts:
        - Known campaigns
        - Preferred exploits (CVEs)
        - Target sectors/types
        - MITRE ATT&CK tactics and techniques
        - Associated IOCs
        - Activity timeline

        Args:
            actor_id: Threat actor identifier

        Returns:
            ThreatActorProfile object
        """
        print(f"[PROFILE] Building threat actor profile: {actor_id}...")

        # TODO: Implement actor profile building
        # 1. Find campaigns attributed to actor
        # 2. Find CVEs exploited by those campaigns
        # 3. Find target assets
        # 4. Map to MITRE ATT&CK framework
        # 5. Find associated IOCs
        # 6. Calculate activity metrics

        profile = ThreatActorProfile(
            actor_id=actor_id,
            name=actor_id,
            aliases=[],
            attributed_campaigns=[],
            preferred_exploits=[],
            preferred_targets=[],
            tactics=[],
            techniques=[],
            known_iocs=[],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            activity_trend="STABLE",
            risk_score=50.0,
        )

        return profile

    async def find_similar_actors(
        self,
        actor_id: str,
        similarity_threshold: float = 0.7,
    ) -> List[Tuple[str, float]]:
        """
        Find threat actors with similar TTPs.

        Similarity based on:
        - Shared exploits (CVE overlap)
        - Shared targets (asset type overlap)
        - Shared techniques (MITRE ATT&CK overlap)

        Args:
            actor_id: Reference actor
            similarity_threshold: Minimum similarity (0-1)

        Returns:
            List of (actor_id, similarity_score) tuples
        """
        print(f"[PROFILE] Finding similar actors to {actor_id}...")

        # TODO: Implement similarity calculation
        # cosine_similarity(actor_profile_vector_1, actor_profile_vector_2)

        return []

    # ============================================================
    # TREND ANALYSIS
    # ============================================================

    async def analyze_vulnerability_trends(
        self,
        days: int = 30,
    ) -> Dict[str, Any]:
        """
        Analyze vulnerability trends over time.

        Metrics:
        - New CVEs per day
        - Severity distribution
        - EPSS score trends
        - Exploitability trends
        - Sector-specific trends

        Args:
            days: Analysis period in days

        Returns:
            Trend analysis with metrics
        """
        print(f"[TRENDS] Analyzing vulnerability trends (days={days})...")

        # TODO: Implement trend analysis
        return {
            "period_days": days,
            "new_cves": 0,
            "avg_cvss": 0.0,
            "high_severity_pct": 0.0,
            "exploited_pct": 0.0,
            "trend": "STABLE",
        }

    async def analyze_exploit_trends(
        self,
        days: int = 30,
    ) -> Dict[str, Any]:
        """
        Analyze exploit availability trends.

        Metrics:
        - New exploits per day
        - Exploit types (POC, Metasploit, etc.)
        - Time-to-exploit (CVE date -> first exploit)
        - Exploit source trends

        Args:
            days: Analysis period in days

        Returns:
            Exploit trend analysis
        """
        print(f"[TRENDS] Analyzing exploit trends (days={days})...")

        # TODO: Implement exploit trend analysis
        return {
            "period_days": days,
            "new_exploits": 0,
            "avg_time_to_exploit": 0.0,
            "sources": {},
            "trend": "STABLE",
        }

    async def analyze_campaign_trends(
        self,
        days: int = 30,
    ) -> Dict[str, Any]:
        """
        Analyze threat campaign trends.

        Metrics:
        - New campaigns
        - Campaign activity changes
        - Target sector shifts
        - Technique evolution

        Args:
            days: Analysis period in days

        Returns:
            Campaign trend analysis
        """
        print(f"[TRENDS] Analyzing campaign trends (days={days})...")

        # TODO: Implement campaign trend analysis
        return {
            "period_days": days,
            "new_campaigns": 0,
            "active_campaigns": 0,
            "target_sectors": {},
            "techniques": {},
        }

    # ============================================================
    # ANOMALY DETECTION
    # ============================================================

    async def detect_anomalies(
        self,
        sensitivity: float = 0.8,
    ) -> List[AnomalyAlert]:
        """
        Detect anomalies in threat graph.

        Types:
        - NEW_ATTACK_PATTERN: Previously unseen relationship pattern
        - SUDDEN_SPIKE: Unusual surge in activity
        - UNUSUAL_TARGETING: Target shift for known actor
        - TECHNIQUE_EVOLUTION: New techniques from known actor

        Args:
            sensitivity: Detection sensitivity (0-1)

        Returns:
            List of AnomalyAlert objects
        """
        print(f"[ANOMALY] Detecting anomalies (sensitivity={sensitivity})...")

        anomalies = []

        # TODO: Implement anomaly detection
        # 1. Calculate baseline metrics
        # 2. Detect deviations from baseline
        # 3. Calculate confidence scores

        print(f"  [ANOMALIES] Detected {len(anomalies)} anomalies")
        return anomalies

    # ============================================================
    # RISK SCORING
    # ============================================================

    async def calculate_risk_score(
        self,
        entity_id: str,
    ) -> float:
        """
        Calculate comprehensive risk score for entity.

        Factors:
        - Severity of vulnerabilities
        - Exploitability (EPSS)
        - Exposure (internet-facing)
        - Criticality (data/system importance)
        - Reachability (network hops from internet)
        - Threat activity (recent campaigns/IOCs)

        Args:
            entity_id: Entity to score

        Returns:
            Risk score (0-100)
        """
        score = 0.0

        # TODO: Implement risk scoring
        # weighted_sum of factors

        return score

    async def calculate_asset_risk(
        self,
        asset_id: str,
    ) -> Dict[str, Any]:
        """
        Calculate detailed risk assessment for asset.

        Returns:
            {
                "total_risk_score": float (0-100),
                "vulnerability_risk": float,
                "exposure_risk": float,
                "reachability_risk": float,
                "threat_activity_risk": float,
                "critical_paths": int,
                "affected_by_campaigns": [campaign_ids],
            }
        """
        print(f"[RISK] Calculating asset risk: {asset_id}...")

        # TODO: Implement detailed asset risk calculation
        return {
            "total_risk_score": 0.0,
            "vulnerability_risk": 0.0,
            "exposure_risk": 0.0,
            "reachability_risk": 0.0,
            "threat_activity_risk": 0.0,
            "critical_paths": 0,
            "affected_by_campaigns": [],
        }

    # ============================================================
    # INTELLIGENCE RECOMMENDATIONS
    # ============================================================

    async def generate_recommendations(
        self,
        entity_id: str,
        recommendation_type: str = "priority",
    ) -> List[str]:
        """
        Generate actionable recommendations for entity.

        Types:
        - priority: Remediation priority (patch first)
        - defensive: Defensive measures (network segmentation)
        - detective: Detective controls (monitoring, alerting)
        - intelligence: Intelligence gathering (threat hunting)

        Args:
            entity_id: Entity to generate recommendations for
            recommendation_type: Type of recommendations

        Returns:
            List of actionable recommendations
        """
        print(f"[INTEL] Generating recommendations for {entity_id}...")

        # TODO: Implement recommendation engine
        recommendations = []

        return recommendations

    # ============================================================
    # GRAPH STATISTICS
    # ============================================================

    async def get_intelligence_statistics(self) -> Dict[str, Any]:
        """Get comprehensive graph intelligence statistics."""
        # TODO: Implement intelligence statistics
        return {
            "communities": 0,
            "threat_actors": 0,
            "attack_patterns": 0,
            "critical_paths": 0,
            "queries_executed": len(self._query_cache),
            "anomalies_detected": 0,
        }

    async def get_query_performance(self) -> Dict[str, float]:
        """Get average query execution times."""
        # TODO: Implement query performance analytics
        return {
            "find_attack_paths": 0.0,
            "find_affected_assets": 0.0,
            "find_reachable": 0.0,
            "find_critical_paths": 0.0,
        }
