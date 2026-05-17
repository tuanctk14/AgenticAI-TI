"""
core/threat_graph_analyzer.py - Advanced Relationship Analysis Engine

Performs graph-based threat intelligence analysis:
- Attack pattern discovery (chains of vulnerabilities + assets)
- Infrastructure mapping (asset topology + data flow)
- Campaign impact analysis (campaign -> CVE -> asset correlation)
- Attack path scoring (risk assessment of reachable vulnerabilities)
- Threat actor attribution (linking indicators to known actors)
- Lateral movement detection (asset-to-asset reachability chains)

Foundation for Phase 4 Graph Intelligence Layer and Phase 5 Neo4j migration.
"""

from typing import Optional, List, Dict, Set, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from datetime import datetime

from core.threat_schema import (
    Vulnerability,
    IOC,
    Asset,
    Relationship,
    RelationshipType,
    EntityType,
)
from core.threat_repository import ThreatKnowledgeRepository


class ThreatPatternType(str, Enum):
    """Types of threat patterns discovered."""
    ATTACK_PATH = "attack_path"
    LATERAL_MOVEMENT = "lateral_movement"
    SUPPLY_CHAIN = "supply_chain"
    ZERO_DAY_CLUSTER = "zero_day_cluster"
    RANSOMWARE_CAMPAIGN = "ransomware_campaign"
    INSIDER_THREAT = "insider_threat"


@dataclass
class ThreatPattern:
    """Discovered threat pattern in the graph."""
    pattern_type: ThreatPatternType
    confidence: float  # 0-1
    entities: List[str]  # entity IDs involved
    relationships: List[str]  # relationship IDs
    risk_score: float  # 0-100
    reasoning: str  # human-readable explanation
    discovered_at: datetime
    evidence: Dict[str, Any]  # supporting data


@dataclass
class AttackPath:
    """Attack path from exposure point to target."""
    source: str  # exposed asset ID
    target: str  # vulnerable asset ID
    steps: List[Tuple[str, str]]  # [(entity_id, relationship_type), ...]
    depth: int
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    exploitable_cves: List[str]  # CVEs on this path
    confidence: float


@dataclass
class InfrastructureNode:
    """Node in infrastructure graph."""
    asset_id: str
    hostname: str
    ip_address: str
    internet_facing: bool
    criticality: str
    centrality_score: float  # PageRank-like score
    vulnerable_to: List[str]  # CVE IDs
    reachable_from: List[str]  # asset IDs
    reaches: List[str]  # asset IDs reachable from this one


@dataclass
class InfrastructureMap:
    """Complete infrastructure topology."""
    nodes: List[InfrastructureNode]
    edges: List[Tuple[str, str]]  # (source_asset, target_asset)
    exposed_assets: List[str]  # internet-facing assets
    critical_assets: List[str]  # high criticality
    network_diameter: int  # max hops between any two nodes
    avg_degree: float  # average connections per node
    discovered_at: datetime


class ThreatGraphAnalyzer:
    """
    Performs advanced relationship analysis on threat intelligence graph.

    Key methods:
    - Attack path discovery (Internet -> exposed asset -> vulnerable asset -> data exfiltration)
    - Infrastructure mapping (asset topology with reachability analysis)
    - Campaign impact analysis (find all assets affected by campaign)
    - Attack pattern detection (zero-day clusters, ransomware campaigns, etc.)
    - Threat actor attribution (link IOCs to known threat actors)
    - Lateral movement detection (multi-hop paths through internal network)
    """

    def __init__(self, repository: ThreatKnowledgeRepository):
        """Initialize graph analyzer with knowledge base."""
        self.repo = repository

    # ============================================================
    # ATTACK PATH DISCOVERY
    # ============================================================

    async def discover_attack_paths(
        self,
        target_cve: Optional[str] = None,
        max_depth: int = 4,
    ) -> List[AttackPath]:
        """
        Discover attack paths from internet-exposed assets to vulnerabilities.

        Example path:
        Internet -> dmz-web-01 (exposed) -> internal-app (reachable) -> vulnerable_to CVE-2026-8181

        Args:
            target_cve: If specified, find paths to this CVE only
            max_depth: Maximum path length (hops)

        Returns:
            List of AttackPath objects ranked by risk
        """
        paths = []

        print(f"[GRAPH] Discovering attack paths (max_depth={max_depth})...")

        # Find all internet-exposed assets
        exposed_assets = await self._find_exposed_assets()
        print(f"  Found {len(exposed_assets)} exposed assets")

        # For each exposed asset, find reachable vulnerabilities
        for exposed_id in exposed_assets:
            # Find all reachable vulnerabilities from this exposed asset
            reachable_vulns = await self._find_reachable_vulnerabilities(
                exposed_id, max_depth
            )

            for vuln_data in reachable_vulns:
                vuln_id = vuln_data["cve_id"]
                path_steps = vuln_data["path"]
                depth = vuln_data["depth"]

                # Filter by target CVE if specified
                if target_cve and vuln_id != target_cve:
                    continue

                # Calculate risk
                cve, _ = await self.repo.get_vulnerability(vuln_id)
                risk_score = (
                    cve.risk_context.threat_score
                    if cve and cve.risk_context
                    else 50
                )

                # Determine risk level
                if risk_score >= 90:
                    risk_level = "CRITICAL"
                elif risk_score >= 70:
                    risk_level = "HIGH"
                elif risk_score >= 50:
                    risk_level = "MEDIUM"
                else:
                    risk_level = "LOW"

                attack_path = AttackPath(
                    source=exposed_id,
                    target=vuln_id,
                    steps=path_steps,
                    depth=depth,
                    risk_level=risk_level,
                    exploitable_cves=[vuln_id],
                    confidence=0.95 if depth <= 2 else 0.85,
                )
                paths.append(attack_path)

        # Sort by risk level and depth
        risk_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        paths.sort(
            key=lambda p: (
                risk_order.get(p.risk_level, 0),
                -p.depth,  # Shorter paths more concerning
            ),
            reverse=True,
        )

        print(f"  [PATHS] Discovered {len(paths)} attack paths")
        return paths

    async def _find_exposed_assets(self) -> List[str]:
        """Find all internet-exposed assets."""
        # Query repository for assets with internet_facing=True
        # This would require extending the repository interface
        # For now, return placeholder
        return []

    async def _find_reachable_vulnerabilities(
        self,
        asset_id: str,
        max_depth: int,
    ) -> List[Dict[str, Any]]:
        """
        Find all vulnerabilities reachable from asset via:
        1. Direct vulnerable_to relationships
        2. Lateral movement to other assets + their vulnerabilities
        """
        vulnerabilities = []

        # Direct vulnerabilities
        direct_vulns = await self.repo.correlate_asset_vulnerabilities(asset_id)
        for vuln in direct_vulns:
            vulnerabilities.append({
                "cve_id": vuln.id,
                "path": [
                    (asset_id, RelationshipType.VULNERABLE_TO.value),
                    (vuln.id, "vulnerability"),
                ],
                "depth": 1,
            })

        # Lateral movement: asset -> reachable_asset -> vulnerabilities
        if max_depth > 1:
            reachable_assets = await self._find_reachable_assets(
                asset_id, max_depth - 1
            )
            for reachable_id in reachable_assets:
                reachable_vulns = await self.repo.correlate_asset_vulnerabilities(
                    reachable_id
                )
                for vuln in reachable_vulns:
                    vulnerabilities.append({
                        "cve_id": vuln.id,
                        "path": [
                            (asset_id, "lateral_movement"),
                            (reachable_id, RelationshipType.VULNERABLE_TO.value),
                            (vuln.id, "vulnerability"),
                        ],
                        "depth": 2,
                    })

        return vulnerabilities

    async def _find_reachable_assets(
        self,
        asset_id: str,
        max_depth: int,
        visited: Optional[Set[str]] = None,
    ) -> List[str]:
        """BFS to find all assets reachable from given asset."""
        if visited is None:
            visited = set()

        if asset_id in visited or max_depth <= 0:
            return []

        visited.add(asset_id)
        reachable = []

        # Query for REACHABLE_TO relationships
        rels = await self.repo.get_relationships(asset_id)
        for rel in rels:
            if rel.relationship_type == RelationshipType.REACHABLE_TO:
                if rel.target_id not in visited:
                    reachable.append(rel.target_id)
                    # Recursively find further reachable assets
                    further = await self._find_reachable_assets(
                        rel.target_id, max_depth - 1, visited
                    )
                    reachable.extend(further)

        return list(set(reachable))

    # ============================================================
    # INFRASTRUCTURE MAPPING
    # ============================================================

    async def map_infrastructure(self) -> InfrastructureMap:
        """
        Build complete infrastructure map with:
        - Asset nodes (hostname, IP, exposure, criticality)
        - Connectivity edges (reachable_to relationships)
        - Centrality scores (PageRank-like)
        - Network diameter (max hops)

        Returns:
            InfrastructureMap with topology analysis
        """
        print("[GRAPH] Building infrastructure map...")

        # TODO: Implement infrastructure mapping
        # For now, return empty map
        return InfrastructureMap(
            nodes=[],
            edges=[],
            exposed_assets=[],
            critical_assets=[],
            network_diameter=0,
            avg_degree=0.0,
            discovered_at=datetime.utcnow(),
        )

    # ============================================================
    # CAMPAIGN IMPACT ANALYSIS
    # ============================================================

    async def analyze_campaign_impact(
        self,
        campaign_id: str,
    ) -> Dict[str, Any]:
        """
        Analyze impact of threat campaign:
        - Find CVEs exploited by campaign
        - Find assets vulnerable to those CVEs
        - Calculate total risk exposure
        - Identify critical assets affected
        - Estimate data exfiltration paths

        Args:
            campaign_id: Campaign identifier

        Returns:
            {
                "campaign_id": str,
                "exploited_cves": [CVE IDs],
                "affected_assets": [asset IDs],
                "critical_assets_at_risk": [asset IDs],
                "total_exposure": int (number of vulnerabilities),
                "risk_score": float (0-100),
                "recommended_actions": [actions],
            }
        """
        print(f"[GRAPH] Analyzing campaign impact: {campaign_id}")

        # TODO: Implement campaign impact analysis
        return {
            "campaign_id": campaign_id,
            "exploited_cves": [],
            "affected_assets": [],
            "critical_assets_at_risk": [],
            "total_exposure": 0,
            "risk_score": 0.0,
            "recommended_actions": [],
        }

    # ============================================================
    # THREAT PATTERN DETECTION
    # ============================================================

    async def detect_threat_patterns(
        self,
        min_confidence: float = 0.7,
    ) -> List[ThreatPattern]:
        """
        Detect threat patterns in the graph:
        - Zero-day clusters (multiple new CVEs with shared characteristics)
        - Ransomware campaigns (campaign node linked to high-impact CVEs)
        - Supply chain attacks (linked to shared vendors)
        - Insider threats (internal asset exploiting other internals)

        Args:
            min_confidence: Minimum pattern confidence threshold

        Returns:
            List of detected ThreatPattern objects
        """
        print(f"[GRAPH] Detecting threat patterns (min_confidence={min_confidence})...")

        patterns = []

        # TODO: Implement pattern detection
        # 1. Zero-day cluster detection
        # 2. Ransomware campaign detection
        # 3. Supply chain attack detection
        # 4. Insider threat detection

        print(f"  [PATTERNS] Detected {len(patterns)} threat patterns")
        return patterns

    # ============================================================
    # THREAT ACTOR ATTRIBUTION
    # ============================================================

    async def attribute_threat_actors(
        self,
        ioc_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Link IOC to known threat actors/campaigns.

        Example flow:
        IOC (malware hash) -> linked_to -> Malware -> attributed_to -> Threat Actor

        Args:
            ioc_id: IOC identifier (IP, domain, hash, etc.)

        Returns:
            List of {actor_id, name, confidence, related_campaigns, ...}
        """
        print(f"[GRAPH] Attributing threat actors for IOC: {ioc_id}")

        # TODO: Implement threat actor attribution
        return []

    # ============================================================
    # LATERAL MOVEMENT DETECTION
    # ============================================================

    async def detect_lateral_movement(
        self,
        source_asset: str,
        max_depth: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Detect lateral movement paths from compromised asset.

        Example:
        compromised-app -> firewall-rule-bypass -> internal-db

        Args:
            source_asset: Compromised asset ID
            max_depth: Maximum hops for lateral movement

        Returns:
            List of {target_asset, path, risk_score, data_exposure}
        """
        print(f"[GRAPH] Detecting lateral movement from: {source_asset}")

        # TODO: Implement lateral movement detection
        return []

    # ============================================================
    # NETWORK CENTRALITY ANALYSIS
    # ============================================================

    def calculate_asset_centrality(
        self,
        nodes: List[InfrastructureNode],
        edges: List[Tuple[str, str]],
    ) -> Dict[str, float]:
        """
        Calculate centrality scores for assets using PageRank-like algorithm.

        High centrality = critical asset that many other assets depend on
        (compromising it would have cascading impact)

        Args:
            nodes: List of infrastructure nodes
            edges: List of (source, target) asset pairs

        Returns:
            {asset_id: centrality_score (0-1), ...}
        """
        centrality = {node.asset_id: 0.5 for node in nodes}

        # Simple iterative centrality calculation
        # (In production, use networkx.pagerank)
        for _ in range(10):  # iterations
            new_centrality = {}
            total_in_degree = len(edges)

            for node in nodes:
                # Find edges pointing to this node
                incoming = sum(1 for src, tgt in edges if tgt == node.asset_id)
                # Find edges from this node
                outgoing = sum(1 for src, tgt in edges if src == node.asset_id)

                # Simple score: (incoming + outgoing) / total
                if total_in_degree > 0:
                    score = (incoming + outgoing) / total_in_degree
                else:
                    score = 0.0

                new_centrality[node.asset_id] = score

            centrality = new_centrality

        return centrality

    # ============================================================
    # GRAPH STATISTICS
    # ============================================================

    async def get_graph_statistics(self) -> Dict[str, Any]:
        """Get overall threat graph statistics."""
        # TODO: Implement graph statistics
        return {
            "total_entities": 0,
            "total_relationships": 0,
            "attack_paths": 0,
            "exposed_assets": 0,
            "critical_assets": 0,
            "threat_actors": 0,
            "campaigns": 0,
        }
