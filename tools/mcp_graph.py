"""
tools/mcp_graph.py - Graph MCP Server

Cung cấp giao diện công cụ cho Knowledge Graph operations:
- Node/edge management (add_node, add_edge, get_node, get_neighbors)
- SPARQL-like queries (find_attack_paths, find_affected_assets, find_reachable)
- Community detection (find_threat_communities)
- Threat actor profiling (profile_threat_actor)

Tái sử dụng:
- core/knowledge_graph.py (GraphNode, GraphEdge, KnowledgeGraph)
- core/graph_intelligence_layer.py (QueryResult, SPARQL-like queries)
- core/community_detection.py (community clustering)
- core/actor_profiling.py (threat actor profiling)
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from dataclasses import dataclass
import logging

from core.knowledge_graph import KnowledgeGraph, NodeType, EdgeType, GraphNode, GraphEdge
from core.graph_intelligence_layer import GraphIntelligenceLayer
from core.community_detection import CommunityDetectionEngine
from core.actor_profiling import ActorProfilingEngine
from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine
from core.threat_repository import ThreatKnowledgeRepository

logger = logging.getLogger(__name__)


# ============================================================
# RESPONSE MODELS
# ============================================================

@dataclass
class GraphMCPResponse:
    """Response wrapper cho graph MCP operations"""
    success: bool
    data: Any = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0


# ============================================================
# GRAPH MCP SERVER
# ============================================================

class GraphMCPServer:
    """MCP server cho graph intelligence operations

    Cung cấp 6 tools:
    1. add_graph_node - Thêm node vào knowledge graph
    2. add_graph_edge - Thêm quan hệ giữa nodes
    3. query_attack_paths - Tìm đường dẫn tấn công (SPARQL-like)
    4. query_campaign_impact - Tìm assets bị ảnh hưởng (SPARQL-like)
    5. find_threat_communities - Phát hiện cộng đồng threat
    6. profile_threat_actor - Xây dựng hồ sơ threat actor
    """

    def __init__(self, repository: ThreatKnowledgeRepository):
        """Khởi tạo Graph MCP server

        Args:
            repository: Threat knowledge repository (SQLite hoặc Neo4j)
        """
        self.repository = repository
        self.graph = KnowledgeGraph()
        self.intelligence = GraphIntelligenceLayer(repository)

        # Initialize support engines
        self.memory_engine = ThreatMemoryEngine()
        self.pattern_engine = PatternDetectionEngine(self.memory_engine)
        self.context_engine = HistoricalContextEngine(self.memory_engine)

        self.community_detector = CommunityDetectionEngine(
            self.memory_engine,
            self.pattern_engine,
            self.context_engine
        )
        self.actor_profiler = ActorProfilingEngine(
            self.memory_engine,
            self.pattern_engine,
            self.context_engine
        )

    # ============================================================
    # TOOL 1: ADD NODE
    # ============================================================

    async def add_graph_node(
        self,
        node_id: str,
        node_type: str,
        properties: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> GraphMCPResponse:
        """Thêm node vào knowledge graph

        Args:
            node_id: Unique node identifier (CVE-2021-44228, IP-192.168.1.1, etc)
            node_type: vulnerability | ioc | asset | campaign | actor | malware | technique | infrastructure
            properties: Node properties (CVSS, severity, description, etc)
            metadata: Additional metadata

        Returns:
            GraphMCPResponse with created GraphNode
        """
        try:
            start_time = datetime.utcnow()

            # Validate node_type
            try:
                nt = NodeType[node_type.upper()]
            except KeyError:
                valid_types = [t.value for t in NodeType]
                return GraphMCPResponse(
                    success=False,
                    error=f"Invalid node_type: {node_type}. Valid types: {valid_types}"
                )

            # Add node to graph
            node = self.graph.add_node(
                node_id=node_id,
                node_type=nt,
                properties=properties or {},
                metadata=metadata or {}
            )

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Graph MCP] Added node: {node_id} ({node_type})")

            return GraphMCPResponse(
                success=True,
                data=node.to_dict(),
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Graph MCP] Error adding node: {str(e)}")
            return GraphMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 2: ADD EDGE
    # ============================================================

    async def add_graph_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str,
        weight: float = 1.0,
        confidence: float = 1.0,
        properties: Optional[Dict[str, Any]] = None
    ) -> GraphMCPResponse:
        """Thêm quan hệ giữa hai nodes

        Args:
            source_id: Source node ID
            target_id: Target node ID
            edge_type: exploits | targets | uses | part_of | communicates_with | attributed_to | similar_to | related_to
            weight: Edge weight/importance (0.0-1.0)
            confidence: Confidence score (0.0-1.0)
            properties: Edge properties

        Returns:
            GraphMCPResponse with created GraphEdge
        """
        try:
            start_time = datetime.utcnow()

            # Validate edge_type
            try:
                et = EdgeType[edge_type.upper()]
            except KeyError:
                valid_types = [t.value for t in EdgeType]
                return GraphMCPResponse(
                    success=False,
                    error=f"Invalid edge_type: {edge_type}. Valid types: {valid_types}"
                )

            # Add edge
            edge = self.graph.add_edge(
                source_id=source_id,
                target_id=target_id,
                edge_type=et,
                weight=weight,
                confidence=confidence,
                properties=properties or {}
            )

            if edge is None:
                return GraphMCPResponse(
                    success=False,
                    error=f"Source node '{source_id}' or target node '{target_id}' not found"
                )

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Graph MCP] Added edge: {source_id} -[{edge_type}]-> {target_id}")

            return GraphMCPResponse(
                success=True,
                data=edge.to_dict(),
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Graph MCP] Error adding edge: {str(e)}")
            return GraphMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 3: QUERY ATTACK PATHS (SPARQL-like)
    # ============================================================

    async def query_attack_paths(
        self,
        target_asset: str,
        min_severity: str = "MEDIUM",
        max_depth: int = 4
    ) -> GraphMCPResponse:
        """Tìm tất cả đường dẫn tấn công tới asset (SPARQL-like query)

        SPARQL equivalent:
        SELECT paths WHERE
          ?exposed rdf:type Asset ;
            internet_facing true ;
            vulnerable_to ?cve ;
            reachable_to* ?target .
          ?target rdf:type Asset ;
            vulnerable_to ?cve .

        Args:
            target_asset: Asset ID hoặc hostname (target)
            min_severity: Minimum CVE severity (LOW, MEDIUM, HIGH, CRITICAL)
            max_depth: Maximum path depth (1-10)

        Returns:
            GraphMCPResponse with attack paths, entities, relationships
        """
        try:
            start_time = datetime.utcnow()

            # Validate min_severity
            valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if min_severity.upper() not in valid_severities:
                return GraphMCPResponse(
                    success=False,
                    error=f"Invalid min_severity: {min_severity}. Valid: {valid_severities}"
                )

            # Validate max_depth
            if not (1 <= max_depth <= 10):
                return GraphMCPResponse(
                    success=False,
                    error=f"max_depth must be 1-10, got {max_depth}"
                )

            # Query attack paths
            result = await self.intelligence.find_attack_paths_to(
                target_asset=target_asset,
                min_severity=min_severity.upper(),
                max_depth=max_depth
            )

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Graph MCP] Found {result.result_count} attack paths to {target_asset}")

            return GraphMCPResponse(
                success=True,
                data={
                    "query_type": result.query_type.value,
                    "target_asset": target_asset,
                    "entities": result.entities,
                    "relationships": result.relationships,
                    "paths": result.paths,
                    "result_count": result.result_count,
                    "query_execution_time_ms": result.execution_time_ms
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Graph MCP] Error querying attack paths: {str(e)}")
            return GraphMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 4: QUERY CAMPAIGN IMPACT (SPARQL-like)
    # ============================================================

    async def query_campaign_impact(
        self,
        campaign_id: str,
        include_metrics: bool = True
    ) -> GraphMCPResponse:
        """Tìm tất cả assets bị ảnh hưởng bởi chiến dịch (SPARQL-like query)

        SPARQL equivalent:
        SELECT assets WHERE
          ?campaign exploits ?cve .
          ?asset vulnerable_to ?cve .

        Args:
            campaign_id: Campaign identifier
            include_metrics: Include risk metrics

        Returns:
            GraphMCPResponse with affected assets, CVEs, metrics
        """
        try:
            start_time = datetime.utcnow()

            # Query campaign impact
            result = await self.intelligence.find_assets_affected_by(
                campaign_id=campaign_id
            )

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Graph MCP] Found {result.result_count} assets affected by campaign {campaign_id}")

            return GraphMCPResponse(
                success=True,
                data={
                    "query_type": result.query_type.value,
                    "campaign_id": campaign_id,
                    "affected_assets": result.entities,
                    "relationships": result.relationships,
                    "result_count": result.result_count,
                    "query_execution_time_ms": result.execution_time_ms
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Graph MCP] Error querying campaign impact: {str(e)}")
            return GraphMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 5: FIND THREAT COMMUNITIES
    # ============================================================

    async def find_threat_communities(
        self,
        min_density: float = 0.3,
        entity_type: str = "all"
    ) -> GraphMCPResponse:
        """Phát hiện cộng đồng threat infrastructure

        Sử dụng clustering để tìm các nhóm entities liên kết:
        - IOC communities (shared C2, shared campaigns)
        - Asset communities (shared vulnerabilities)
        - Campaign communities (shared tactics)
        - Actor communities (shared infrastructure)

        Args:
            min_density: Minimum community density threshold (0.0-1.0)
            entity_type: ioc | asset | campaign | actor | all

        Returns:
            GraphMCPResponse with communities, members, metrics
        """
        try:
            start_time = datetime.utcnow()

            # Validate min_density
            if not (0.0 <= min_density <= 1.0):
                return GraphMCPResponse(
                    success=False,
                    error=f"min_density must be 0.0-1.0, got {min_density}"
                )

            # Validate entity_type
            valid_types = ["ioc", "asset", "campaign", "actor", "all"]
            if entity_type.lower() not in valid_types:
                return GraphMCPResponse(
                    success=False,
                    error=f"Invalid entity_type: {entity_type}. Valid: {valid_types}"
                )

            # Detect communities
            communities = await self.community_detector.detect_actor_communities(
                similarity_threshold=min_density
            )

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Graph MCP] Detected {len(communities)} threat communities")

            return GraphMCPResponse(
                success=True,
                data={
                    "communities_count": len(communities),
                    "entity_type_filter": entity_type,
                    "min_density": min_density,
                    "communities": [
                        {
                            "community_id": c.community_id,
                            "size": c.size,
                            "density": c.community_strength,
                            "shared_campaigns": c.shared_campaigns,
                            "shared_techniques": c.shared_techniques,
                            "members": c.actor_ids[:5]  # Top 5 members (prevent large response)
                        }
                        for c in communities
                    ]
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Graph MCP] Error finding communities: {str(e)}")
            return GraphMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 6: PROFILE THREAT ACTOR
    # ============================================================

    async def profile_threat_actor(
        self,
        actor_id: str,
        include_campaigns: bool = True,
        include_techniques: bool = True,
        include_targets: bool = True
    ) -> GraphMCPResponse:
        """Xây dựng hồ sơ threat actor từ graph

        Phân tích:
        - Attributed campaigns
        - Primary attack techniques
        - Target sectors/countries
        - Infrastructure preferences
        - Activity timeline
        - MITRE ATT&CK mapping

        Args:
            actor_id: Threat actor ID (APT28, Lazarus, FIN7, etc)
            include_campaigns: Include attributed campaigns
            include_techniques: Include MITRE ATT&CK techniques
            include_targets: Include target sectors/countries

        Returns:
            GraphMCPResponse with actor profile, TTPs, metrics
        """
        try:
            start_time = datetime.utcnow()

            # Build actor profile
            profile = self.actor_profiler.profile_actor(actor_id=actor_id)

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Graph MCP] Profiled threat actor: {actor_id}")

            return GraphMCPResponse(
                success=True,
                data={
                    "actor_id": profile.actor_id,
                    "total_campaigns": profile.total_campaigns,
                    "campaigns": profile.campaigns if include_campaigns else [],
                    "primary_techniques": profile.primary_techniques if include_techniques else [],
                    "techniques_count": len(profile.techniques),
                    "target_sectors": profile.target_sectors if include_targets else [],
                    "targets_count": len(profile.targets),
                    "activity_tempo": profile.activity_tempo,
                    "sophistication_level": profile.sophistication_level,
                    "first_observed": profile.first_observed.isoformat() if profile.first_observed else None,
                    "last_observed": profile.last_observed.isoformat() if profile.last_observed else None,
                    "is_active": profile.is_active,
                    "confidence_score": profile.confidence_score
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Graph MCP] Error profiling actor: {str(e)}")
            return GraphMCPResponse(
                success=False,
                error=str(e)
            )


# ============================================================
# SINGLETON INSTANCE
# ============================================================

_graph_mcp_instance: Optional[GraphMCPServer] = None


def get_graph_mcp_server(repository: ThreatKnowledgeRepository) -> GraphMCPServer:
    """Lấy singleton instance của Graph MCP server

    Args:
        repository: Threat knowledge repository

    Returns:
        GraphMCPServer instance
    """
    global _graph_mcp_instance
    if _graph_mcp_instance is None:
        _graph_mcp_instance = GraphMCPServer(repository)
    return _graph_mcp_instance
