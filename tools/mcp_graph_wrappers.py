"""
tools/mcp_graph_wrappers.py - Tool wrappers cho Graph MCP

Cung cấp các tool functions cho agents gọi qua TOOLS_MAPPING.
Mỗi wrapper chuyển đổi agent call → MCP call.
"""

import asyncio
import json
from typing import Dict, Any, Optional, List
import logging

from tools.mcp_graph import get_graph_mcp_server, GraphMCPResponse
from core.sqlite_repository import SQLiteRepository

logger = logging.getLogger(__name__)

# Lazy-load repository (tránh circular imports)
_repository = None


def _get_repository():
    """Lấy singleton repository instance"""
    global _repository
    if _repository is None:
        _repository = SQLiteRepository("data/threat_knowledge.db")
    return _repository


def _get_mcp():
    """Lấy Graph MCP server instance"""
    return get_graph_mcp_server(_get_repository())


# ============================================================
# WRAPPER FUNCTIONS (for agents/TOOLS_MAPPING)
# ============================================================

def graph_add_node(
    node_id: str,
    node_type: str,
    properties: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Wrapper: Add node to knowledge graph

    Used by agents via TOOLS_MAPPING["graph_add_node"]

    Args:
        node_id: Node identifier
        node_type: vulnerability, ioc, asset, campaign, actor, malware, technique, infrastructure
        properties: Node properties
        metadata: Additional metadata

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: GraphMCPResponse = asyncio.run(
            mcp.add_graph_node(node_id, node_type, properties, metadata)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in graph_add_node wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def graph_add_edge(
    source_id: str,
    target_id: str,
    edge_type: str,
    weight: float = 1.0,
    confidence: float = 1.0,
    properties: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Wrapper: Add edge between nodes

    Used by agents via TOOLS_MAPPING["graph_add_edge"]

    Args:
        source_id: Source node ID
        target_id: Target node ID
        edge_type: exploits, targets, uses, part_of, communicates_with, attributed_to, similar_to, related_to
        weight: Edge weight (0.0-1.0)
        confidence: Confidence score (0.0-1.0)
        properties: Edge properties

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: GraphMCPResponse = asyncio.run(
            mcp.add_graph_edge(source_id, target_id, edge_type, weight, confidence, properties)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in graph_add_edge wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def graph_query_attack_paths(
    target_asset: str,
    min_severity: str = "MEDIUM",
    max_depth: int = 4
) -> Dict[str, Any]:
    """Wrapper: Find attack paths to asset (SPARQL-like query)

    Used by agents via TOOLS_MAPPING["graph_query_attack_paths"]

    Args:
        target_asset: Target asset ID
        min_severity: LOW, MEDIUM, HIGH, CRITICAL
        max_depth: Maximum path depth (1-10)

    Returns:
        Dict with attack paths, entities, relationships
    """
    try:
        mcp = _get_mcp()
        response: GraphMCPResponse = asyncio.run(
            mcp.query_attack_paths(target_asset, min_severity, max_depth)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in graph_query_attack_paths wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def graph_query_campaign_impact(
    campaign_id: str,
    include_metrics: bool = True
) -> Dict[str, Any]:
    """Wrapper: Find assets affected by campaign (SPARQL-like query)

    Used by agents via TOOLS_MAPPING["graph_query_campaign_impact"]

    Args:
        campaign_id: Campaign ID
        include_metrics: Include risk metrics

    Returns:
        Dict with affected assets, metrics
    """
    try:
        mcp = _get_mcp()
        response: GraphMCPResponse = asyncio.run(
            mcp.query_campaign_impact(campaign_id, include_metrics)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in graph_query_campaign_impact wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def graph_find_threat_communities(
    min_density: float = 0.3,
    entity_type: str = "all"
) -> Dict[str, Any]:
    """Wrapper: Find threat communities (clustering)

    Used by agents via TOOLS_MAPPING["graph_find_threat_communities"]

    Args:
        min_density: Minimum community density (0.0-1.0)
        entity_type: ioc, asset, campaign, actor, all

    Returns:
        Dict with communities, members, metrics
    """
    try:
        mcp = _get_mcp()
        response: GraphMCPResponse = asyncio.run(
            mcp.find_threat_communities(min_density, entity_type)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in graph_find_threat_communities wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def graph_profile_threat_actor(
    actor_id: str,
    include_campaigns: bool = True,
    include_techniques: bool = True,
    include_targets: bool = True
) -> Dict[str, Any]:
    """Wrapper: Build threat actor profile

    Used by agents via TOOLS_MAPPING["graph_profile_threat_actor"]

    Args:
        actor_id: Threat actor ID (APT28, Lazarus, etc)
        include_campaigns: Include campaigns
        include_techniques: Include MITRE ATT&CK techniques
        include_targets: Include target sectors

    Returns:
        Dict with actor profile, TTPs, metrics
    """
    try:
        mcp = _get_mcp()
        response: GraphMCPResponse = asyncio.run(
            mcp.profile_threat_actor(
                actor_id,
                include_campaigns,
                include_techniques,
                include_targets
            )
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in graph_profile_threat_actor wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


# ============================================================
# TOOL DESCRIPTIONS (for agents)
# ============================================================

GRAPH_MCP_TOOLS_DESCRIPTION = """
GRAPH MCP TOOLS - Quản lý và truy vấn Knowledge Graph:

MANAGEMENT:
- graph_add_node(node_id, node_type, properties): Thêm node vào graph
  Types: vulnerability, ioc, asset, campaign, actor, malware, technique, infrastructure

- graph_add_edge(source_id, target_id, edge_type, weight, confidence): Thêm quan hệ
  Types: exploits, targets, uses, part_of, communicates_with, attributed_to, similar_to, related_to

SPARQL-LIKE QUERIES:
- graph_query_attack_paths(target_asset, min_severity, max_depth): Tìm đường dẫn tấn công
  Returns: paths, entities, relationships

- graph_query_campaign_impact(campaign_id, include_metrics): Tìm assets bị ảnh hưởng
  Returns: affected_assets, relationships, metrics

ANALYSIS:
- graph_find_threat_communities(min_density, entity_type): Phát hiện cộng đồng threat
  Returns: communities with members, density, shared_campaigns

- graph_profile_threat_actor(actor_id, include_campaigns, include_techniques): Xây dựng hồ sơ threat actor
  Returns: campaigns, techniques, targets, activity_tempo, sophistication_level
"""
