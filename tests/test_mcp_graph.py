"""
tests/test_mcp_graph.py - Test suite cho Graph MCP

Kiểm tra:
1. Node management (add_node)
2. Edge management (add_edge)
3. SPARQL-like queries (attack paths, campaign impact)
4. Community detection
5. Threat actor profiling
6. Agent integration via wrappers
"""

import pytest
import asyncio
from datetime import datetime

from tools.mcp_graph import GraphMCPServer, GraphMCPResponse
from tools.mcp_graph_wrappers import (
    graph_add_node, graph_add_edge,
    graph_query_attack_paths, graph_query_campaign_impact,
    graph_find_threat_communities, graph_profile_threat_actor
)
from core.threat_repository import SQLiteRepository
from core.knowledge_graph import NodeType, EdgeType


@pytest.fixture
def test_db():
    """Tạo test database"""
    return SQLiteRepository(":memory:")


@pytest.fixture
def graph_mcp(test_db):
    """Tạo Graph MCP server instance"""
    return GraphMCPServer(test_db)


# ============================================================
# TEST 1: NODE MANAGEMENT
# ============================================================

@pytest.mark.asyncio
async def test_add_node_vulnerability(graph_mcp):
    """Test thêm CVE node"""
    response = await graph_mcp.add_graph_node(
        node_id="CVE-2021-44228",
        node_type="vulnerability",
        properties={
            "cvss": 10.0,
            "severity": "CRITICAL",
            "description": "Log4j remote code execution"
        }
    )

    assert response.success
    assert response.data["node_id"] == "CVE-2021-44228"
    assert response.data["node_type"] == "vulnerability"
    assert response.execution_time_ms > 0


@pytest.mark.asyncio
async def test_add_node_asset(graph_mcp):
    """Test thêm asset node"""
    response = await graph_mcp.add_graph_node(
        node_id="ASSET-001",
        node_type="asset",
        properties={
            "hostname": "web-server-01",
            "ip_address": "192.168.1.100",
            "os": "Linux",
            "criticality": "HIGH"
        }
    )

    assert response.success
    assert response.data["node_id"] == "ASSET-001"
    assert response.data["node_type"] == "asset"


@pytest.mark.asyncio
async def test_add_node_invalid_type(graph_mcp):
    """Test thêm node với invalid type"""
    response = await graph_mcp.add_graph_node(
        node_id="TEST-001",
        node_type="invalid_type"
    )

    assert not response.success
    assert "Invalid node_type" in response.error


@pytest.mark.asyncio
async def test_add_node_campaign(graph_mcp):
    """Test thêm campaign node"""
    response = await graph_mcp.add_graph_node(
        node_id="CAMPAIGN-APT28-2026",
        node_type="campaign",
        properties={
            "name": "APT28 Campaign 2026",
            "objective": "Cyber espionage",
            "first_observed": datetime.utcnow().isoformat()
        }
    )

    assert response.success
    assert response.data["node_type"] == "campaign"


# ============================================================
# TEST 2: EDGE MANAGEMENT
# ============================================================

@pytest.mark.asyncio
async def test_add_edge_asset_vulnerable(graph_mcp):
    """Test thêm vulnerable_to edge"""
    # Thêm nodes trước
    await graph_mcp.add_graph_node("ASSET-001", "asset")
    await graph_mcp.add_graph_node("CVE-2021-44228", "vulnerability")

    # Thêm edge
    response = await graph_mcp.add_graph_edge(
        source_id="ASSET-001",
        target_id="CVE-2021-44228",
        edge_type="exploits",
        confidence=0.95
    )

    assert response.success
    assert response.data["confidence"] == 0.95
    assert response.data["source_id"] == "ASSET-001"


@pytest.mark.asyncio
async def test_add_edge_missing_source(graph_mcp):
    """Test thêm edge khi source node không tồn tại"""
    response = await graph_mcp.add_graph_edge(
        source_id="NONEXISTENT",
        target_id="CVE-2021-44228",
        edge_type="exploits"
    )

    assert not response.success
    assert "not found" in response.error


@pytest.mark.asyncio
async def test_add_edge_invalid_type(graph_mcp):
    """Test thêm edge với invalid type"""
    await graph_mcp.add_graph_node("ASSET-001", "asset")
    await graph_mcp.add_graph_node("CVE-2021-44228", "vulnerability")

    response = await graph_mcp.add_graph_edge(
        source_id="ASSET-001",
        target_id="CVE-2021-44228",
        edge_type="invalid_edge_type"
    )

    assert not response.success
    assert "Invalid edge_type" in response.error


@pytest.mark.asyncio
async def test_add_edge_campaign_exploits(graph_mcp):
    """Test thêm campaign → CVE relationship"""
    await graph_mcp.add_graph_node("CAMPAIGN-APT28", "campaign")
    await graph_mcp.add_graph_node("CVE-2021-44228", "vulnerability")

    response = await graph_mcp.add_graph_edge(
        source_id="CAMPAIGN-APT28",
        target_id="CVE-2021-44228",
        edge_type="exploits",
        confidence=0.90
    )

    assert response.success


# ============================================================
# TEST 3: SPARQL-LIKE QUERIES
# ============================================================

@pytest.mark.asyncio
async def test_query_attack_paths(graph_mcp):
    """Test query attack paths"""
    # Thêm nodes
    await graph_mcp.add_graph_node("ASSET-001", "asset")
    await graph_mcp.add_graph_node("CVE-2021-44228", "vulnerability", {"cvss": 10.0})

    # Thêm edge
    await graph_mcp.add_graph_edge(
        "ASSET-001", "CVE-2021-44228", "exploits", confidence=0.95
    )

    # Query
    response = await graph_mcp.query_attack_paths(
        target_asset="ASSET-001",
        min_severity="MEDIUM",
        max_depth=4
    )

    assert response.success
    assert "paths" in response.data
    assert response.data["target_asset"] == "ASSET-001"


@pytest.mark.asyncio
async def test_query_attack_paths_invalid_severity(graph_mcp):
    """Test query với invalid severity"""
    response = await graph_mcp.query_attack_paths(
        target_asset="ASSET-001",
        min_severity="INVALID"
    )

    assert not response.success
    assert "Invalid min_severity" in response.error


@pytest.mark.asyncio
async def test_query_attack_paths_invalid_depth(graph_mcp):
    """Test query với invalid max_depth"""
    response = await graph_mcp.query_attack_paths(
        target_asset="ASSET-001",
        max_depth=15  # Out of range (1-10)
    )

    assert not response.success
    assert "max_depth must be 1-10" in response.error


@pytest.mark.asyncio
async def test_query_campaign_impact(graph_mcp):
    """Test query campaign impact"""
    # Thêm nodes
    await graph_mcp.add_graph_node("CAMPAIGN-APT28", "campaign")
    await graph_mcp.add_graph_node("ASSET-001", "asset")
    await graph_mcp.add_graph_node("CVE-2021-44228", "vulnerability")

    # Thêm edges: campaign → CVE, asset → CVE
    await graph_mcp.add_graph_edge("CAMPAIGN-APT28", "CVE-2021-44228", "exploits")
    await graph_mcp.add_graph_edge("ASSET-001", "CVE-2021-44228", "exploits")

    # Query
    response = await graph_mcp.query_campaign_impact(
        campaign_id="CAMPAIGN-APT28"
    )

    assert response.success
    assert "affected_assets" in response.data
    assert response.data["campaign_id"] == "CAMPAIGN-APT28"


# ============================================================
# TEST 4: COMMUNITY DETECTION
# ============================================================

@pytest.mark.asyncio
async def test_find_threat_communities(graph_mcp):
    """Test phát hiện threat communities"""
    # Thêm nodes
    for i in range(3):
        await graph_mcp.add_graph_node(f"ACTOR-{i}", "actor")

    # Thêm edges để tạo community
    await graph_mcp.add_graph_edge("ACTOR-0", "ACTOR-1", "attributed_to")
    await graph_mcp.add_graph_edge("ACTOR-1", "ACTOR-2", "attributed_to")

    # Query
    response = await graph_mcp.find_threat_communities(
        min_density=0.3,
        entity_type="all"
    )

    assert response.success
    assert "communities_count" in response.data


@pytest.mark.asyncio
async def test_find_communities_invalid_density(graph_mcp):
    """Test dengan invalid density"""
    response = await graph_mcp.find_threat_communities(
        min_density=1.5  # Out of range (0.0-1.0)
    )

    assert not response.success
    assert "min_density must be 0.0-1.0" in response.error


@pytest.mark.asyncio
async def test_find_communities_invalid_entity_type(graph_mcp):
    """Test với invalid entity_type"""
    response = await graph_mcp.find_threat_communities(
        entity_type="invalid_type"
    )

    assert not response.success
    assert "Invalid entity_type" in response.error


# ============================================================
# TEST 5: THREAT ACTOR PROFILING
# ============================================================

@pytest.mark.asyncio
async def test_profile_threat_actor(graph_mcp):
    """Test xây dựng threat actor profile"""
    # Thêm actor node
    await graph_mcp.add_graph_node(
        node_id="APT28",
        node_type="actor",
        properties={
            "name": "APT28",
            "aliases": ["Fancy Bear", "Sofacy"]
        }
    )

    # Query
    response = await graph_mcp.profile_threat_actor(
        actor_id="APT28",
        include_campaigns=True,
        include_techniques=True
    )

    assert response.success
    assert response.data["actor_id"] == "APT28"
    assert "total_campaigns" in response.data
    assert "sophistication_level" in response.data


# ============================================================
# TEST 6: WRAPPER INTEGRATION (Agent calls)
# ============================================================

def test_graph_add_node_wrapper():
    """Test graph_add_node wrapper (như agent call)"""
    response = graph_add_node(
        node_id="CVE-TEST-001",
        node_type="vulnerability",
        properties={"cvss": 9.0}
    )

    assert response["success"]
    assert response["data"]["node_id"] == "CVE-TEST-001"


def test_graph_add_edge_wrapper():
    """Test graph_add_edge wrapper"""
    # Thêm nodes trước
    graph_add_node("ASSET-TEST", "asset")
    graph_add_node("CVE-TEST-002", "vulnerability")

    # Thêm edge
    response = graph_add_edge(
        source_id="ASSET-TEST",
        target_id="CVE-TEST-002",
        edge_type="exploits",
        confidence=0.95
    )

    assert response["success"]


def test_graph_query_attack_paths_wrapper():
    """Test graph_query_attack_paths wrapper"""
    response = graph_query_attack_paths(
        target_asset="ASSET-TEST",
        min_severity="MEDIUM",
        max_depth=3
    )

    assert response["success"]
    assert "paths" in response["data"]


def test_graph_find_communities_wrapper():
    """Test graph_find_threat_communities wrapper"""
    response = graph_find_threat_communities(
        min_density=0.3,
        entity_type="all"
    )

    assert response["success"]
    assert "communities_count" in response["data"]


def test_graph_profile_actor_wrapper():
    """Test graph_profile_threat_actor wrapper"""
    # Thêm actor node
    graph_add_node("APT-TEST", "actor")

    response = graph_profile_threat_actor(
        actor_id="APT-TEST",
        include_campaigns=True
    )

    assert response["success"]
    assert response["data"]["actor_id"] == "APT-TEST"


# ============================================================
# TEST 7: PERFORMANCE
# ============================================================

@pytest.mark.asyncio
async def test_add_node_performance(graph_mcp):
    """Test node addition performance"""
    response = await graph_mcp.add_graph_node("PERF-TEST", "vulnerability")

    # Execution time should be < 100ms
    assert response.execution_time_ms < 100


@pytest.mark.asyncio
async def test_query_attack_paths_performance(graph_mcp):
    """Test query performance"""
    # Setup
    await graph_mcp.add_graph_node("ASSET-PERF", "asset")
    await graph_mcp.add_graph_node("CVE-PERF", "vulnerability")
    await graph_mcp.add_graph_edge("ASSET-PERF", "CVE-PERF", "exploits")

    # Query
    response = await graph_mcp.query_attack_paths("ASSET-PERF")

    # Execution time should be < 500ms
    assert response.execution_time_ms < 500


# ============================================================
# TEST 8: INTEGRATION WITH AGENTS
# ============================================================

def test_graph_mcp_in_tools_mapping():
    """Test Graph MCP tools trong TOOLS_MAPPING"""
    from agents.base import TOOLS_MAPPING

    # Kiểm tra tất cả 6 tools trong mapping
    graph_tools = [
        "graph_add_node",
        "graph_add_edge",
        "graph_query_attack_paths",
        "graph_query_campaign_impact",
        "graph_find_threat_communities",
        "graph_profile_threat_actor"
    ]

    for tool_name in graph_tools:
        assert tool_name in TOOLS_MAPPING, f"{tool_name} not in TOOLS_MAPPING"
        assert TOOLS_MAPPING[tool_name] is not None


def test_graph_mcp_in_tool_permissions():
    """Test Graph MCP tools trong TOOL_PERMISSIONS"""
    from agents.base import TOOL_PERMISSIONS

    # agent_analyst có quyền truy cập tất cả graph tools
    analyst_tools = TOOL_PERMISSIONS.get("agent_analyst", [])
    graph_tools = [
        "graph_add_node",
        "graph_add_edge",
        "graph_query_attack_paths",
        "graph_query_campaign_impact",
        "graph_find_threat_communities",
        "graph_profile_threat_actor"
    ]

    for tool_name in graph_tools:
        assert tool_name in analyst_tools, f"{tool_name} not in agent_analyst permissions"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
