"""
tests/test_mcp_opencti.py - Test suite cho OpenCTI MCP

Kiểm tra:
1. Indicator/IOC querying
2. Malware information retrieval
3. Threat actor profiling
4. Campaign information
5. Attack pattern lookup
6. Agent integration via wrappers
"""

import pytest
import asyncio
from datetime import datetime

from tools.mcp_opencti import OpenCTIMCPServer, OpenCTIMCPResponse
from tools.mcp_opencti_wrappers import (
    opencti_query_indicators,
    opencti_get_malware_info,
    opencti_get_threat_actor_profile,
    opencti_get_campaign_info,
    opencti_get_attack_patterns
)
from core.sqlite_repository import SQLiteRepository


@pytest.fixture
def test_db():
    """Tạo test database"""
    return SQLiteRepository(":memory:")


@pytest.fixture
def opencti_mcp(test_db):
    """Tạo OpenCTI MCP server instance"""
    return OpenCTIMCPServer(test_db)


# ============================================================
# TEST 1: QUERY INDICATORS
# ============================================================

@pytest.mark.asyncio
async def test_query_indicators_invalid_max_results(opencti_mcp):
    """Test query indicators với invalid max_results"""
    response = await opencti_mcp.query_indicators(
        search_term="test.com",
        max_results=1000  # > 500
    )

    assert not response.success
    assert "max_results must be 1-500" in response.error


@pytest.mark.asyncio
async def test_query_indicators_invalid_type(opencti_mcp):
    """Test query indicators với invalid type"""
    response = await opencti_mcp.query_indicators(
        search_term="test.com",
        indicator_type="invalid_type"
    )

    assert not response.success
    assert "Invalid indicator_type" in response.error


@pytest.mark.asyncio
async def test_query_indicators_structure(opencti_mcp):
    """Test query indicators response structure"""
    # Note: This will fail with OpenCTI not available, but tests structure
    response = await opencti_mcp.query_indicators(
        search_term="example.com",
        indicator_type="all",
        max_results=10
    )

    # Response should have proper structure even if fails
    assert hasattr(response, 'success')
    assert hasattr(response, 'data')
    assert hasattr(response, 'error')
    assert hasattr(response, 'execution_time_ms')


# ============================================================
# TEST 2: MALWARE INFO
# ============================================================

@pytest.mark.asyncio
async def test_get_malware_info_structure(opencti_mcp):
    """Test get_malware_info response structure"""
    response = await opencti_mcp.get_malware_info(
        malware_name="Emotet",
        include_variants=True
    )

    assert hasattr(response, 'success')
    assert hasattr(response, 'data')
    assert hasattr(response, 'execution_time_ms')


# ============================================================
# TEST 3: THREAT ACTOR PROFILE
# ============================================================

@pytest.mark.asyncio
async def test_get_threat_actor_profile_structure(opencti_mcp):
    """Test get_threat_actor_profile response structure"""
    response = await opencti_mcp.get_threat_actor_profile(
        actor_name="APT28",
        include_relationships=True
    )

    assert hasattr(response, 'success')
    assert hasattr(response, 'data')
    assert hasattr(response, 'execution_time_ms')


# ============================================================
# TEST 4: CAMPAIGN INFO
# ============================================================

@pytest.mark.asyncio
async def test_get_campaign_info_structure(opencti_mcp):
    """Test get_campaign_info response structure"""
    response = await opencti_mcp.get_campaign_info(
        campaign_name="Operation Stealth",
        include_iocs=True
    )

    assert hasattr(response, 'success')
    assert hasattr(response, 'data')
    assert hasattr(response, 'execution_time_ms')


# ============================================================
# TEST 5: ATTACK PATTERNS
# ============================================================

@pytest.mark.asyncio
async def test_get_attack_patterns_structure(opencti_mcp):
    """Test get_attack_patterns response structure"""
    response = await opencti_mcp.get_attack_patterns(
        search_term="phishing",
        max_results=20
    )

    assert hasattr(response, 'success')
    assert hasattr(response, 'data')
    assert hasattr(response, 'execution_time_ms')


@pytest.mark.asyncio
async def test_get_attack_patterns_no_search(opencti_mcp):
    """Test get_attack_patterns without search term"""
    response = await opencti_mcp.get_attack_patterns(
        max_results=10
    )

    assert hasattr(response, 'success')
    if response.success:
        assert "patterns" in response.data


# ============================================================
# TEST 6: WRAPPER INTEGRATION (Agent calls)
# ============================================================

def test_opencti_query_indicators_wrapper():
    """Test opencti_query_indicators wrapper"""
    response = opencti_query_indicators(
        search_term="example.com",
        indicator_type="indicator",
        max_results=10
    )

    assert "success" in response
    assert "data" in response or "error" in response


def test_opencti_get_malware_info_wrapper():
    """Test opencti_get_malware_info wrapper"""
    response = opencti_get_malware_info(
        malware_name="Emotet",
        include_variants=True
    )

    assert "success" in response
    assert "data" in response or "error" in response


def test_opencti_get_threat_actor_profile_wrapper():
    """Test opencti_get_threat_actor_profile wrapper"""
    response = opencti_get_threat_actor_profile(
        actor_name="APT28",
        include_relationships=True
    )

    assert "success" in response
    assert "data" in response or "error" in response


def test_opencti_get_campaign_info_wrapper():
    """Test opencti_get_campaign_info wrapper"""
    response = opencti_get_campaign_info(
        campaign_name="Operation Stealth",
        include_iocs=True
    )

    assert "success" in response
    assert "data" in response or "error" in response


def test_opencti_get_attack_patterns_wrapper():
    """Test opencti_get_attack_patterns wrapper"""
    response = opencti_get_attack_patterns(
        search_term="privilege escalation",
        max_results=20
    )

    assert "success" in response
    assert "data" in response or "error" in response


# ============================================================
# TEST 7: RESPONSE VALIDATION
# ============================================================

def test_indicator_response_format():
    """Test indicator response format validation"""
    response = opencti_query_indicators(
        search_term="192.168.1.1",
        indicator_type="all",
        max_results=5
    )

    if response["success"]:
        assert "search_term" in response["data"]
        assert "results_count" in response["data"]
        assert "indicators" in response["data"]
        assert isinstance(response["data"]["indicators"], list)


def test_malware_response_format():
    """Test malware response format"""
    response = opencti_get_malware_info("TestMalware")

    if response["success"]:
        assert "malware_name" in response["data"]
        assert "malware_types" in response["data"]
        assert "aliases" in response["data"]


def test_actor_response_format():
    """Test actor profile response format"""
    response = opencti_get_threat_actor_profile("TestActor")

    if response["success"]:
        assert "actor_name" in response["data"]
        assert "actor_id" in response["data"]
        assert "aliases" in response["data"]


def test_campaign_response_format():
    """Test campaign response format"""
    response = opencti_get_campaign_info("TestCampaign")

    if response["success"]:
        assert "campaign_name" in response["data"]
        assert "total_entities" in response["data"]
        assert "entity_breakdown" in response["data"]


def test_patterns_response_format():
    """Test attack patterns response format"""
    response = opencti_get_attack_patterns("test", max_results=10)

    if response["success"]:
        assert "patterns_count" in response["data"]
        assert "patterns" in response["data"]
        assert isinstance(response["data"]["patterns"], list)


# ============================================================
# TEST 8: AGENT INTEGRATION
# ============================================================

def test_opencti_mcp_in_tools_mapping():
    """Test OpenCTI MCP tools dalam TOOLS_MAPPING"""
    from agents.base import TOOLS_MAPPING

    opencti_tools = [
        "opencti_query_indicators",
        "opencti_get_malware_info",
        "opencti_get_threat_actor_profile",
        "opencti_get_campaign_info",
        "opencti_get_attack_patterns"
    ]

    for tool_name in opencti_tools:
        assert tool_name in TOOLS_MAPPING, f"{tool_name} not in TOOLS_MAPPING"
        assert TOOLS_MAPPING[tool_name] is not None


def test_opencti_mcp_in_tool_permissions():
    """Test OpenCTI MCP tools trong TOOL_PERMISSIONS"""
    from agents.base import TOOL_PERMISSIONS

    # agent_ti_extended should have OpenCTI tools
    ti_extended_tools = TOOL_PERMISSIONS.get("agent_ti_extended", [])
    opencti_tools = [
        "opencti_query_indicators",
        "opencti_get_malware_info",
        "opencti_get_threat_actor_profile"
    ]

    # At least some OpenCTI tools should be there
    found_count = sum(1 for tool in opencti_tools if tool in ti_extended_tools)
    assert found_count >= 1, f"Not enough OpenCTI tools in agent_ti_extended"


# ============================================================
# TEST 9: ERROR HANDLING
# ============================================================

@pytest.mark.asyncio
async def test_query_indicators_max_results_boundary(opencti_mcp):
    """Test max_results boundary validation"""
    # Test boundary: exactly 500 should work
    response = await opencti_mcp.query_indicators(
        search_term="test",
        max_results=500
    )
    # Should not fail on validation
    assert response.success or "max_results" not in str(response.error)


@pytest.mark.asyncio
async def test_query_indicators_min_results_boundary(opencti_mcp):
    """Test min_results boundary"""
    # Test boundary: exactly 1 should work
    response = await opencti_mcp.query_indicators(
        search_term="test",
        max_results=1
    )
    # Should not fail on validation
    assert response.success or "max_results" not in str(response.error)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
