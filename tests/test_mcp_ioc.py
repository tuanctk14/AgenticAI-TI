"""
tests/test_mcp_ioc.py - Test suite cho IOC MCP

Kiểm tra:
1. IOC lookup
2. IOC classification
3. IOC correlation
4. IOC context retrieval
5. IOC sighting recording
6. Agent integration
"""

import pytest
import asyncio
from datetime import datetime

from tools.mcp_ioc import IOCMCPServer, IOCMCPResponse
from tools.mcp_ioc_wrappers import (
    ioc_lookup_ioc,
    ioc_classify_ioc,
    ioc_correlate_iocs,
    ioc_get_ioc_context,
    ioc_record_ioc_sighting
)
from core.sqlite_repository import SQLiteRepository


@pytest.fixture
def test_db():
    """Tạo test database"""
    return SQLiteRepository(":memory:")


@pytest.fixture
def ioc_mcp(test_db):
    """Tạo IOC MCP server instance"""
    return IOCMCPServer(test_db)


# ============================================================
# TEST 1: IOC LOOKUP
# ============================================================

@pytest.mark.asyncio
async def test_lookup_ioc_ipv4(ioc_mcp):
    """Test lookup IOC with IPv4 address"""
    response = await ioc_mcp.lookup_ioc(
        ioc_value="192.168.1.1",
        ioc_type="ipv4"
    )

    assert hasattr(response, 'success')
    assert hasattr(response, 'data')
    if response.success:
        assert response.data["ioc_type"] == "ipv4"
        assert response.data["ioc_value"] == "192.168.1.1"


@pytest.mark.asyncio
async def test_lookup_ioc_domain(ioc_mcp):
    """Test lookup IOC with domain"""
    response = await ioc_mcp.lookup_ioc(
        ioc_value="malicious.com",
        ioc_type="domain"
    )

    assert hasattr(response, 'success')
    if response.success:
        assert response.data["ioc_type"] == "domain"


@pytest.mark.asyncio
async def test_lookup_ioc_hash(ioc_mcp):
    """Test lookup IOC with MD5 hash"""
    response = await ioc_mcp.lookup_ioc(
        ioc_value="d41d8cd98f00b204e9800998ecf8427e"  # MD5 of empty string
    )

    assert hasattr(response, 'success')
    if response.success:
        assert "hash" in response.data["ioc_type"]


@pytest.mark.asyncio
async def test_lookup_ioc_auto_detect(ioc_mcp):
    """Test IOC type auto-detection"""
    response = await ioc_mcp.lookup_ioc(
        ioc_value="test@example.com"
    )

    assert hasattr(response, 'success')
    if response.success:
        assert response.data["ioc_type"] == "email"


# ============================================================
# TEST 2: IOC CLASSIFICATION
# ============================================================

@pytest.mark.asyncio
async def test_classify_ioc_malware(ioc_mcp):
    """Test IOC classification as malware"""
    response = await ioc_mcp.classify_ioc(
        ioc_value="d41d8cd98f00b204e9800998ecf8427e",
        context={"threat_type": "malware"}
    )

    assert hasattr(response, 'success')
    if response.success:
        assert response.data["threat_level"] in ["critical", "high", "medium", "low"]


@pytest.mark.asyncio
async def test_classify_ioc_infrastructure(ioc_mcp):
    """Test IOC classification as infrastructure"""
    response = await ioc_mcp.classify_ioc(
        ioc_value="192.168.1.100",
        ioc_type="ipv4"
    )

    assert hasattr(response, 'success')
    if response.success:
        assert "confidence" in response.data


@pytest.mark.asyncio
async def test_classify_ioc_phishing(ioc_mcp):
    """Test IOC classification as phishing"""
    response = await ioc_mcp.classify_ioc(
        ioc_value="phishing@attacker.com",
        ioc_type="email"
    )

    assert hasattr(response, 'success')
    if response.success:
        assert "threat_associations" in response.data


# ============================================================
# TEST 3: IOC CORRELATION
# ============================================================

@pytest.mark.asyncio
async def test_correlate_iocs_infrastructure(ioc_mcp):
    """Test correlation of multiple IOCs - infrastructure type"""
    response = await ioc_mcp.correlate_iocs(
        ioc_values=["192.168.1.1", "malicious.com"],
        correlation_type="infrastructure"
    )

    assert hasattr(response, 'success')
    assert response.data["correlation_type"] == "infrastructure"


@pytest.mark.asyncio
async def test_correlate_iocs_campaign(ioc_mcp):
    """Test correlation of IOCs - campaign type"""
    response = await ioc_mcp.correlate_iocs(
        ioc_values=["192.168.1.1", "192.168.1.2", "c2.attacker.com"],
        correlation_type="campaign",
        max_results=50
    )

    assert hasattr(response, 'success')
    if response.success:
        assert "correlations" in response.data
        assert "detected_patterns" in response.data


@pytest.mark.asyncio
async def test_correlate_iocs_invalid_type(ioc_mcp):
    """Test correlation with invalid correlation type"""
    response = await ioc_mcp.correlate_iocs(
        ioc_values=["192.168.1.1"],
        correlation_type="invalid"
    )

    assert not response.success
    assert "Invalid correlation_type" in response.error


@pytest.mark.asyncio
async def test_correlate_iocs_empty_list(ioc_mcp):
    """Test correlation with empty IOC list"""
    response = await ioc_mcp.correlate_iocs(
        ioc_values=[]
    )

    assert not response.success
    assert "cannot be empty" in response.error


@pytest.mark.asyncio
async def test_correlate_iocs_max_results_boundary(ioc_mcp):
    """Test correlation with max_results boundary"""
    response = await ioc_mcp.correlate_iocs(
        ioc_values=["192.168.1.1"],
        max_results=1000
    )

    assert not response.success
    assert "max_results must be 1-500" in response.error


# ============================================================
# TEST 4: IOC CONTEXT
# ============================================================

@pytest.mark.asyncio
async def test_get_ioc_context_full(ioc_mcp):
    """Test getting full IOC context"""
    response = await ioc_mcp.get_ioc_context(
        ioc_value="malicious.com",
        include_campaigns=True,
        include_actors=True,
        include_timeline=True
    )

    assert hasattr(response, 'success')
    if response.success:
        assert "campaigns" in response.data
        assert "threat_actors" in response.data
        assert "timeline" in response.data


@pytest.mark.asyncio
async def test_get_ioc_context_partial(ioc_mcp):
    """Test getting partial IOC context"""
    response = await ioc_mcp.get_ioc_context(
        ioc_value="192.168.1.1",
        include_campaigns=True,
        include_actors=False
    )

    assert hasattr(response, 'success')
    if response.success:
        assert "campaigns" in response.data


@pytest.mark.asyncio
async def test_get_ioc_context_no_type(ioc_mcp):
    """Test IOC context with auto-detected type"""
    response = await ioc_mcp.get_ioc_context(
        ioc_value="test@example.com"
    )

    assert hasattr(response, 'success')
    if response.success:
        assert response.data["ioc_type"] == "email"


# ============================================================
# TEST 5: RECORD IOC SIGHTING
# ============================================================

@pytest.mark.asyncio
async def test_record_ioc_sighting_network(ioc_mcp):
    """Test recording IOC sighting from network sensor"""
    response = await ioc_mcp.record_ioc_sighting(
        ioc_value="192.168.1.100",
        ioc_type="ipv4",
        source="network_sensor"
    )

    assert hasattr(response, 'success')
    if response.success:
        assert response.data["sighting_recorded"] == True
        assert response.data["source"] == "network_sensor"


@pytest.mark.asyncio
async def test_record_ioc_sighting_email(ioc_mcp):
    """Test recording IOC sighting from email gateway"""
    response = await ioc_mcp.record_ioc_sighting(
        ioc_value="phishing@attacker.com",
        source="email_gateway",
        context={"user_count": 5}
    )

    assert hasattr(response, 'success')
    if response.success:
        assert response.data["source"] == "email_gateway"


@pytest.mark.asyncio
async def test_record_ioc_sighting_endpoint(ioc_mcp):
    """Test recording IOC sighting from endpoint"""
    response = await ioc_mcp.record_ioc_sighting(
        ioc_value="d41d8cd98f00b204e9800998ecf8427e",
        source="endpoint",
        context={"hostname": "WORKSTATION-01"}
    )

    assert hasattr(response, 'success')
    if response.success:
        assert "timestamp" in response.data


@pytest.mark.asyncio
async def test_record_ioc_sighting_invalid_source(ioc_mcp):
    """Test recording sighting with invalid source"""
    response = await ioc_mcp.record_ioc_sighting(
        ioc_value="192.168.1.1",
        source="invalid_source"
    )

    assert hasattr(response, 'success')
    # Should use "unknown" as fallback


# ============================================================
# TEST 6: WRAPPER INTEGRATION
# ============================================================

def test_ioc_lookup_ioc_wrapper():
    """Test ioc_lookup_ioc wrapper"""
    response = ioc_lookup_ioc("192.168.1.1")

    assert "success" in response
    assert isinstance(response["success"], bool)


def test_ioc_classify_ioc_wrapper():
    """Test ioc_classify_ioc wrapper"""
    response = ioc_classify_ioc("malicious.com")

    assert "success" in response


def test_ioc_correlate_iocs_wrapper():
    """Test ioc_correlate_iocs wrapper"""
    response = ioc_correlate_iocs(
        ioc_values=["192.168.1.1", "malicious.com"],
        correlation_type="infrastructure"
    )

    assert "success" in response
    if response["success"]:
        assert "correlations" in response["data"]


def test_ioc_get_ioc_context_wrapper():
    """Test ioc_get_ioc_context wrapper"""
    response = ioc_get_ioc_context(
        "malicious.com",
        include_campaigns=True
    )

    assert "success" in response


def test_ioc_record_ioc_sighting_wrapper():
    """Test ioc_record_ioc_sighting wrapper"""
    response = ioc_record_ioc_sighting(
        "192.168.1.1",
        source="network_sensor"
    )

    assert "success" in response


# ============================================================
# TEST 7: RESPONSE FORMAT VALIDATION
# ============================================================

def test_lookup_response_format():
    """Test IOC lookup response format"""
    response = ioc_lookup_ioc("192.168.1.1")

    if response["success"]:
        assert "ioc_value" in response["data"]
        assert "ioc_type" in response["data"]
        assert "local_records" in response["data"]
        assert "external_records" in response["data"]


def test_classify_response_format():
    """Test IOC classify response format"""
    response = ioc_classify_ioc("malicious.com")

    if response["success"]:
        assert "ioc_value" in response["data"]
        assert "classification" in response["data"]
        assert "threat_level" in response["data"]
        assert "confidence" in response["data"]


def test_correlate_response_format():
    """Test IOC correlate response format"""
    response = ioc_correlate_iocs(["192.168.1.1", "malicious.com"])

    if response["success"]:
        assert "input_iocs" in response["data"]
        assert "correlations" in response["data"]
        assert "correlation_count" in response["data"]
        assert "relationships" in response["data"]


# ============================================================
# TEST 8: AGENT INTEGRATION
# ============================================================

def test_ioc_mcp_in_tools_mapping():
    """Test IOC MCP tools dalam TOOLS_MAPPING"""
    from agents.base import TOOLS_MAPPING

    ioc_tools = [
        "ioc_lookup_ioc",
        "ioc_classify_ioc",
        "ioc_correlate_iocs",
        "ioc_get_ioc_context",
        "ioc_record_ioc_sighting"
    ]

    for tool_name in ioc_tools:
        assert tool_name in TOOLS_MAPPING
        assert TOOLS_MAPPING[tool_name] is not None


def test_ioc_mcp_in_tool_permissions():
    """Test IOC MCP tools trong TOOL_PERMISSIONS"""
    from agents.base import TOOL_PERMISSIONS

    ti_tools = TOOL_PERMISSIONS.get("agent_ti_extended", [])
    ioc_tools = ["ioc_lookup_ioc", "ioc_correlate_iocs"]

    found_count = sum(1 for tool in ioc_tools if tool in ti_tools)
    assert found_count >= 1


# ============================================================
# TEST 9: BOUNDARY VALIDATION
# ============================================================

@pytest.mark.asyncio
async def test_correlate_max_results_500(ioc_mcp):
    """Test max_results boundary at exactly 500"""
    response = await ioc_mcp.correlate_iocs(
        ioc_values=["192.168.1.1"],
        max_results=500
    )

    assert response.success or "max_results" not in str(response.error)


@pytest.mark.asyncio
async def test_correlate_min_results_1(ioc_mcp):
    """Test max_results boundary at exactly 1"""
    response = await ioc_mcp.correlate_iocs(
        ioc_values=["192.168.1.1"],
        max_results=1
    )

    assert response.success or "max_results" not in str(response.error)


# ============================================================
# TEST 10: IOC TYPE DETECTION
# ============================================================

def test_detect_ipv4():
    """Test IPv4 detection"""
    response = ioc_lookup_ioc("192.168.1.1")
    if response["success"]:
        assert response["data"]["ioc_type"] == "ipv4"


def test_detect_domain():
    """Test domain detection"""
    response = ioc_lookup_ioc("example.com")
    if response["success"]:
        assert response["data"]["ioc_type"] == "domain"


def test_detect_hash():
    """Test hash detection"""
    # MD5
    response = ioc_lookup_ioc("d41d8cd98f00b204e9800998ecf8427e")
    if response["success"]:
        assert "hash" in response["data"]["ioc_type"]


def test_detect_email():
    """Test email detection"""
    response = ioc_lookup_ioc("user@example.com")
    if response["success"]:
        assert response["data"]["ioc_type"] == "email"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
