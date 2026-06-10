"""
tests/test_mcp_threat_memory.py - Test suite cho Threat Memory MCP

Kiểm tra:
1. IOC occurrence recording and retrieval
2. Campaign activity tracking
3. Asset exposure history
4. Infrastructure reuse patterns
5. Exploitation pattern memory
6. Memory analysis and queries
7. Agent integration via wrappers
"""

import pytest
import asyncio
from datetime import datetime

from tools.mcp_threat_memory import ThreatMemoryMCPServer, ThreatMemoryMCPResponse
from tools.mcp_threat_memory_wrappers import (
    memory_record_ioc_occurrence,
    memory_record_campaign_activity,
    memory_record_asset_exposure,
    memory_record_infrastructure_use,
    memory_record_exploitation_pattern,
    memory_get_analysis
)
from core.sqlite_repository import SQLiteRepository


@pytest.fixture
def test_db():
    """Tạo test database"""
    return SQLiteRepository(":memory:")


@pytest.fixture
def threat_memory_mcp(test_db):
    """Tạo Threat Memory MCP server instance"""
    return ThreatMemoryMCPServer(test_db)


# ============================================================
# TEST 1: IOC OCCURRENCE RECORDING
# ============================================================

@pytest.mark.asyncio
async def test_record_ioc_occurrence(threat_memory_mcp):
    """Test ghi nhận IOC xuất hiện"""
    response = await threat_memory_mcp.record_ioc_occurrence(
        ioc_id="IP-192.168.1.1",
        ioc_value="192.168.1.1",
        context="campaign_C2",
        campaign_id="CAMPAIGN-APT28",
        severity="high",
        confidence=0.95
    )

    assert response.success
    assert response.data["ioc_id"] == "IP-192.168.1.1"
    assert response.data["occurrence_count"] == 1
    assert response.data["is_recurring"] == False
    assert response.execution_time_ms >= 0


@pytest.mark.asyncio
async def test_record_ioc_occurrence_multiple(threat_memory_mcp):
    """Test ghi nhận IOC multiple lần (recurring)"""
    ioc_id = "IP-192.168.1.1"

    # First occurrence
    response1 = await threat_memory_mcp.record_ioc_occurrence(
        ioc_id=ioc_id,
        ioc_value="192.168.1.1",
        context="campaign_C2",
        campaign_id="CAMPAIGN-APT28"
    )

    # Second occurrence
    response2 = await threat_memory_mcp.record_ioc_occurrence(
        ioc_id=ioc_id,
        ioc_value="192.168.1.1",
        context="malware_delivery",
        campaign_id="CAMPAIGN-LAZARUS"
    )

    assert response2.success
    assert response2.data["occurrence_count"] == 2
    assert response2.data["is_recurring"] == True
    assert len(response2.data["associated_campaigns"]) == 2


@pytest.mark.asyncio
async def test_record_ioc_invalid_severity(threat_memory_mcp):
    """Test ghi nhận IOC với invalid severity"""
    response = await threat_memory_mcp.record_ioc_occurrence(
        ioc_id="IP-TEST",
        ioc_value="192.168.1.1",
        context="test",
        severity="invalid_severity"
    )

    assert not response.success
    assert "Invalid severity" in response.error


@pytest.mark.asyncio
async def test_record_ioc_invalid_confidence(threat_memory_mcp):
    """Test ghi nhận IOC với invalid confidence"""
    response = await threat_memory_mcp.record_ioc_occurrence(
        ioc_id="IP-TEST",
        ioc_value="192.168.1.1",
        context="test",
        confidence=1.5  # > 1.0
    )

    assert not response.success
    assert "Confidence must be 0.0-1.0" in response.error


# ============================================================
# TEST 2: CAMPAIGN ACTIVITY RECORDING
# ============================================================

@pytest.mark.asyncio
async def test_record_campaign_activity(threat_memory_mcp):
    """Test ghi nhận hoạt động chiến dịch"""
    response = await threat_memory_mcp.record_campaign_activity(
        campaign_id="CAMPAIGN-APT28",
        campaign_name="APT28 Campaign Q2 2026",
        activity_type="exploit",
        targets_count=5,
        techniques_used=["T1566", "T1059"],
        severity="critical",
        confidence=0.9
    )

    assert response.success
    assert response.data["campaign_id"] == "CAMPAIGN-APT28"
    assert response.data["activity_count"] == 1
    assert response.data["is_active"] == True
    assert len(response.data["techniques_evolution"]) == 2


@pytest.mark.asyncio
async def test_record_campaign_activity_evolution(threat_memory_mcp):
    """Test tracking technique evolution"""
    campaign_id = "CAMPAIGN-EVOLVE"

    # First activity
    await threat_memory_mcp.record_campaign_activity(
        campaign_id=campaign_id,
        campaign_name="Evolving Campaign",
        activity_type="reconnaissance",
        techniques_used=["T1595"]
    )

    # Second activity with new technique
    response = await threat_memory_mcp.record_campaign_activity(
        campaign_id=campaign_id,
        campaign_name="Evolving Campaign",
        activity_type="exploit",
        techniques_used=["T1595", "T1566"]
    )

    assert response.success
    assert response.data["activity_count"] == 2
    assert len(response.data["techniques_evolution"]) == 2


@pytest.mark.asyncio
async def test_record_campaign_invalid_activity_type(threat_memory_mcp):
    """Test ghi nhận campaign với invalid activity type"""
    response = await threat_memory_mcp.record_campaign_activity(
        campaign_id="CAMPAIGN-TEST",
        campaign_name="Test",
        activity_type="invalid_activity"
    )

    assert not response.success
    assert "Invalid activity_type" in response.error


# ============================================================
# TEST 3: ASSET EXPOSURE RECORDING
# ============================================================

@pytest.mark.asyncio
async def test_record_asset_exposure(threat_memory_mcp):
    """Test ghi nhận asset exposure"""
    response = await threat_memory_mcp.record_asset_exposure(
        asset_id="ASSET-001",
        asset_name="Web Server 1",
        exposure_type="cve",
        cve_id="CVE-2021-44228",
        severity="critical"
    )

    assert response.success
    assert response.data["asset_id"] == "ASSET-001"
    assert response.data["exposure_count"] == 1
    assert response.data["is_currently_exposed"] == True
    assert response.data["exposure_trend"] == "unknown"


@pytest.mark.asyncio
async def test_record_asset_multiple_exposures(threat_memory_mcp):
    """Test asset với multiple exposures"""
    asset_id = "ASSET-CRITICAL"

    # First exposure
    await threat_memory_mcp.record_asset_exposure(
        asset_id=asset_id,
        asset_name="Critical Server",
        exposure_type="cve",
        cve_id="CVE-2021-44228"
    )

    # Second exposure
    response = await threat_memory_mcp.record_asset_exposure(
        asset_id=asset_id,
        asset_name="Critical Server",
        exposure_type="ioc_detected",
        ioc_id="IP-MALWARE"
    )

    assert response.success
    assert response.data["exposure_count"] == 2
    assert response.data["is_currently_exposed"] == True


@pytest.mark.asyncio
async def test_record_asset_invalid_exposure_type(threat_memory_mcp):
    """Test ghi nhận asset với invalid exposure type"""
    response = await threat_memory_mcp.record_asset_exposure(
        asset_id="ASSET-TEST",
        asset_name="Test",
        exposure_type="invalid_type"
    )

    assert not response.success
    assert "Invalid exposure_type" in response.error


# ============================================================
# TEST 4: INFRASTRUCTURE REUSE RECORDING
# ============================================================

@pytest.mark.asyncio
async def test_record_infrastructure_use(threat_memory_mcp):
    """Test ghi nhận sử dụng infrastructure"""
    response = await threat_memory_mcp.record_infrastructure_use(
        infrastructure_id="INFRA-C2-CLUSTER-1",
        node_type="domain",
        node_value="c2.attacker.com",
        campaign_id="CAMPAIGN-APT28"
    )

    assert response.success
    assert response.data["infrastructure_id"] == "INFRA-C2-CLUSTER-1"
    assert response.data["reuse_count"] == 1
    assert "CAMPAIGN-APT28" in response.data["associated_campaigns"]


@pytest.mark.asyncio
async def test_record_infrastructure_reuse(threat_memory_mcp):
    """Test infrastructure được tái sử dụng"""
    infra_id = "INFRA-REUSED"

    # First use
    await threat_memory_mcp.record_infrastructure_use(
        infrastructure_id=infra_id,
        node_type="ip",
        node_value="192.168.1.100",
        campaign_id="CAMPAIGN-APT28"
    )

    # Second use (different campaign)
    response = await threat_memory_mcp.record_infrastructure_use(
        infrastructure_id=infra_id,
        node_type="ip",
        node_value="192.168.1.100",
        campaign_id="CAMPAIGN-LAZARUS"
    )

    assert response.success
    assert response.data["reuse_count"] == 2
    assert len(response.data["associated_campaigns"]) == 2


@pytest.mark.asyncio
async def test_record_infrastructure_invalid_node_type(threat_memory_mcp):
    """Test ghi nhận infrastructure với invalid node type"""
    response = await threat_memory_mcp.record_infrastructure_use(
        infrastructure_id="INFRA-TEST",
        node_type="invalid_type",
        node_value="test.com"
    )

    assert not response.success
    assert "Invalid node_type" in response.error


# ============================================================
# TEST 5: EXPLOITATION PATTERN RECORDING
# ============================================================

@pytest.mark.asyncio
async def test_record_exploitation_pattern(threat_memory_mcp):
    """Test ghi nhận exploitation pattern"""
    response = await threat_memory_mcp.record_exploitation_pattern(
        pattern_id="PATTERN-T1566-PHISHING",
        pattern_name="Spear Phishing with Attachment",
        technique_id="T1566",
        technique_name="Phishing",
        campaign_id="CAMPAIGN-APT28",
        success=True,
        target_count=3
    )

    assert response.success
    assert response.data["pattern_id"] == "PATTERN-T1566-PHISHING"
    assert response.data["occurrence_count"] == 1
    assert response.data["success_rate"] == 1.0  # 1 success / 1 total


@pytest.mark.asyncio
async def test_record_exploitation_pattern_evolution(threat_memory_mcp):
    """Test pattern success rate calculation"""
    pattern_id = "PATTERN-EVOLVE"

    # First occurrence (successful)
    await threat_memory_mcp.record_exploitation_pattern(
        pattern_id=pattern_id,
        pattern_name="Test Pattern",
        technique_id="T1595",
        technique_name="Active Scanning",
        success=True
    )

    # Second occurrence (unsuccessful)
    response = await threat_memory_mcp.record_exploitation_pattern(
        pattern_id=pattern_id,
        pattern_name="Test Pattern",
        technique_id="T1595",
        technique_name="Active Scanning",
        success=False
    )

    assert response.success
    assert response.data["occurrence_count"] == 2
    assert response.data["success_rate"] == 0.5  # 1 success / 2 total


# ============================================================
# TEST 6: MEMORY ANALYSIS
# ============================================================

@pytest.mark.asyncio
async def test_get_memory_summary(threat_memory_mcp):
    """Test lấy memory summary"""
    # Record some data first
    await threat_memory_mcp.record_ioc_occurrence(
        ioc_id="IP-1", ioc_value="192.168.1.1", context="test"
    )
    await threat_memory_mcp.record_campaign_activity(
        campaign_id="CAMP-1", campaign_name="Test", activity_type="exploit"
    )

    response = await threat_memory_mcp.get_memory_analysis(
        analysis_type="summary"
    )

    assert response.success
    assert response.data["ioc_memory_count"] == 1
    assert response.data["campaign_memory_count"] == 1
    assert response.execution_time_ms >= 0


@pytest.mark.asyncio
async def test_get_memory_timeline(threat_memory_mcp):
    """Test lấy memory timeline"""
    # Record some data
    await threat_memory_mcp.record_ioc_occurrence(
        ioc_id="IP-1", ioc_value="192.168.1.1", context="test"
    )

    response = await threat_memory_mcp.get_memory_analysis(
        analysis_type="timeline",
        days_back=30
    )

    assert response.success
    assert "timeline_events_count" in response.data
    assert "recent_events" in response.data


@pytest.mark.asyncio
async def test_get_threat_landscape(threat_memory_mcp):
    """Test threat landscape analysis"""
    # Record multiple occurrences
    for i in range(2):
        await threat_memory_mcp.record_ioc_occurrence(
            ioc_id="IP-RECURRING",
            ioc_value="192.168.1.1",
            context=f"context_{i}",
            campaign_id=f"CAMP-{i}"
        )

    response = await threat_memory_mcp.get_memory_analysis(
        analysis_type="threat_landscape"
    )

    assert response.success
    assert "threat_landscape" in response.data
    assert response.data["threat_landscape"]["recurring_iocs_count"] >= 1


@pytest.mark.asyncio
async def test_get_memory_invalid_analysis_type(threat_memory_mcp):
    """Test get_memory_analysis dengan invalid type"""
    response = await threat_memory_mcp.get_memory_analysis(
        analysis_type="invalid_type"
    )

    assert not response.success
    assert "Invalid analysis_type" in response.error


# ============================================================
# TEST 7: WRAPPER INTEGRATION (Agent calls)
# ============================================================

def test_memory_record_ioc_wrapper():
    """Test memory_record_ioc_occurrence wrapper"""
    response = memory_record_ioc_occurrence(
        ioc_id="IP-WRAP-001",
        ioc_value="192.168.1.1",
        context="test",
        severity="high"
    )

    assert response["success"]
    assert response["data"]["ioc_id"] == "IP-WRAP-001"
    assert response["data"]["occurrence_count"] == 1


def test_memory_record_campaign_wrapper():
    """Test memory_record_campaign_activity wrapper"""
    response = memory_record_campaign_activity(
        campaign_id="CAMP-WRAP-001",
        campaign_name="Test Campaign",
        activity_type="exploit",
        targets_count=5
    )

    assert response["success"]
    assert response["data"]["campaign_id"] == "CAMP-WRAP-001"
    assert response["data"]["activity_count"] == 1


def test_memory_record_asset_wrapper():
    """Test memory_record_asset_exposure wrapper"""
    response = memory_record_asset_exposure(
        asset_id="ASSET-WRAP-001",
        asset_name="Test Asset",
        exposure_type="cve",
        cve_id="CVE-2021-44228"
    )

    assert response["success"]
    assert response["data"]["asset_id"] == "ASSET-WRAP-001"
    assert response["data"]["exposure_count"] == 1


def test_memory_record_infrastructure_wrapper():
    """Test memory_record_infrastructure_use wrapper"""
    response = memory_record_infrastructure_use(
        infrastructure_id="INFRA-WRAP-001",
        node_type="domain",
        node_value="test.com",
        campaign_id="CAMP-TEST"
    )

    assert response["success"]
    assert response["data"]["infrastructure_id"] == "INFRA-WRAP-001"
    assert response["data"]["reuse_count"] == 1


def test_memory_record_pattern_wrapper():
    """Test memory_record_exploitation_pattern wrapper"""
    response = memory_record_exploitation_pattern(
        pattern_id="PATTERN-WRAP-001",
        pattern_name="Test Pattern",
        technique_id="T1595",
        technique_name="Active Scanning",
        success=True
    )

    assert response["success"]
    assert response["data"]["pattern_id"] == "PATTERN-WRAP-001"
    assert response["data"]["success_rate"] == 1.0


def test_memory_get_analysis_wrapper():
    """Test memory_get_analysis wrapper"""
    response = memory_get_analysis(
        analysis_type="summary"
    )

    assert response["success"]
    assert "ioc_memory_count" in response["data"]


# ============================================================
# TEST 8: PERFORMANCE
# ============================================================

@pytest.mark.asyncio
async def test_record_ioc_performance(threat_memory_mcp):
    """Test IOC recording performance"""
    response = await threat_memory_mcp.record_ioc_occurrence(
        ioc_id="PERF-TEST-1",
        ioc_value="192.168.1.1",
        context="test"
    )

    # Should be < 50ms
    assert response.execution_time_ms < 50


@pytest.mark.asyncio
async def test_record_campaign_performance(threat_memory_mcp):
    """Test campaign recording performance"""
    response = await threat_memory_mcp.record_campaign_activity(
        campaign_id="PERF-CAMP",
        campaign_name="Test",
        activity_type="exploit"
    )

    # Should be < 50ms
    assert response.execution_time_ms < 50


@pytest.mark.asyncio
async def test_memory_analysis_performance(threat_memory_mcp):
    """Test memory analysis performance"""
    # Record multiple items
    for i in range(5):
        await threat_memory_mcp.record_ioc_occurrence(
            ioc_id=f"IP-PERF-{i}",
            ioc_value=f"192.168.1.{i}",
            context="perf_test"
        )

    response = await threat_memory_mcp.get_memory_analysis(
        analysis_type="threat_landscape"
    )

    # Should be < 200ms
    assert response.execution_time_ms < 200


# ============================================================
# TEST 9: INTEGRATION WITH AGENTS
# ============================================================

def test_threat_memory_mcp_in_tools_mapping():
    """Test Threat Memory MCP tools trong TOOLS_MAPPING"""
    from agents.base import TOOLS_MAPPING

    # Kiểm tra tất cả 6 tools trong mapping
    memory_tools = [
        "memory_record_ioc_occurrence",
        "memory_record_campaign_activity",
        "memory_record_asset_exposure",
        "memory_record_infrastructure_use",
        "memory_record_exploitation_pattern",
        "memory_get_analysis"
    ]

    for tool_name in memory_tools:
        assert tool_name in TOOLS_MAPPING, f"{tool_name} not in TOOLS_MAPPING"
        assert TOOLS_MAPPING[tool_name] is not None


def test_threat_memory_mcp_in_tool_permissions():
    """Test Threat Memory MCP tools trong TOOL_PERMISSIONS"""
    from agents.base import TOOL_PERMISSIONS

    # agent_analyst nên có quyền truy cập tất cả memory tools
    analyst_tools = TOOL_PERMISSIONS.get("agent_analyst", [])
    memory_tools = [
        "memory_record_ioc_occurrence",
        "memory_record_campaign_activity",
        "memory_record_asset_exposure",
        "memory_record_infrastructure_use",
        "memory_record_exploitation_pattern",
        "memory_get_analysis"
    ]

    for tool_name in memory_tools:
        assert tool_name in analyst_tools, f"{tool_name} not in agent_analyst permissions"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
