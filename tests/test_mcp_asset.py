"""
tests/test_mcp_asset.py - Test suite cho Asset MCP

Kiểm tra:
1. Asset registration
2. Asset details retrieval
3. Asset exposure listing
4. Remediation updates
5. Risk scoring
6. Agent integration via wrappers
"""

import pytest
import asyncio
from datetime import datetime

from tools.mcp_asset import AssetMCPServer, AssetMCPResponse
from tools.mcp_asset_wrappers import (
    asset_register,
    asset_get_details,
    asset_list_exposures,
    asset_update_remediation,
    asset_get_risk_score
)
from core.sqlite_repository import SQLiteRepository


@pytest.fixture
def test_db():
    """Tạo test database"""
    return SQLiteRepository(":memory:")


@pytest.fixture
def asset_mcp(test_db):
    """Tạo Asset MCP server instance"""
    return AssetMCPServer(test_db)


# ============================================================
# TEST 1: ASSET REGISTRATION
# ============================================================

@pytest.mark.asyncio
async def test_register_asset(asset_mcp):
    """Test đăng ký asset mới"""
    response = await asset_mcp.register_asset(
        asset_id="ASSET-001",
        hostname="web-server-01",
        asset_type="server",
        software=[
            {"name": "Apache", "version": "2.4.41"},
            {"name": "OpenSSL", "version": "1.1.1"}
        ],
        os="Linux",
        ip_address="192.168.1.10",
        criticality="high"
    )

    assert response.success
    assert response.data["asset_id"] == "ASSET-001"
    assert response.data["hostname"] == "web-server-01"
    assert response.data["software_count"] == 2
    assert response.data["criticality"] == "high"
    assert response.data["status"] == "registered"
    assert response.execution_time_ms >= 0


@pytest.mark.asyncio
async def test_register_asset_invalid_type(asset_mcp):
    """Test đăng ký asset với invalid type"""
    response = await asset_mcp.register_asset(
        asset_id="ASSET-TEST",
        hostname="test",
        asset_type="invalid_type",
        software=[],
        os="Linux"
    )

    assert not response.success
    assert "Invalid asset_type" in response.error


@pytest.mark.asyncio
async def test_register_asset_invalid_criticality(asset_mcp):
    """Test đăng ký asset với invalid criticality"""
    response = await asset_mcp.register_asset(
        asset_id="ASSET-TEST",
        hostname="test",
        asset_type="server",
        software=[],
        os="Linux",
        criticality="invalid"
    )

    assert not response.success
    assert "Invalid criticality" in response.error


@pytest.mark.asyncio
async def test_register_duplicate_asset(asset_mcp):
    """Test đăng ký asset duplicate"""
    # Register first asset
    await asset_mcp.register_asset(
        asset_id="ASSET-DUP",
        hostname="test",
        asset_type="server",
        software=[],
        os="Linux"
    )

    # Try to register again
    response = await asset_mcp.register_asset(
        asset_id="ASSET-DUP",
        hostname="test2",
        asset_type="workstation",
        software=[],
        os="Windows"
    )

    assert not response.success
    assert "already exists" in response.error


# ============================================================
# TEST 2: GET ASSET DETAILS
# ============================================================

@pytest.mark.asyncio
async def test_get_asset_details(asset_mcp):
    """Test lấy chi tiết asset"""
    # Register asset first
    await asset_mcp.register_asset(
        asset_id="ASSET-002",
        hostname="app-server",
        asset_type="server",
        software=[{"name": "Tomcat", "version": "9.0"}],
        os="Linux",
        ip_address="192.168.1.20",
        criticality="critical"
    )

    # Get details
    response = await asset_mcp.get_asset_details("ASSET-002")

    assert response.success
    assert response.data["asset_id"] == "ASSET-002"
    assert response.data["hostname"] == "app-server"
    assert response.data["criticality"] == "critical"


@pytest.mark.asyncio
async def test_get_asset_details_not_found(asset_mcp):
    """Test lấy chi tiết asset không tồn tại"""
    response = await asset_mcp.get_asset_details("ASSET-NONEXISTENT")

    assert not response.success
    assert "not found" in response.error


# ============================================================
# TEST 3: LIST ASSET EXPOSURES
# ============================================================

@pytest.mark.asyncio
async def test_list_asset_exposures_empty(asset_mcp):
    """Test liệt kê exposures khi không có"""
    response = await asset_mcp.list_asset_exposures("ASSET-NO-EXP")

    assert response.success
    assert response.data["exposure_count"] == 0
    assert response.data["exposures"] == []


@pytest.mark.asyncio
async def test_list_asset_exposures_with_data(asset_mcp):
    """Test liệt kê exposures với dữ liệu"""
    asset_id = "ASSET-EXP"

    # Record exposure
    asset_mcp.memory_engine.record_asset_exposure(
        asset_id=asset_id,
        asset_name="Exposed Asset",
        exposure_type="cve",
        cve_id="CVE-2021-44228",
        severity="critical"
    )

    response = await asset_mcp.list_asset_exposures(asset_id)

    assert response.success
    assert response.data["exposure_count"] == 1


@pytest.mark.asyncio
async def test_list_asset_exposures_invalid_severity(asset_mcp):
    """Test list exposures với invalid severity"""
    response = await asset_mcp.list_asset_exposures(
        "ASSET-001",
        min_severity="INVALID"
    )

    assert not response.success
    assert "Invalid min_severity" in response.error


# ============================================================
# TEST 4: UPDATE REMEDIATION
# ============================================================

@pytest.mark.asyncio
async def test_update_asset_remediation(asset_mcp):
    """Test cập nhật remediation"""
    asset_id = "ASSET-REMEDIATE"

    # Record exposure first
    asset_mcp.memory_engine.record_asset_exposure(
        asset_id=asset_id,
        asset_name="Test Asset",
        exposure_type="cve",
        cve_id="CVE-2021-44228"
    )

    # Update remediation
    response = await asset_mcp.update_asset_remediation(
        asset_id=asset_id,
        exposure_duration_days=5,
        remediation_action="Applied security patch",
        action_status="completed"
    )

    assert response.success
    assert response.data["action_status"] == "completed"
    assert response.data["remediation_action"] == "Applied security patch"


@pytest.mark.asyncio
async def test_update_remediation_invalid_status(asset_mcp):
    """Test update remediation với invalid status"""
    response = await asset_mcp.update_asset_remediation(
        asset_id="ASSET-001",
        exposure_duration_days=5,
        remediation_action="Test",
        action_status="invalid_status"
    )

    assert not response.success
    assert "Invalid action_status" in response.error


@pytest.mark.asyncio
async def test_update_remediation_no_exposure(asset_mcp):
    """Test update remediation khi không có exposure"""
    response = await asset_mcp.update_asset_remediation(
        asset_id="ASSET-NO-EXP",
        exposure_duration_days=5,
        remediation_action="Test"
    )

    assert not response.success
    assert "No exposures" in response.error


# ============================================================
# TEST 5: RISK SCORING
# ============================================================

@pytest.mark.asyncio
async def test_get_asset_risk_score(asset_mcp):
    """Test tính risk score"""
    # Register asset first
    await asset_mcp.register_asset(
        asset_id="ASSET-RISK",
        hostname="critical-server",
        asset_type="server",
        software=[
            {"name": "App1", "version": "1.0"},
            {"name": "App2", "version": "2.0"},
            {"name": "App3", "version": "3.0"}
        ],
        os="Linux",
        criticality="critical"
    )

    response = await asset_mcp.get_asset_risk_score("ASSET-RISK")

    assert response.success
    assert "risk_score" in response.data
    assert "risk_level" in response.data
    assert "components" in response.data
    assert "recommendation" in response.data
    assert 0 <= response.data["risk_score"] <= 10


@pytest.mark.asyncio
async def test_get_risk_score_not_found(asset_mcp):
    """Test risk score untuk asset tidak tồn tại"""
    response = await asset_mcp.get_asset_risk_score("ASSET-NONEXISTENT")

    assert not response.success
    assert "not found" in response.error


# ============================================================
# TEST 6: WRAPPER INTEGRATION (Agent calls)
# ============================================================

def test_asset_register_wrapper():
    """Test asset_register wrapper"""
    response = asset_register(
        asset_id="ASSET-WRAP-001",
        hostname="test-server",
        asset_type="server",
        software=[{"name": "Apache", "version": "2.4"}],
        os="Linux",
        ip_address="192.168.1.100",
        criticality="high"
    )

    assert response["success"]
    assert response["data"]["asset_id"] == "ASSET-WRAP-001"


def test_asset_get_details_wrapper():
    """Test asset_get_details wrapper"""
    # Register first
    asset_register(
        asset_id="ASSET-WRAP-002",
        hostname="app-server",
        asset_type="server",
        software=[],
        os="Linux"
    )

    # Get details
    response = asset_get_details("ASSET-WRAP-002")

    assert response["success"]
    assert response["data"]["asset_id"] == "ASSET-WRAP-002"


def test_asset_list_exposures_wrapper():
    """Test asset_list_exposures wrapper"""
    response = asset_list_exposures("ASSET-WRAP-001")

    assert response["success"]
    assert "exposure_count" in response["data"]


def test_asset_update_remediation_wrapper():
    """Test asset_update_remediation wrapper"""
    # This will fail as no exposure exists, but wrapper should work
    response = asset_update_remediation(
        asset_id="ASSET-WRAP-001",
        exposure_duration_days=3,
        remediation_action="Test action"
    )

    # Should handle error gracefully
    assert "success" in response


def test_asset_get_risk_score_wrapper():
    """Test asset_get_risk_score wrapper"""
    # Register first
    asset_register(
        asset_id="ASSET-WRAP-RISK",
        hostname="test",
        asset_type="server",
        software=[],
        os="Linux",
        criticality="medium"
    )

    response = asset_get_risk_score("ASSET-WRAP-RISK")

    assert response["success"]
    assert "risk_score" in response["data"]


# ============================================================
# TEST 7: PERFORMANCE
# ============================================================

@pytest.mark.asyncio
async def test_register_asset_performance(asset_mcp):
    """Test registration performance"""
    response = await asset_mcp.register_asset(
        asset_id="ASSET-PERF-1",
        hostname="test",
        asset_type="server",
        software=[],
        os="Linux"
    )

    assert response.execution_time_ms < 100


@pytest.mark.asyncio
async def test_get_risk_score_performance(asset_mcp):
    """Test risk score calculation performance"""
    # Register asset
    await asset_mcp.register_asset(
        asset_id="ASSET-PERF-RISK",
        hostname="test",
        asset_type="server",
        software=[],
        os="Linux"
    )

    response = await asset_mcp.get_asset_risk_score("ASSET-PERF-RISK")

    assert response.execution_time_ms < 100


# ============================================================
# TEST 8: INTEGRATION WITH AGENTS
# ============================================================

def test_asset_mcp_in_tools_mapping():
    """Test Asset MCP tools dalam TOOLS_MAPPING"""
    from agents.base import TOOLS_MAPPING

    asset_tools = [
        "asset_register",
        "asset_get_details",
        "asset_list_exposures",
        "asset_update_remediation",
        "asset_get_risk_score"
    ]

    for tool_name in asset_tools:
        assert tool_name in TOOLS_MAPPING, f"{tool_name} not in TOOLS_MAPPING"
        assert TOOLS_MAPPING[tool_name] is not None


def test_asset_mcp_in_tool_permissions():
    """Test Asset MCP tools trong TOOL_PERMISSIONS"""
    from agents.base import TOOL_PERMISSIONS

    # agent_device should have asset tools
    device_tools = TOOL_PERMISSIONS.get("agent_device", [])
    asset_tools = [
        "asset_register",
        "asset_get_details",
        "asset_list_exposures",
        "asset_update_remediation",
        "asset_get_risk_score"
    ]

    # At least some asset tools should be there
    found_count = sum(1 for tool in asset_tools if tool in device_tools)
    assert found_count >= 2, f"Not enough asset tools in agent_device permissions"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
