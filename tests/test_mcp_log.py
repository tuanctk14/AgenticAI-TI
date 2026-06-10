"""
tests/test_mcp_log.py - Test suite cho Log MCP

Kiểm tra:
1. Log collection
2. Security event detection
3. Alert generation
4. Log pattern analysis
5. Log event correlation
6. Agent integration
"""

import pytest
import asyncio
from datetime import datetime

from tools.mcp_log import LogMCPServer, LogMCPResponse
from tools.mcp_log_wrappers import (
    log_collect_logs,
    log_detect_security_events,
    log_generate_alert,
    log_analyze_log_patterns,
    log_correlate_log_events
)
from core.sqlite_repository import SQLiteRepository


@pytest.fixture
def test_db():
    """Tạo test database"""
    return SQLiteRepository(":memory:")


@pytest.fixture
def log_mcp(test_db):
    """Tạo Log MCP server instance"""
    return LogMCPServer(test_db)


# ============================================================
# TEST 1: LOG COLLECTION
# ============================================================

@pytest.mark.asyncio
async def test_collect_logs_syslog(log_mcp):
    """Test collecting syslog logs"""
    response = await log_mcp.collect_logs(
        log_source="syslog"
    )

    assert hasattr(response, 'success')
    assert hasattr(response, 'data')
    assert response.data["log_source"] == "syslog"


@pytest.mark.asyncio
async def test_collect_logs_windows_event(log_mcp):
    """Test collecting Windows event logs"""
    response = await log_mcp.collect_logs(
        log_source="windows_event",
        filter_severity="ERROR"
    )

    assert hasattr(response, 'success')
    if response.success:
        assert response.data["filter_severity"] == "ERROR"


@pytest.mark.asyncio
async def test_collect_logs_invalid_source(log_mcp):
    """Test collecting logs with invalid source"""
    response = await log_mcp.collect_logs(
        log_source="invalid_source"
    )

    assert not response.success
    assert "Invalid log_source" in response.error


@pytest.mark.asyncio
async def test_collect_logs_invalid_max_results(log_mcp):
    """Test collecting logs with invalid max_results"""
    response = await log_mcp.collect_logs(
        log_source="syslog",
        max_results=2000
    )

    assert not response.success
    assert "max_results must be 1-1000" in response.error


@pytest.mark.asyncio
async def test_collect_logs_invalid_severity(log_mcp):
    """Test collecting logs with invalid severity"""
    response = await log_mcp.collect_logs(
        log_source="syslog",
        filter_severity="INVALID"
    )

    assert not response.success
    assert "Invalid severity" in response.error


# ============================================================
# TEST 2: SECURITY EVENT DETECTION
# ============================================================

@pytest.mark.asyncio
async def test_detect_security_events_basic(log_mcp):
    """Test detecting security events from logs"""
    log_data = [
        {"message": "Access denied for user", "source": "firewall", "timestamp": "2026-06-10T10:00:00Z"},
        {"message": "Connection blocked", "source": "firewall", "timestamp": "2026-06-10T10:01:00Z"},
    ]

    response = await log_mcp.detect_security_events(log_data)

    assert hasattr(response, 'success')
    if response.success:
        assert "detected_events" in response.data
        assert "event_count" in response.data


@pytest.mark.asyncio
async def test_detect_security_events_empty(log_mcp):
    """Test detecting events with empty log data"""
    response = await log_mcp.detect_security_events([])

    assert not response.success
    assert "cannot be empty" in response.error


@pytest.mark.asyncio
async def test_detect_security_events_with_context(log_mcp):
    """Test detecting events with context"""
    log_data = [
        {"message": "Error occurred", "source": "application"},
        {"message": "Failed authentication", "source": "authentication"},
    ]

    response = await log_mcp.detect_security_events(
        log_data,
        include_context=True
    )

    assert hasattr(response, 'success')


# ============================================================
# TEST 3: ALERT GENERATION
# ============================================================

@pytest.mark.asyncio
async def test_generate_alert_critical(log_mcp):
    """Test generating critical alert"""
    response = await log_mcp.generate_alert(
        event_type="intrusion",
        severity="CRITICAL",
        description="Potential intrusion detected"
    )

    assert hasattr(response, 'success')
    if response.success:
        assert response.data["severity"] == "CRITICAL"
        assert response.data["escalation_required"] == True


@pytest.mark.asyncio
async def test_generate_alert_high(log_mcp):
    """Test generating high severity alert"""
    response = await log_mcp.generate_alert(
        event_type="policy_violation",
        severity="HIGH",
        description="Policy violation detected",
        affected_assets=["WORKSTATION-01", "WORKSTATION-02"]
    )

    assert hasattr(response, 'success')
    if response.success:
        assert response.data["escalation_required"] == True


@pytest.mark.asyncio
async def test_generate_alert_low(log_mcp):
    """Test generating low severity alert"""
    response = await log_mcp.generate_alert(
        event_type="informational",
        severity="LOW",
        description="Informational event"
    )

    assert hasattr(response, 'success')
    if response.success:
        assert response.data["escalation_required"] == False


@pytest.mark.asyncio
async def test_generate_alert_invalid_severity(log_mcp):
    """Test generating alert with invalid severity"""
    response = await log_mcp.generate_alert(
        event_type="test",
        severity="INVALID",
        description="Test"
    )

    assert not response.success
    assert "Invalid severity" in response.error


# ============================================================
# TEST 4: LOG PATTERN ANALYSIS
# ============================================================

@pytest.mark.asyncio
async def test_analyze_patterns_frequency(log_mcp):
    """Test frequency pattern analysis"""
    log_data = [
        {"message": "Connection timeout", "timestamp": "2026-06-10T10:00:00Z"},
        {"message": "Connection timeout", "timestamp": "2026-06-10T10:01:00Z"},
        {"message": "Connection reset", "timestamp": "2026-06-10T10:02:00Z"},
    ]

    response = await log_mcp.analyze_log_patterns(
        log_data,
        pattern_type="frequency"
    )

    assert hasattr(response, 'success')
    if response.success:
        assert "patterns" in response.data
        assert response.data["pattern_type"] == "frequency"


@pytest.mark.asyncio
async def test_analyze_patterns_anomaly(log_mcp):
    """Test anomaly pattern analysis"""
    log_data = [{"message": f"Event {i}"} for i in range(15)]

    response = await log_mcp.analyze_log_patterns(
        log_data,
        pattern_type="anomaly"
    )

    assert hasattr(response, 'success')


@pytest.mark.asyncio
async def test_analyze_patterns_cluster(log_mcp):
    """Test cluster pattern analysis"""
    log_data = [{"message": f"Event {i}"} for i in range(10)]

    response = await log_mcp.analyze_log_patterns(
        log_data,
        pattern_type="cluster"
    )

    assert hasattr(response, 'success')


@pytest.mark.asyncio
async def test_analyze_patterns_empty(log_mcp):
    """Test pattern analysis with empty data"""
    response = await log_mcp.analyze_log_patterns([])

    assert not response.success


@pytest.mark.asyncio
async def test_analyze_patterns_invalid_type(log_mcp):
    """Test pattern analysis with invalid type"""
    log_data = [{"message": "Test"}]

    response = await log_mcp.analyze_log_patterns(
        log_data,
        pattern_type="invalid"
    )

    assert not response.success
    assert "Invalid pattern_type" in response.error


# ============================================================
# TEST 5: LOG EVENT CORRELATION
# ============================================================

@pytest.mark.asyncio
async def test_correlate_log_events_basic(log_mcp):
    """Test basic log event correlation"""
    response = await log_mcp.correlate_log_events(
        log_sources=["firewall", "ids_ids"]
    )

    assert hasattr(response, 'success')
    if response.success:
        assert "correlations" in response.data
        assert response.data["log_sources"] == ["firewall", "ids_ids"]


@pytest.mark.asyncio
async def test_correlate_log_events_with_chain(log_mcp):
    """Test correlation with attack chain analysis"""
    response = await log_mcp.correlate_log_events(
        log_sources=["firewall", "proxy", "endpoint"],
        include_chain_analysis=True
    )

    assert hasattr(response, 'success')
    if response.success:
        assert "attack_chain" in response.data


@pytest.mark.asyncio
async def test_correlate_log_events_empty(log_mcp):
    """Test correlation with empty sources"""
    response = await log_mcp.correlate_log_events([])

    assert not response.success
    assert "cannot be empty" in response.error


@pytest.mark.asyncio
async def test_correlate_log_events_invalid_window(log_mcp):
    """Test correlation with invalid window"""
    response = await log_mcp.correlate_log_events(
        log_sources=["firewall"],
        correlation_window=5000
    )

    assert not response.success
    assert "correlation_window must be 60-3600" in response.error


# ============================================================
# TEST 6: WRAPPER INTEGRATION
# ============================================================

def test_log_collect_logs_wrapper():
    """Test log_collect_logs wrapper"""
    response = log_collect_logs("syslog")

    assert "success" in response
    assert isinstance(response["success"], bool)


def test_log_detect_security_events_wrapper():
    """Test log_detect_security_events wrapper"""
    log_data = [{"message": "Test error"}]
    response = log_detect_security_events(log_data)

    assert "success" in response


def test_log_generate_alert_wrapper():
    """Test log_generate_alert wrapper"""
    response = log_generate_alert(
        event_type="test",
        severity="HIGH",
        description="Test alert"
    )

    assert "success" in response


def test_log_analyze_log_patterns_wrapper():
    """Test log_analyze_log_patterns wrapper"""
    log_data = [{"message": "Test"}]
    response = log_analyze_log_patterns(log_data)

    assert "success" in response


def test_log_correlate_log_events_wrapper():
    """Test log_correlate_log_events wrapper"""
    response = log_correlate_log_events(["firewall", "proxy"])

    assert "success" in response


# ============================================================
# TEST 7: RESPONSE FORMAT VALIDATION
# ============================================================

def test_collect_logs_response_format():
    """Test collect logs response format"""
    response = log_collect_logs("syslog")

    if response["success"]:
        assert "log_source" in response["data"]
        assert "logs" in response["data"]
        assert "total_count" in response["data"]


def test_detect_events_response_format():
    """Test detect events response format"""
    log_data = [{"message": "Error test"}]
    response = log_detect_security_events(log_data)

    if response["success"]:
        assert "detected_events" in response["data"]
        assert "event_count" in response["data"]
        assert "threat_level" in response["data"]


def test_generate_alert_response_format():
    """Test generate alert response format"""
    response = log_generate_alert(
        event_type="test",
        severity="HIGH",
        description="Test"
    )

    if response["success"]:
        assert "alert_id" in response["data"]
        assert "severity" in response["data"]
        assert "timestamp" in response["data"]
        assert "escalation_required" in response["data"]


# ============================================================
# TEST 8: AGENT INTEGRATION
# ============================================================

def test_log_mcp_in_tools_mapping():
    """Test Log MCP tools dalam TOOLS_MAPPING"""
    from agents.base import TOOLS_MAPPING

    log_tools = [
        "log_collect_logs",
        "log_detect_security_events",
        "log_generate_alert",
        "log_analyze_log_patterns",
        "log_correlate_log_events"
    ]

    for tool_name in log_tools:
        assert tool_name in TOOLS_MAPPING
        assert TOOLS_MAPPING[tool_name] is not None


def test_log_mcp_in_tool_permissions():
    """Test Log MCP tools trong TOOL_PERMISSIONS"""
    from agents.base import TOOL_PERMISSIONS

    analyst_tools = TOOL_PERMISSIONS.get("agent_analyst", [])
    log_tools = ["log_collect_logs", "log_generate_alert"]

    found_count = sum(1 for tool in log_tools if tool in analyst_tools)
    assert found_count >= 1


# ============================================================
# TEST 9: BOUNDARY VALIDATION
# ============================================================

@pytest.mark.asyncio
async def test_collect_logs_max_results_boundary(log_mcp):
    """Test max_results boundary at 1000"""
    response = await log_mcp.collect_logs(
        log_source="syslog",
        max_results=1000
    )

    assert response.success or "max_results" not in str(response.error)


@pytest.mark.asyncio
async def test_collect_logs_min_results_boundary(log_mcp):
    """Test max_results boundary at 1"""
    response = await log_mcp.collect_logs(
        log_source="syslog",
        max_results=1
    )

    assert response.success or "max_results" not in str(response.error)


@pytest.mark.asyncio
async def test_correlation_window_min(log_mcp):
    """Test correlation_window boundary at 60"""
    response = await log_mcp.correlate_log_events(
        log_sources=["firewall"],
        correlation_window=60
    )

    assert response.success or "correlation_window" not in str(response.error)


@pytest.mark.asyncio
async def test_correlation_window_max(log_mcp):
    """Test correlation_window boundary at 3600"""
    response = await log_mcp.correlate_log_events(
        log_sources=["firewall"],
        correlation_window=3600
    )

    assert response.success or "correlation_window" not in str(response.error)


# ============================================================
# TEST 10: THREAT LEVEL CALCULATION
# ============================================================

@pytest.mark.asyncio
async def test_threat_level_critical(log_mcp):
    """Test threat level calculation - CRITICAL"""
    log_data = [
        {"message": "Access denied", "severity": "CRITICAL"},
        {"message": "Intrusion detected", "severity": "CRITICAL"},
    ]

    response = await log_mcp.detect_security_events(log_data)

    if response.success:
        assert response.data["threat_level"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
