"""
tools/mcp_log_wrappers.py - Tool wrappers cho Log MCP

Cung cấp các tool functions cho agents gọi qua TOOLS_MAPPING.
"""

import asyncio
from typing import Dict, Any, Optional, List
import logging

from tools.mcp_log import get_log_mcp_server, LogMCPResponse
from core.sqlite_repository import SQLiteRepository

logger = logging.getLogger(__name__)

_repository = None


def _get_repository():
    """Lấy singleton repository instance"""
    global _repository
    if _repository is None:
        _repository = SQLiteRepository("data/threat_knowledge.db")
    return _repository


def _get_mcp():
    """Lấy Log MCP server instance"""
    return get_log_mcp_server(_get_repository())


# ============================================================
# WRAPPER FUNCTIONS
# ============================================================

def log_collect_logs(
    log_source: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    filter_severity: Optional[str] = None,
    max_results: int = 100
) -> Dict[str, Any]:
    """Wrapper: Thu thập logs từ source

    Used by agents via TOOLS_MAPPING["log_collect_logs"]

    Args:
        log_source: Log source (syslog, windows_event, apache, firewall, etc)
        start_time: ISO format timestamp để filter
        end_time: ISO format timestamp để filter
        filter_severity: INFO, WARNING, ERROR, CRITICAL
        max_results: Số lượng logs (1-1000)

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: LogMCPResponse = asyncio.run(
            mcp.collect_logs(log_source, start_time, end_time, filter_severity, max_results)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in log_collect_logs wrapper: {str(e)}")
        return {"success": False, "error": str(e)}


def log_detect_security_events(
    log_data: List[Dict[str, Any]],
    detection_rules: Optional[List[str]] = None,
    include_context: bool = True
) -> Dict[str, Any]:
    """Wrapper: Phát hiện security events từ logs

    Used by agents via TOOLS_MAPPING["log_detect_security_events"]

    Args:
        log_data: List của log entries
        detection_rules: Optional list của rule names
        include_context: Include surrounding logs

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: LogMCPResponse = asyncio.run(
            mcp.detect_security_events(log_data, detection_rules, include_context)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in log_detect_security_events wrapper: {str(e)}")
        return {"success": False, "error": str(e)}


def log_generate_alert(
    event_type: str,
    severity: str,
    description: str,
    source: Optional[str] = None,
    affected_assets: Optional[List[str]] = None,
    actions: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Wrapper: Tạo alert từ event

    Used by agents via TOOLS_MAPPING["log_generate_alert"]

    Args:
        event_type: Event type (intrusion, malware, policy_violation, etc)
        severity: CRITICAL, HIGH, MEDIUM, LOW
        description: Alert description
        source: Source của alert
        affected_assets: Assets bị ảnh hưởng
        actions: Recommended actions

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: LogMCPResponse = asyncio.run(
            mcp.generate_alert(event_type, severity, description, source, affected_assets, actions)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in log_generate_alert wrapper: {str(e)}")
        return {"success": False, "error": str(e)}


def log_analyze_log_patterns(
    log_data: List[Dict[str, Any]],
    pattern_type: str = "frequency",
    time_window: int = 3600
) -> Dict[str, Any]:
    """Wrapper: Phân tích mô hình logs

    Used by agents via TOOLS_MAPPING["log_analyze_log_patterns"]

    Args:
        log_data: List của log entries
        pattern_type: frequency, anomaly, cluster
        time_window: Time window in seconds

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: LogMCPResponse = asyncio.run(
            mcp.analyze_log_patterns(log_data, pattern_type, time_window)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in log_analyze_log_patterns wrapper: {str(e)}")
        return {"success": False, "error": str(e)}


def log_correlate_log_events(
    log_sources: List[str],
    correlation_window: int = 300,
    include_chain_analysis: bool = True
) -> Dict[str, Any]:
    """Wrapper: Tương quan events giữa các log sources

    Used by agents via TOOLS_MAPPING["log_correlate_log_events"]

    Args:
        log_sources: List của log sources để correlate
        correlation_window: Time window in seconds
        include_chain_analysis: Include attack chain analysis

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: LogMCPResponse = asyncio.run(
            mcp.correlate_log_events(log_sources, correlation_window, include_chain_analysis)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in log_correlate_log_events wrapper: {str(e)}")
        return {"success": False, "error": str(e)}


# ============================================================
# TOOL DESCRIPTIONS
# ============================================================

LOG_MCP_TOOLS_DESCRIPTION = """
LOG MCP TOOLS - Quản lý logs và security events:

COLLECTION:
- log_collect_logs(log_source, start_time, end_time, filter_severity, max_results): Thu thập logs
  Returns: logs[], total_count, filter_severity, time_range

DETECTION:
- log_detect_security_events(log_data, detection_rules, include_context): Phát hiện events
  Returns: detected_events[], event_count, threat_level, context_logs

ALERTING:
- log_generate_alert(event_type, severity, description, source, affected_assets, actions): Tạo alert
  Returns: alert_created, alert_id, escalation_required, escalation_level

ANALYSIS:
- log_analyze_log_patterns(log_data, pattern_type, time_window): Phân tích mô hình
  Returns: patterns[], pattern_count, anomaly_score

CORRELATION:
- log_correlate_log_events(log_sources, correlation_window, include_chain_analysis): Tương quan events
  Returns: correlations[], correlation_count, attack_chain, severity_summary
"""
