"""
tools/mcp_threat_memory_wrappers.py - Tool wrappers cho Threat Memory MCP

Cung cấp các tool functions cho agents gọi qua TOOLS_MAPPING.
Mỗi wrapper chuyển đổi agent call → MCP call.
"""

import asyncio
import json
from typing import Dict, Any, Optional, List
import logging

from tools.mcp_threat_memory import get_threat_memory_mcp_server, ThreatMemoryMCPResponse
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
    """Lấy Threat Memory MCP server instance"""
    return get_threat_memory_mcp_server(_get_repository())


# ============================================================
# WRAPPER FUNCTIONS (for agents/TOOLS_MAPPING)
# ============================================================

def memory_record_ioc_occurrence(
    ioc_id: str,
    ioc_value: str,
    context: str,
    campaign_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    severity: str = "unknown",
    confidence: float = 0.5,
) -> Dict[str, Any]:
    """Wrapper: Record IOC occurrence in memory

    Used by agents via TOOLS_MAPPING["memory_record_ioc_occurrence"]

    Args:
        ioc_id: IOC identifier
        ioc_value: IOC value
        context: Where/how observed
        campaign_id: Associated campaign ID (optional)
        asset_id: Associated asset ID (optional)
        severity: unknown, low, medium, high, critical
        confidence: Confidence score (0.0-1.0)

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: ThreatMemoryMCPResponse = asyncio.run(
            mcp.record_ioc_occurrence(
                ioc_id, ioc_value, context, campaign_id, asset_id, severity, confidence
            )
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in memory_record_ioc_occurrence wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def memory_record_campaign_activity(
    campaign_id: str,
    campaign_name: str,
    activity_type: str,
    targets_count: int = 0,
    techniques_used: Optional[List[str]] = None,
    severity: str = "unknown",
    confidence: float = 0.5,
) -> Dict[str, Any]:
    """Wrapper: Record campaign activity in memory

    Used by agents via TOOLS_MAPPING["memory_record_campaign_activity"]

    Args:
        campaign_id: Campaign ID
        campaign_name: Campaign name
        activity_type: exploit, reconnaissance, malware_delivery, c2_communication, data_exfiltration
        targets_count: Number of targets affected
        techniques_used: List of MITRE ATT&CK technique IDs
        severity: unknown, low, medium, high, critical
        confidence: Confidence score

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: ThreatMemoryMCPResponse = asyncio.run(
            mcp.record_campaign_activity(
                campaign_id, campaign_name, activity_type, targets_count,
                techniques_used, severity, confidence
            )
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in memory_record_campaign_activity wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def memory_record_asset_exposure(
    asset_id: str,
    asset_name: str,
    exposure_type: str,
    cve_id: Optional[str] = None,
    ioc_id: Optional[str] = None,
    severity: str = "unknown",
) -> Dict[str, Any]:
    """Wrapper: Record asset exposure in memory

    Used by agents via TOOLS_MAPPING["memory_record_asset_exposure"]

    Args:
        asset_id: Asset ID
        asset_name: Asset name
        exposure_type: cve, ioc_detected, malware, anomaly
        cve_id: Associated CVE ID (optional)
        ioc_id: Associated IOC ID (optional)
        severity: unknown, low, medium, high, critical

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: ThreatMemoryMCPResponse = asyncio.run(
            mcp.record_asset_exposure(
                asset_id, asset_name, exposure_type, cve_id, ioc_id, severity
            )
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in memory_record_asset_exposure wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def memory_record_infrastructure_use(
    infrastructure_id: str,
    node_type: str,
    node_value: str,
    campaign_id: Optional[str] = None,
    malware_family: Optional[str] = None,
) -> Dict[str, Any]:
    """Wrapper: Record infrastructure use in memory

    Used by agents via TOOLS_MAPPING["memory_record_infrastructure_use"]

    Args:
        infrastructure_id: Infrastructure cluster ID
        node_type: ip, domain, c2, proxy, vps
        node_value: IP address, domain name, etc
        campaign_id: Associated campaign ID (optional)
        malware_family: Associated malware family (optional)

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: ThreatMemoryMCPResponse = asyncio.run(
            mcp.record_infrastructure_use(
                infrastructure_id, node_type, node_value, campaign_id, malware_family
            )
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in memory_record_infrastructure_use wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def memory_record_exploitation_pattern(
    pattern_id: str,
    pattern_name: str,
    technique_id: str,
    technique_name: str,
    campaign_id: Optional[str] = None,
    success: bool = False,
    target_count: int = 0,
) -> Dict[str, Any]:
    """Wrapper: Record exploitation pattern in memory

    Used by agents via TOOLS_MAPPING["memory_record_exploitation_pattern"]

    Args:
        pattern_id: Pattern ID
        pattern_name: Pattern name
        technique_id: MITRE ATT&CK technique ID
        technique_name: MITRE ATT&CK technique name
        campaign_id: Associated campaign ID (optional)
        success: Whether exploitation was successful
        target_count: Number of targets affected

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: ThreatMemoryMCPResponse = asyncio.run(
            mcp.record_exploitation_pattern(
                pattern_id, pattern_name, technique_id, technique_name,
                campaign_id, success, target_count
            )
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in memory_record_exploitation_pattern wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def memory_get_analysis(
    analysis_type: str = "summary",
    days_back: int = 30,
    min_recurring: int = 2,
) -> Dict[str, Any]:
    """Wrapper: Get memory analysis

    Used by agents via TOOLS_MAPPING["memory_get_analysis"]

    Args:
        analysis_type: summary, detailed, timeline, threat_landscape
        days_back: Number of days to analyze
        min_recurring: Minimum occurrences for recurring detection

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: ThreatMemoryMCPResponse = asyncio.run(
            mcp.get_memory_analysis(analysis_type, days_back, min_recurring)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in memory_get_analysis wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


# ============================================================
# TOOL DESCRIPTIONS (for agents)
# ============================================================

THREAT_MEMORY_MCP_TOOLS_DESCRIPTION = """
THREAT MEMORY MCP TOOLS - Quản lý persistent threat memory:

RECORDING:
- memory_record_ioc_occurrence(ioc_id, ioc_value, context, campaign_id, asset_id): Ghi nhận IOC xuất hiện
  Returns: occurrence_count, reuse_frequency, is_recurring

- memory_record_campaign_activity(campaign_id, campaign_name, activity_type, targets_count, techniques_used): Ghi nhận hoạt động chiến dịch
  Returns: activity_count, is_active, techniques_evolution

- memory_record_asset_exposure(asset_id, asset_name, exposure_type, cve_id, ioc_id): Ghi nhận asset exposure
  Returns: exposure_count, is_currently_exposed, exposure_trend

- memory_record_infrastructure_use(infrastructure_id, node_type, node_value, campaign_id): Ghi nhận sử dụng infrastructure
  Returns: reuse_count, associated_campaigns, nodes_count

- memory_record_exploitation_pattern(pattern_id, pattern_name, technique_id, technique_name, campaign_id, success): Ghi nhận pattern khai thác
  Returns: occurrence_count, success_rate, adopting_campaigns

ANALYSIS:
- memory_get_analysis(analysis_type, days_back, min_recurring): Lấy phân tích toàn bộ memory
  Types: summary, detailed, timeline, threat_landscape
  Returns: memory counts + threat landscape overview
"""
