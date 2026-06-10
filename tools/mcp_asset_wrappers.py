"""
tools/mcp_asset_wrappers.py - Tool wrappers cho Asset MCP

Cung cấp các tool functions cho agents gọi qua TOOLS_MAPPING.
Mỗi wrapper chuyển đổi agent call → MCP call.
"""

import asyncio
from typing import Dict, Any, Optional, List
import logging

from tools.mcp_asset import get_asset_mcp_server, AssetMCPResponse
from core.sqlite_repository import SQLiteRepository

logger = logging.getLogger(__name__)

# Lazy-load repository
_repository = None


def _get_repository():
    """Lấy singleton repository instance"""
    global _repository
    if _repository is None:
        _repository = SQLiteRepository("data/threat_knowledge.db")
    return _repository


def _get_mcp():
    """Lấy Asset MCP server instance"""
    return get_asset_mcp_server(_get_repository())


# ============================================================
# WRAPPER FUNCTIONS (for agents/TOOLS_MAPPING)
# ============================================================

def asset_register(
    asset_id: str,
    hostname: str,
    asset_type: str,
    software: List[Dict[str, str]],
    os: str,
    ip_address: Optional[str] = None,
    criticality: str = "medium"
) -> Dict[str, Any]:
    """Wrapper: Register asset to CMDB

    Used by agents via TOOLS_MAPPING["asset_register"]

    Args:
        asset_id: Asset ID (ASSET-001)
        hostname: Device hostname
        asset_type: server, workstation, appliance, network_device
        software: List of installed software
        os: Operating system
        ip_address: IP address (optional)
        criticality: low, medium, high, critical

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: AssetMCPResponse = asyncio.run(
            mcp.register_asset(asset_id, hostname, asset_type, software, os, ip_address, criticality)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in asset_register wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def asset_get_details(
    asset_id: str,
    include_cves: bool = True
) -> Dict[str, Any]:
    """Wrapper: Get asset details

    Used by agents via TOOLS_MAPPING["asset_get_details"]

    Args:
        asset_id: Asset ID
        include_cves: Include affecting CVEs

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: AssetMCPResponse = asyncio.run(
            mcp.get_asset_details(asset_id, include_cves)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in asset_get_details wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def asset_list_exposures(
    asset_id: str,
    exposure_type: Optional[str] = None,
    min_severity: str = "MEDIUM"
) -> Dict[str, Any]:
    """Wrapper: List asset exposures

    Used by agents via TOOLS_MAPPING["asset_list_exposures"]

    Args:
        asset_id: Asset ID
        exposure_type: cve, ioc_detected, malware, anomaly
        min_severity: LOW, MEDIUM, HIGH, CRITICAL

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: AssetMCPResponse = asyncio.run(
            mcp.list_asset_exposures(asset_id, exposure_type, min_severity)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in asset_list_exposures wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def asset_update_remediation(
    asset_id: str,
    exposure_duration_days: int,
    remediation_action: str,
    action_status: str = "completed"
) -> Dict[str, Any]:
    """Wrapper: Update asset remediation

    Used by agents via TOOLS_MAPPING["asset_update_remediation"]

    Args:
        asset_id: Asset ID
        exposure_duration_days: Duration of exposure
        remediation_action: Description of action taken
        action_status: completed, in_progress, planned, failed

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: AssetMCPResponse = asyncio.run(
            mcp.update_asset_remediation(asset_id, exposure_duration_days, remediation_action, action_status)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in asset_update_remediation wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def asset_get_risk_score(
    asset_id: str,
    include_trend: bool = True
) -> Dict[str, Any]:
    """Wrapper: Get asset risk score

    Used by agents via TOOLS_MAPPING["asset_get_risk_score"]

    Args:
        asset_id: Asset ID
        include_trend: Include trend analysis

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: AssetMCPResponse = asyncio.run(
            mcp.get_asset_risk_score(asset_id, include_trend)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in asset_get_risk_score wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


# ============================================================
# TOOL DESCRIPTIONS (for agents)
# ============================================================

ASSET_MCP_TOOLS_DESCRIPTION = """
ASSET MCP TOOLS - Quản lý assets và vulnerabilities:

REGISTRATION & DETAILS:
- asset_register(asset_id, hostname, asset_type, software, os, ip_address, criticality): Đăng ký asset mới
  Returns: asset_id, software_count, criticality, status

- asset_get_details(asset_id, include_cves): Lấy chi tiết asset
  Returns: hostname, software, ip_address, exposure_history

EXPOSURE TRACKING:
- asset_list_exposures(asset_id, exposure_type, min_severity): Liệt kê exposures
  Returns: exposure_count, exposures[], first_exposure, last_exposure, exposure_frequency

REMEDIATION:
- asset_update_remediation(asset_id, exposure_duration_days, remediation_action): Cập nhật remediation
  Returns: action_status, remediation_action, is_currently_exposed

RISK SCORING:
- asset_get_risk_score(asset_id, include_trend): Tính risk score
  Returns: risk_score (0-10), risk_level, components breakdown, recommendation
"""
