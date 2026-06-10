"""
tools/mcp_ioc_wrappers.py - Tool wrappers cho IOC MCP

Cung cấp các tool functions cho agents gọi qua TOOLS_MAPPING.
"""

import asyncio
from typing import Dict, Any, Optional, List
import logging

from tools.mcp_ioc import get_ioc_mcp_server, IOCMCPResponse
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
    """Lấy IOC MCP server instance"""
    return get_ioc_mcp_server(_get_repository())


# ============================================================
# WRAPPER FUNCTIONS
# ============================================================

def ioc_lookup_ioc(
    ioc_value: str,
    ioc_type: Optional[str] = None,
    include_reputation: bool = True,
    include_related: bool = True
) -> Dict[str, Any]:
    """Wrapper: Lookup IOC và lấy thông tin chi tiết

    Used by agents via TOOLS_MAPPING["ioc_lookup_ioc"]

    Args:
        ioc_value: IOC value (IP, domain, hash, URL, email)
        ioc_type: Optional type hint (ip, domain, hash, url, email)
        include_reputation: Include reputation scores
        include_related: Include related IOCs

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: IOCMCPResponse = asyncio.run(
            mcp.lookup_ioc(ioc_value, ioc_type, include_reputation, include_related)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in ioc_lookup_ioc wrapper: {str(e)}")
        return {"success": False, "error": str(e)}


def ioc_classify_ioc(
    ioc_value: str,
    ioc_type: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Wrapper: Phân loại IOC (malware, C2, phishing, etc)

    Used by agents via TOOLS_MAPPING["ioc_classify_ioc"]

    Args:
        ioc_value: IOC value
        ioc_type: Optional type hint
        context: Additional context (campaign, threat_actor, etc)

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: IOCMCPResponse = asyncio.run(
            mcp.classify_ioc(ioc_value, ioc_type, context)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in ioc_classify_ioc wrapper: {str(e)}")
        return {"success": False, "error": str(e)}


def ioc_correlate_iocs(
    ioc_values: List[str],
    correlation_type: str = "infrastructure",
    max_results: int = 50
) -> Dict[str, Any]:
    """Wrapper: Tìm liên hệ giữa các IOC

    Used by agents via TOOLS_MAPPING["ioc_correlate_iocs"]

    Args:
        ioc_values: List của IOC values để correlate
        correlation_type: infrastructure, campaign, actor, malware
        max_results: Số lượng kết quả (1-500)

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: IOCMCPResponse = asyncio.run(
            mcp.correlate_iocs(ioc_values, correlation_type, max_results)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in ioc_correlate_iocs wrapper: {str(e)}")
        return {"success": False, "error": str(e)}


def ioc_get_ioc_context(
    ioc_value: str,
    ioc_type: Optional[str] = None,
    include_campaigns: bool = True,
    include_actors: bool = True,
    include_timeline: bool = True
) -> Dict[str, Any]:
    """Wrapper: Lấy context đầy đủ (campaigns, actors, timeline)

    Used by agents via TOOLS_MAPPING["ioc_get_ioc_context"]

    Args:
        ioc_value: IOC value
        ioc_type: Optional type hint
        include_campaigns: Include campaign associations
        include_actors: Include threat actor associations
        include_timeline: Include historical timeline

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: IOCMCPResponse = asyncio.run(
            mcp.get_ioc_context(
                ioc_value, ioc_type, include_campaigns, include_actors, include_timeline
            )
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in ioc_get_ioc_context wrapper: {str(e)}")
        return {"success": False, "error": str(e)}


def ioc_record_ioc_sighting(
    ioc_value: str,
    ioc_type: Optional[str] = None,
    source: str = "unknown",
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Wrapper: Ghi nhận IOC sighting cho tracking

    Used by agents via TOOLS_MAPPING["ioc_record_ioc_sighting"]

    Args:
        ioc_value: IOC value
        ioc_type: Optional type hint
        source: Source của sighting (network_sensor, email_gateway, endpoint, etc)
        context: Additional context (timestamp, location, etc)

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: IOCMCPResponse = asyncio.run(
            mcp.record_ioc_sighting(ioc_value, ioc_type, source, context)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in ioc_record_ioc_sighting wrapper: {str(e)}")
        return {"success": False, "error": str(e)}


# ============================================================
# TOOL DESCRIPTIONS
# ============================================================

IOC_MCP_TOOLS_DESCRIPTION = """
IOC MCP TOOLS - Quản lý IOC/Indicators:

LOOKUP:
- ioc_lookup_ioc(ioc_value, ioc_type, include_reputation, include_related): Tìm IOC chi tiết
  Returns: ioc_value, ioc_type, local_records, external_records, reputation, related_iocs

CLASSIFICATION:
- ioc_classify_ioc(ioc_value, ioc_type, context): Phân loại IOC (malware, C2, phishing)
  Returns: classification, threat_level, threat_associations, confidence

CORRELATION:
- ioc_correlate_iocs(ioc_values, correlation_type, max_results): Tìm liên hệ giữa IOC
  Returns: correlations[], detected_patterns[], relationships[], correlation_count

CONTEXT:
- ioc_get_ioc_context(ioc_value, ioc_type, campaigns, actors, timeline): Lấy context đầy đủ
  Returns: campaigns[], threat_actors[], timeline[], historical_analysis

TRACKING:
- ioc_record_ioc_sighting(ioc_value, ioc_type, source, context): Ghi nhận sighting
  Returns: sighting_recorded, total_sightings, first_seen, last_seen, timestamp
"""
