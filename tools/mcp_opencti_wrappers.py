"""
tools/mcp_opencti_wrappers.py - Tool wrappers cho OpenCTI MCP

Cung cấp các tool functions cho agents gọi qua TOOLS_MAPPING.
Mỗi wrapper chuyển đổi agent call → MCP call.
"""

import asyncio
from typing import Dict, Any, Optional, List
import logging

from tools.mcp_opencti import get_opencti_mcp_server, OpenCTIMCPResponse
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
    """Lấy OpenCTI MCP server instance"""
    return get_opencti_mcp_server(_get_repository())


# ============================================================
# WRAPPER FUNCTIONS (for agents/TOOLS_MAPPING)
# ============================================================

def opencti_query_indicators(
    search_term: str,
    indicator_type: str = "all",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    max_results: int = 50
) -> Dict[str, Any]:
    """Wrapper: Query IOC/Indicators from OpenCTI

    Used by agents via TOOLS_MAPPING["opencti_query_indicators"]

    Args:
        search_term: Indicator to search (IP, domain, hash)
        indicator_type: all, indicator, malware, threat_actor, attack_pattern
        start_date: ISO format date filter
        end_date: ISO format date filter
        max_results: Number of results (1-500)

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: OpenCTIMCPResponse = asyncio.run(
            mcp.query_indicators(search_term, indicator_type, start_date, end_date, max_results)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in opencti_query_indicators wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def opencti_get_malware_info(
    malware_name: str,
    include_variants: bool = True
) -> Dict[str, Any]:
    """Wrapper: Get malware family information

    Used by agents via TOOLS_MAPPING["opencti_get_malware_info"]

    Args:
        malware_name: Malware family name (Emotet, Trickbot, etc)
        include_variants: Include malware variants

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: OpenCTIMCPResponse = asyncio.run(
            mcp.get_malware_info(malware_name, include_variants)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in opencti_get_malware_info wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def opencti_get_threat_actor_profile(
    actor_name: str,
    include_relationships: bool = True
) -> Dict[str, Any]:
    """Wrapper: Get threat actor profile

    Used by agents via TOOLS_MAPPING["opencti_get_threat_actor_profile"]

    Args:
        actor_name: Threat actor name (APT28, Lazarus, etc)
        include_relationships: Include campaign/malware relationships

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: OpenCTIMCPResponse = asyncio.run(
            mcp.get_threat_actor_profile(actor_name, include_relationships)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in opencti_get_threat_actor_profile wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def opencti_get_campaign_info(
    campaign_name: str,
    include_iocs: bool = True
) -> Dict[str, Any]:
    """Wrapper: Get campaign information

    Used by agents via TOOLS_MAPPING["opencti_get_campaign_info"]

    Args:
        campaign_name: Campaign name
        include_iocs: Include associated IOCs

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: OpenCTIMCPResponse = asyncio.run(
            mcp.get_campaign_info(campaign_name, include_iocs)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in opencti_get_campaign_info wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


def opencti_get_attack_patterns(
    search_term: Optional[str] = None,
    max_results: int = 50
) -> Dict[str, Any]:
    """Wrapper: Get attack patterns/MITRE techniques

    Used by agents via TOOLS_MAPPING["opencti_get_attack_patterns"]

    Args:
        search_term: Search for specific pattern (optional)
        max_results: Number of results

    Returns:
        Dict with success/data/error
    """
    try:
        mcp = _get_mcp()
        response: OpenCTIMCPResponse = asyncio.run(
            mcp.get_attack_patterns(search_term, max_results)
        )

        return {
            "success": response.success,
            "data": response.data,
            "error": response.error,
            "execution_time_ms": response.execution_time_ms
        }
    except Exception as e:
        logger.error(f"Error in opencti_get_attack_patterns wrapper: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


# ============================================================
# TOOL DESCRIPTIONS (for agents)
# ============================================================

OPENCTI_MCP_TOOLS_DESCRIPTION = """
OPENCTI MCP TOOLS - Tích hợp OpenCTI threat intelligence:

IOC SEARCH:
- opencti_query_indicators(search_term, indicator_type, start_date, end_date): Tìm IOC từ OpenCTI
  Types: all, indicator, malware, threat_actor, attack_pattern
  Returns: indicators[], results_count, source

MALWARE:
- opencti_get_malware_info(malware_name, include_variants): Lấy thông tin malware family
  Returns: malware_types, aliases, variants[], source

THREAT ACTORS:
- opencti_get_threat_actor_profile(actor_name, include_relationships): Lấy profil threat actor
  Returns: aliases, description, score, relationships_count

CAMPAIGNS:
- opencti_get_campaign_info(campaign_name, include_iocs): Lấy thông tin campaign
  Returns: total_entities, iocs[], entity_breakdown

ATTACK PATTERNS:
- opencti_get_attack_patterns(search_term, max_results): Lấy MITRE ATT&CK patterns
  Returns: patterns[], patterns_count, source
"""
