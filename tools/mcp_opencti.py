"""
tools/mcp_opencti.py - OpenCTI Integration MCP Server

Cung cấp giao diện công cụ cho OpenCTI operations:
- IOC/Indicator querying
- Malware family lookup
- Threat actor profiling
- Campaign retrieval
- Attack pattern mapping

Tái sử dụng:
- tools/opencti_client.py (OpenCTI GraphQL API)
- core/threat_memory.py (persistence)
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from dataclasses import dataclass
import logging

from tools.opencti_client import fetch_opencti_indicators
from core.threat_repository import ThreatKnowledgeRepository
from core.threat_memory import ThreatMemoryEngine

logger = logging.getLogger(__name__)


# ============================================================
# RESPONSE MODELS
# ============================================================

@dataclass
class OpenCTIMCPResponse:
    """Response wrapper cho OpenCTI MCP operations"""
    success: bool
    data: Any = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0


# ============================================================
# OPENCTI MCP SERVER
# ============================================================

class OpenCTIMCPServer:
    """MCP server cho OpenCTI threat intelligence operations

    Cung cấp 5 tools:
    1. query_indicators - Tìm IOC/Indicators từ OpenCTI
    2. get_malware_info - Lấy thông tin malware family
    3. get_threat_actor_profile - Lấy profil threat actor
    4. get_campaign_info - Lấy thông tin campaign
    5. get_attack_patterns - Lấy attack patterns/TTPs
    """

    def __init__(self, repository: ThreatKnowledgeRepository):
        """Khởi tạo OpenCTI MCP server

        Args:
            repository: Threat knowledge repository
        """
        self.repository = repository
        self.memory_engine = ThreatMemoryEngine()

    # ============================================================
    # TOOL 1: QUERY INDICATORS (IOCs)
    # ============================================================

    async def query_indicators(
        self,
        search_term: str,
        indicator_type: str = "all",
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        max_results: int = 50
    ) -> OpenCTIMCPResponse:
        """Tìm kiếm IOC/Indicators từ OpenCTI

        Args:
            search_term: Indicator value (IP, domain, hash, etc)
            indicator_type: all, indicator, malware, threat_actor, attack_pattern
            start_date: ISO format để lọc theo ngày (optional)
            end_date: ISO format để lọc theo ngày (optional)
            max_results: Số lượng kết quả (1-500)

        Returns:
            OpenCTIMCPResponse with indicators data
        """
        try:
            start_time = datetime.utcnow()

            # Validate max_results
            if not (1 <= max_results <= 500):
                return OpenCTIMCPResponse(
                    success=False,
                    error=f"max_results must be 1-500, got {max_results}"
                )

            # Validate indicator_type
            valid_types = ["all", "indicator", "malware", "threat_actor", "attack_pattern"]
            if indicator_type.lower() not in valid_types:
                return OpenCTIMCPResponse(
                    success=False,
                    error=f"Invalid indicator_type: {indicator_type}. Valid: {valid_types}"
                )

            # Query OpenCTI
            result = fetch_opencti_indicators(
                search_term=search_term,
                indicator_type=indicator_type.lower(),
                start_date=start_date,
                end_date=end_date,
                max_results=max_results
            )

            # Check for errors
            if result.get("source") == "OpenCTI-ERROR":
                return OpenCTIMCPResponse(
                    success=False,
                    error=result.get("error", "OpenCTI query failed")
                )

            indicators = result.get("context", [])

            # Filter by type if needed
            if indicator_type.lower() != "all":
                indicators = [
                    ind for ind in indicators
                    if ind.get("entity_type", "").lower().replace(" ", "_") == indicator_type.lower()
                ]

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[OpenCTI MCP] Found {len(indicators)} indicators for: {search_term}")

            # Record findings in memory
            for indicator in indicators:
                if indicator.get("entity_type") == "Indicator":
                    self.memory_engine.record_ioc_occurrence(
                        ioc_id=indicator.get("id", search_term),
                        ioc_value=search_term,
                        context="opencti_lookup",
                        severity="unknown",
                        confidence=indicator.get("confidence", 0.5) / 100.0
                    )

            return OpenCTIMCPResponse(
                success=True,
                data={
                    "search_term": search_term,
                    "indicator_type": indicator_type.lower(),
                    "results_count": len(indicators),
                    "indicators": indicators[:50],  # Limit response
                    "source": "OpenCTI"
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[OpenCTI MCP] Error querying indicators: {str(e)}")
            return OpenCTIMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 2: GET MALWARE INFO
    # ============================================================

    async def get_malware_info(
        self,
        malware_name: str,
        include_variants: bool = True
    ) -> OpenCTIMCPResponse:
        """Lấy thông tin malware family

        Args:
            malware_name: Tên malware (Emotet, Trickbot, etc)
            include_variants: Include malware variants

        Returns:
            OpenCTIMCPResponse with malware details
        """
        try:
            start_time = datetime.utcnow()

            # Query OpenCTI for malware
            result = fetch_opencti_indicators(
                search_term=malware_name,
                indicator_type="malware",
                max_results=100
            )

            if result.get("source") == "OpenCTI-ERROR":
                return OpenCTIMCPResponse(
                    success=False,
                    error=result.get("error", "OpenCTI query failed")
                )

            malwares = result.get("context", [])

            if not malwares:
                return OpenCTIMCPResponse(
                    success=False,
                    error=f"Malware '{malware_name}' not found in OpenCTI"
                )

            # Get primary malware
            primary = malwares[0]
            variants = malwares[1:] if include_variants else []

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[OpenCTI MCP] Retrieved malware info: {malware_name}")

            return OpenCTIMCPResponse(
                success=True,
                data={
                    "malware_name": primary.get("name", malware_name),
                    "malware_types": primary.get("malware_types", []),
                    "aliases": primary.get("aliases", []),
                    "description": primary.get("description", ""),
                    "variants_count": len(variants),
                    "variants": [
                        {
                            "name": m.get("name"),
                            "types": m.get("malware_types", []),
                            "aliases": m.get("aliases", [])
                        }
                        for m in variants[:10]
                    ] if include_variants else [],
                    "source": "OpenCTI",
                    "last_updated": primary.get("created_at")
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[OpenCTI MCP] Error getting malware info: {str(e)}")
            return OpenCTIMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 3: GET THREAT ACTOR PROFILE
    # ============================================================

    async def get_threat_actor_profile(
        self,
        actor_name: str,
        include_relationships: bool = True
    ) -> OpenCTIMCPResponse:
        """Lấy profil threat actor

        Args:
            actor_name: Tên threat actor (APT28, Lazarus, etc)
            include_relationships: Include relationships to campaigns/malware

        Returns:
            OpenCTIMCPResponse with actor profile
        """
        try:
            start_time = datetime.utcnow()

            # Query OpenCTI for threat actors
            result = fetch_opencti_indicators(
                search_term=actor_name,
                indicator_type="threat_actor",
                max_results=100
            )

            if result.get("source") == "OpenCTI-ERROR":
                return OpenCTIMCPResponse(
                    success=False,
                    error=result.get("error", "OpenCTI query failed")
                )

            actors = result.get("context", [])

            if not actors:
                return OpenCTIMCPResponse(
                    success=False,
                    error=f"Threat actor '{actor_name}' not found in OpenCTI"
                )

            actor = actors[0]

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[OpenCTI MCP] Retrieved actor profile: {actor_name}")

            # Record in memory
            self.memory_engine.record_campaign_activity(
                campaign_id=f"ACTOR-{actor.get('id', actor_name)}",
                campaign_name=actor.get("name", actor_name),
                activity_type="reconnaissance",
                severity="unknown"
            )

            return OpenCTIMCPResponse(
                success=True,
                data={
                    "actor_name": actor.get("name", actor_name),
                    "actor_id": actor.get("id", ""),
                    "aliases": actor.get("aliases", []),
                    "description": actor.get("description", ""),
                    "score": actor.get("score", 0),
                    "known_relationships_count": 0,  # Would need additional query
                    "source": "OpenCTI",
                    "last_updated": actor.get("created_at")
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[OpenCTI MCP] Error getting actor profile: {str(e)}")
            return OpenCTIMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 4: GET CAMPAIGN INFO
    # ============================================================

    async def get_campaign_info(
        self,
        campaign_name: str,
        include_iocs: bool = True
    ) -> OpenCTIMCPResponse:
        """Lấy thông tin campaign từ OpenCTI

        Args:
            campaign_name: Tên campaign
            include_iocs: Include associated IOCs

        Returns:
            OpenCTIMCPResponse with campaign details
        """
        try:
            start_time = datetime.utcnow()

            # Query OpenCTI
            result = fetch_opencti_indicators(
                search_term=campaign_name,
                indicator_type="all",
                max_results=100
            )

            if result.get("source") == "OpenCTI-ERROR":
                return OpenCTIMCPResponse(
                    success=False,
                    error=result.get("error", "OpenCTI query failed")
                )

            results = result.get("context", [])

            if not results:
                return OpenCTIMCPResponse(
                    success=False,
                    error=f"Campaign '{campaign_name}' not found in OpenCTI"
                )

            # Extract IOCs if needed
            iocs = []
            if include_iocs:
                iocs = [
                    {
                        "id": r.get("id"),
                        "name": r.get("name"),
                        "type": r.get("entity_type"),
                        "pattern": r.get("pattern", "")[:100]
                    }
                    for r in results if r.get("entity_type") == "Indicator"
                ][:20]

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[OpenCTI MCP] Retrieved campaign info: {campaign_name}")

            return OpenCTIMCPResponse(
                success=True,
                data={
                    "campaign_name": campaign_name,
                    "total_entities": len(results),
                    "iocs_count": len(iocs),
                    "iocs": iocs if include_iocs else [],
                    "entity_breakdown": _get_entity_breakdown(results),
                    "source": "OpenCTI"
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[OpenCTI MCP] Error getting campaign info: {str(e)}")
            return OpenCTIMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 5: GET ATTACK PATTERNS
    # ============================================================

    async def get_attack_patterns(
        self,
        search_term: Optional[str] = None,
        max_results: int = 50
    ) -> OpenCTIMCPResponse:
        """Lấy attack patterns/MITRE ATT&CK techniques

        Args:
            search_term: Tìm kiếm pattern cụ thể (optional)
            max_results: Số lượng kết quả

        Returns:
            OpenCTIMCPResponse with attack patterns
        """
        try:
            start_time = datetime.utcnow()

            # Query OpenCTI for attack patterns
            result = fetch_opencti_indicators(
                search_term=search_term or "attack",
                indicator_type="attack_pattern",
                max_results=max_results
            )

            if result.get("source") == "OpenCTI-ERROR":
                return OpenCTIMCPResponse(
                    success=False,
                    error=result.get("error", "OpenCTI query failed")
                )

            patterns = result.get("context", [])

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[OpenCTI MCP] Retrieved {len(patterns)} attack patterns")

            return OpenCTIMCPResponse(
                success=True,
                data={
                    "search_term": search_term or "all",
                    "patterns_count": len(patterns),
                    "patterns": [
                        {
                            "id": p.get("id"),
                            "name": p.get("name"),
                            "technique_id": p.get("technique_id", "N/A"),
                            "description": p.get("description", "")[:200]
                        }
                        for p in patterns[:50]
                    ],
                    "source": "OpenCTI"
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[OpenCTI MCP] Error getting attack patterns: {str(e)}")
            return OpenCTIMCPResponse(
                success=False,
                error=str(e)
            )


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def _get_entity_breakdown(entities: List[Dict]) -> Dict[str, int]:
    """Get breakdown of entities by type"""
    breakdown = {}
    for entity in entities:
        entity_type = entity.get("entity_type", "Unknown")
        breakdown[entity_type] = breakdown.get(entity_type, 0) + 1
    return breakdown


# ============================================================
# SINGLETON INSTANCE
# ============================================================

_opencti_mcp_instance: Optional[OpenCTIMCPServer] = None


def get_opencti_mcp_server(repository: ThreatKnowledgeRepository) -> OpenCTIMCPServer:
    """Lấy singleton instance của OpenCTI MCP server

    Args:
        repository: Threat knowledge repository

    Returns:
        OpenCTIMCPServer instance
    """
    global _opencti_mcp_instance
    if _opencti_mcp_instance is None:
        _opencti_mcp_instance = OpenCTIMCPServer(repository)
    return _opencti_mcp_instance
