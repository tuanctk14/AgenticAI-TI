"""
tools/mcp_threat_memory.py - Threat Memory MCP Server

Cung cấp giao diện công cụ cho persistent threat memory operations:
- IOC occurrence recording and retrieval
- Campaign persistence tracking
- Asset exposure history
- Infrastructure reuse patterns
- Exploitation pattern memory

Tái sử dụng:
- core/threat_memory.py (ThreatMemoryEngine, 5 memory types)
- core/pattern_detection.py (pattern analysis)
- core/historical_context.py (timeline building)
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from dataclasses import dataclass
import logging

from core.threat_memory import (
    ThreatMemoryEngine,
    RecurringIOCMemory,
    CampaignPersistenceMemory,
    AssetExposureHistoryMemory,
    InfrastructureReuseMemory,
    ExploitationPatternMemory,
)
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine
from core.threat_repository import ThreatKnowledgeRepository

logger = logging.getLogger(__name__)


# ============================================================
# RESPONSE MODELS
# ============================================================

@dataclass
class ThreatMemoryMCPResponse:
    """Response wrapper cho threat memory MCP operations"""
    success: bool
    data: Any = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0


# ============================================================
# THREAT MEMORY MCP SERVER
# ============================================================

class ThreatMemoryMCPServer:
    """MCP server cho threat memory operations

    Cung cấp 6 tools:
    1. record_ioc_occurrence - Ghi nhận IOC xuất hiện
    2. record_campaign_activity - Ghi nhận hoạt động chiến dịch
    3. record_asset_exposure - Ghi nhận asset exposure
    4. record_infrastructure_use - Ghi nhận sử dụng infrastructure
    5. record_exploitation_pattern - Ghi nhận pattern khai thác
    6. get_memory_analysis - Phân tích toàn bộ memory (tổng hợp)
    """

    def __init__(self, repository: ThreatKnowledgeRepository):
        """Khởi tạo Threat Memory MCP server

        Args:
            repository: Threat knowledge repository
        """
        self.repository = repository
        self.memory_engine = ThreatMemoryEngine()

        # Initialize support engines (order matters: pattern before context)
        self.pattern_engine = PatternDetectionEngine(self.memory_engine)
        self.context_engine = HistoricalContextEngine(self.memory_engine, self.pattern_engine)

    # ============================================================
    # TOOL 1: RECORD IOC OCCURRENCE
    # ============================================================

    async def record_ioc_occurrence(
        self,
        ioc_id: str,
        ioc_value: str,
        context: str,
        campaign_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        severity: str = "unknown",
        confidence: float = 0.5,
    ) -> ThreatMemoryMCPResponse:
        """Ghi nhận xuất hiện của IOC

        Args:
            ioc_id: IOC identifier (IP-192.168.1.1, DOMAIN-malware.com, HASH-abc123)
            ioc_value: IOC value (192.168.1.1, malware.com, sha256hash)
            context: Where/how observed (campaign, asset, network, etc)
            campaign_id: Associated campaign ID (optional)
            asset_id: Associated asset ID (optional)
            severity: unknown, low, medium, high, critical
            confidence: Confidence score (0.0-1.0)

        Returns:
            ThreatMemoryMCPResponse with recorded IOCOccurrence and memory state
        """
        try:
            start_time = datetime.utcnow()

            # Validate severity
            valid_severities = ["unknown", "low", "medium", "high", "critical"]
            if severity.lower() not in valid_severities:
                return ThreatMemoryMCPResponse(
                    success=False,
                    error=f"Invalid severity: {severity}. Valid: {valid_severities}"
                )

            # Validate confidence
            if not (0.0 <= confidence <= 1.0):
                return ThreatMemoryMCPResponse(
                    success=False,
                    error=f"Confidence must be 0.0-1.0, got {confidence}"
                )

            # Record occurrence
            ioc_memory = self.memory_engine.record_ioc_occurrence(
                ioc_id=ioc_id,
                ioc_value=ioc_value,
                context=context,
                campaign_id=campaign_id,
                asset_id=asset_id,
                severity=severity.lower(),
                confidence=confidence
            )

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Threat Memory MCP] Recorded IOC occurrence: {ioc_id}")

            return ThreatMemoryMCPResponse(
                success=True,
                data={
                    "ioc_id": ioc_id,
                    "ioc_value": ioc_value,
                    "occurrence_count": ioc_memory.occurrence_count,
                    "last_observed": ioc_memory.last_observed.isoformat(),
                    "reuse_frequency": ioc_memory.reuse_frequency,
                    "associated_campaigns": ioc_memory.associated_campaigns,
                    "is_recurring": ioc_memory.occurrence_count > 1
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Threat Memory MCP] Error recording IOC: {str(e)}")
            return ThreatMemoryMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 2: RECORD CAMPAIGN ACTIVITY
    # ============================================================

    async def record_campaign_activity(
        self,
        campaign_id: str,
        campaign_name: str,
        activity_type: str,
        targets_count: int = 0,
        techniques_used: Optional[List[str]] = None,
        severity: str = "unknown",
        confidence: float = 0.5,
    ) -> ThreatMemoryMCPResponse:
        """Ghi nhận hoạt động của chiến dịch

        Args:
            campaign_id: Campaign identifier (CAMPAIGN-APT28-2026)
            campaign_name: Campaign name (APT28 Campaign Q2 2026)
            activity_type: exploit, reconnaissance, malware_delivery, c2_communication, data_exfiltration
            targets_count: Number of targets affected
            techniques_used: List of MITRE ATT&CK technique IDs
            severity: unknown, low, medium, high, critical
            confidence: Confidence score (0.0-1.0)

        Returns:
            ThreatMemoryMCPResponse with recorded campaign activity
        """
        try:
            start_time = datetime.utcnow()

            # Validate activity_type
            valid_types = [
                "exploit", "reconnaissance", "malware_delivery",
                "c2_communication", "data_exfiltration", "lateral_movement"
            ]
            if activity_type.lower() not in valid_types:
                return ThreatMemoryMCPResponse(
                    success=False,
                    error=f"Invalid activity_type: {activity_type}. Valid: {valid_types}"
                )

            # Validate severity
            valid_severities = ["unknown", "low", "medium", "high", "critical"]
            if severity.lower() not in valid_severities:
                return ThreatMemoryMCPResponse(
                    success=False,
                    error=f"Invalid severity: {severity}. Valid: {valid_severities}"
                )

            # Record activity
            campaign_memory = self.memory_engine.record_campaign_activity(
                campaign_id=campaign_id,
                campaign_name=campaign_name,
                activity_type=activity_type.lower(),
                targets_count=targets_count,
                techniques_used=techniques_used or [],
                severity=severity.lower(),
                confidence=confidence
            )

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Threat Memory MCP] Recorded campaign activity: {campaign_id}")

            return ThreatMemoryMCPResponse(
                success=True,
                data={
                    "campaign_id": campaign_id,
                    "campaign_name": campaign_name,
                    "activity_count": campaign_memory.activity_count,
                    "last_observed": campaign_memory.last_observed.isoformat(),
                    "is_active": campaign_memory.is_active,
                    "techniques_count": len(campaign_memory.techniques_evolution),
                    "techniques_evolution": campaign_memory.techniques_evolution
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Threat Memory MCP] Error recording campaign activity: {str(e)}")
            return ThreatMemoryMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 3: RECORD ASSET EXPOSURE
    # ============================================================

    async def record_asset_exposure(
        self,
        asset_id: str,
        asset_name: str,
        exposure_type: str,
        cve_id: Optional[str] = None,
        ioc_id: Optional[str] = None,
        severity: str = "unknown",
    ) -> ThreatMemoryMCPResponse:
        """Ghi nhận asset exposure

        Args:
            asset_id: Asset identifier (ASSET-001, SRV-APP-01)
            asset_name: Asset name (Web Server 1)
            exposure_type: cve, ioc_detected, malware, anomaly
            cve_id: Associated CVE ID (optional)
            ioc_id: Associated IOC ID (optional)
            severity: unknown, low, medium, high, critical

        Returns:
            ThreatMemoryMCPResponse with recorded exposure
        """
        try:
            start_time = datetime.utcnow()

            # Validate exposure_type
            valid_types = ["cve", "ioc_detected", "malware", "anomaly"]
            if exposure_type.lower() not in valid_types:
                return ThreatMemoryMCPResponse(
                    success=False,
                    error=f"Invalid exposure_type: {exposure_type}. Valid: {valid_types}"
                )

            # Record exposure
            asset_memory = self.memory_engine.record_asset_exposure(
                asset_id=asset_id,
                asset_name=asset_name,
                exposure_type=exposure_type.lower(),
                cve_id=cve_id,
                ioc_id=ioc_id,
                severity=severity.lower()
            )

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Threat Memory MCP] Recorded asset exposure: {asset_id}")

            return ThreatMemoryMCPResponse(
                success=True,
                data={
                    "asset_id": asset_id,
                    "asset_name": asset_name,
                    "exposure_count": asset_memory.exposure_count,
                    "last_exposure": asset_memory.last_exposure.isoformat(),
                    "is_currently_exposed": asset_memory.is_currently_exposed,
                    "exposure_frequency": asset_memory.exposure_frequency,
                    "exposure_trend": asset_memory.exposure_trend
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Threat Memory MCP] Error recording asset exposure: {str(e)}")
            return ThreatMemoryMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 4: RECORD INFRASTRUCTURE USE
    # ============================================================

    async def record_infrastructure_use(
        self,
        infrastructure_id: str,
        node_type: str,
        node_value: str,
        campaign_id: Optional[str] = None,
        malware_family: Optional[str] = None,
    ) -> ThreatMemoryMCPResponse:
        """Ghi nhận sử dụng infrastructure

        Args:
            infrastructure_id: Infrastructure cluster ID (INFRA-C2-CLUSTER-1)
            node_type: ip, domain, c2, proxy, vps
            node_value: 192.168.1.1, malware.com, c2.attacker.com
            campaign_id: Associated campaign ID (optional)
            malware_family: Associated malware family (optional)

        Returns:
            ThreatMemoryMCPResponse with recorded infrastructure use
        """
        try:
            start_time = datetime.utcnow()

            # Validate node_type
            valid_types = ["ip", "domain", "c2", "proxy", "vps"]
            if node_type.lower() not in valid_types:
                return ThreatMemoryMCPResponse(
                    success=False,
                    error=f"Invalid node_type: {node_type}. Valid: {valid_types}"
                )

            # Record infrastructure use
            infra_memory = self.memory_engine.record_infrastructure_use(
                infrastructure_id=infrastructure_id,
                node_type=node_type.lower(),
                node_value=node_value,
                campaign_id=campaign_id,
                malware_family=malware_family
            )

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Threat Memory MCP] Recorded infrastructure use: {infrastructure_id}")

            return ThreatMemoryMCPResponse(
                success=True,
                data={
                    "infrastructure_id": infrastructure_id,
                    "node_type": node_type.lower(),
                    "reuse_count": infra_memory.reuse_count,
                    "last_observed": infra_memory.last_observed.isoformat(),
                    "associated_campaigns": infra_memory.associated_campaigns,
                    "nodes_count": len(infra_memory.nodes)
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Threat Memory MCP] Error recording infrastructure use: {str(e)}")
            return ThreatMemoryMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 5: RECORD EXPLOITATION PATTERN
    # ============================================================

    async def record_exploitation_pattern(
        self,
        pattern_id: str,
        pattern_name: str,
        technique_id: str,
        technique_name: str,
        campaign_id: Optional[str] = None,
        success: bool = False,
        target_count: int = 0,
    ) -> ThreatMemoryMCPResponse:
        """Ghi nhận exploitation pattern

        Args:
            pattern_id: Pattern identifier (PATTERN-T1566-PHISHING)
            pattern_name: Pattern name (Spear Phishing with Attachment)
            technique_id: MITRE ATT&CK technique ID (T1566)
            technique_name: MITRE ATT&CK technique name (Phishing)
            campaign_id: Associated campaign ID (optional)
            success: Whether exploitation was successful
            target_count: Number of targets affected

        Returns:
            ThreatMemoryMCPResponse with recorded pattern
        """
        try:
            start_time = datetime.utcnow()

            # Record pattern
            pattern_memory = self.memory_engine.record_exploitation_pattern(
                pattern_id=pattern_id,
                pattern_name=pattern_name,
                technique_id=technique_id,
                technique_name=technique_name,
                campaign_id=campaign_id,
                success=success,
                target_count=target_count
            )

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Threat Memory MCP] Recorded exploitation pattern: {pattern_id}")

            return ThreatMemoryMCPResponse(
                success=True,
                data={
                    "pattern_id": pattern_id,
                    "pattern_name": pattern_name,
                    "technique_id": technique_id,
                    "occurrence_count": pattern_memory.occurrence_count,
                    "success_rate": pattern_memory.success_rate,
                    "last_observed": pattern_memory.last_observed.isoformat(),
                    "adopting_campaigns": pattern_memory.adopting_campaigns
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Threat Memory MCP] Error recording pattern: {str(e)}")
            return ThreatMemoryMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 6: GET MEMORY ANALYSIS
    # ============================================================

    async def get_memory_analysis(
        self,
        analysis_type: str = "summary",
        days_back: int = 30,
        min_recurring: int = 2,
    ) -> ThreatMemoryMCPResponse:
        """Lấy phân tích toàn bộ memory

        Args:
            analysis_type: summary, detailed, timeline, threat_landscape
            days_back: Number of days to analyze (for timeline)
            min_recurring: Minimum occurrences for recurring detection

        Returns:
            ThreatMemoryMCPResponse with memory analysis
        """
        try:
            start_time = datetime.utcnow()

            # Validate analysis_type
            valid_types = ["summary", "detailed", "timeline", "threat_landscape"]
            if analysis_type.lower() not in valid_types:
                return ThreatMemoryMCPResponse(
                    success=False,
                    error=f"Invalid analysis_type: {analysis_type}. Valid: {valid_types}"
                )

            # Get base summary
            summary = self.memory_engine.get_memory_summary()

            if analysis_type.lower() == "summary":
                analysis_data = summary

            elif analysis_type.lower() == "timeline":
                timeline = self.memory_engine.get_threat_timeline(days_back=days_back)
                analysis_data = {
                    **summary,
                    "timeline_events_count": len(timeline),
                    "recent_events": timeline[-10:] if timeline else [],  # Last 10 events
                    "days_back": days_back
                }

            elif analysis_type.lower() == "threat_landscape":
                # Threat landscape: recurring entities + active campaigns + exposed assets
                recurring_iocs = self.memory_engine.get_recurring_iocs(min_occurrences=min_recurring)
                active_campaigns = self.memory_engine.get_active_campaigns()
                exposed_assets = self.memory_engine.get_exposed_assets()
                reused_infra = self.memory_engine.get_reused_infrastructure(min_reuses=min_recurring)
                effective_patterns = self.memory_engine.get_effective_patterns(min_success_rate=0.3)

                analysis_data = {
                    **summary,
                    "threat_landscape": {
                        "recurring_iocs_count": len(recurring_iocs),
                        "recurring_iocs": [
                            {
                                "ioc_id": ioc.ioc_id,
                                "ioc_value": ioc.ioc_value,
                                "occurrence_count": ioc.occurrence_count,
                                "reuse_frequency": ioc.reuse_frequency
                            }
                            for ioc in recurring_iocs[:5]  # Top 5
                        ],
                        "active_campaigns_count": len(active_campaigns),
                        "active_campaigns": [
                            {
                                "campaign_id": camp.campaign_id,
                                "campaign_name": camp.campaign_name,
                                "activity_count": camp.activity_count,
                                "last_observed": camp.last_observed.isoformat()
                            }
                            for camp in active_campaigns[:5]
                        ],
                        "exposed_assets_count": len(exposed_assets),
                        "exposed_assets": [
                            {
                                "asset_id": asset.asset_id,
                                "asset_name": asset.asset_name,
                                "exposure_count": asset.exposure_count,
                                "exposure_frequency": asset.exposure_frequency
                            }
                            for asset in exposed_assets[:5]
                        ],
                        "reused_infrastructure_count": len(reused_infra),
                        "effective_patterns_count": len(effective_patterns)
                    }
                }

            else:  # detailed
                recurring_iocs = self.memory_engine.get_recurring_iocs(min_occurrences=min_recurring)
                active_campaigns = self.memory_engine.get_active_campaigns()
                exposed_assets = self.memory_engine.get_exposed_assets()

                analysis_data = {
                    **summary,
                    "detailed_breakdown": {
                        "recurring_iocs": [ioc.ioc_id for ioc in recurring_iocs[:10]],
                        "active_campaigns": [c.campaign_id for c in active_campaigns[:10]],
                        "exposed_assets": [a.asset_id for a in exposed_assets[:10]]
                    }
                }

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Threat Memory MCP] Generated {analysis_type} analysis")

            return ThreatMemoryMCPResponse(
                success=True,
                data=analysis_data,
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Threat Memory MCP] Error getting memory analysis: {str(e)}")
            return ThreatMemoryMCPResponse(
                success=False,
                error=str(e)
            )


# ============================================================
# SINGLETON INSTANCE
# ============================================================

_threat_memory_mcp_instance: Optional[ThreatMemoryMCPServer] = None


def get_threat_memory_mcp_server(repository: ThreatKnowledgeRepository) -> ThreatMemoryMCPServer:
    """Lấy singleton instance của Threat Memory MCP server

    Args:
        repository: Threat knowledge repository

    Returns:
        ThreatMemoryMCPServer instance
    """
    global _threat_memory_mcp_instance
    if _threat_memory_mcp_instance is None:
        _threat_memory_mcp_instance = ThreatMemoryMCPServer(repository)
    return _threat_memory_mcp_instance
