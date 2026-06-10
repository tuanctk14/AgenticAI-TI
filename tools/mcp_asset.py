"""
tools/mcp_asset.py - Asset Management MCP Server

Cung cấp giao diện công cụ cho asset management operations:
- Asset registration and details
- Vulnerability exposure tracking
- Remediation management
- Risk scoring

Tái sử dụng:
- tools/cmdb.py (CMDB operations)
- tools/analyzer.py (risk analysis)
- tools/risk_scorer.py (risk calculation)
- core/threat_memory.py (asset exposure history)
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from dataclasses import dataclass
import logging
import json
import os

from tools.cmdb import list_all_devices
from core.threat_repository import ThreatKnowledgeRepository
from core.threat_memory import ThreatMemoryEngine

logger = logging.getLogger(__name__)


# ============================================================
# RESPONSE MODELS
# ============================================================

@dataclass
class AssetMCPResponse:
    """Response wrapper cho asset MCP operations"""
    success: bool
    data: Any = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0


# ============================================================
# ASSET DATA MODELS
# ============================================================

class Asset:
    """Asset entity model"""
    def __init__(
        self,
        asset_id: str,
        hostname: str,
        asset_type: str,
        software: List[Dict[str, Any]],
        os: str,
        ip_address: Optional[str] = None,
        criticality: str = "medium"
    ):
        self.asset_id = asset_id
        self.hostname = hostname
        self.asset_type = asset_type  # server, workstation, appliance
        self.software = software  # List of installed software
        self.os = os
        self.ip_address = ip_address
        self.criticality = criticality  # low, medium, high, critical
        self.first_seen = datetime.utcnow()
        self.last_seen = datetime.utcnow()
        self.exposure_count = 0
        self.cves_affecting = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "hostname": self.hostname,
            "asset_type": self.asset_type,
            "software": self.software,
            "os": self.os,
            "ip_address": self.ip_address,
            "criticality": self.criticality,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "exposure_count": self.exposure_count,
            "cves_affecting": self.cves_affecting
        }


# ============================================================
# ASSET MCP SERVER
# ============================================================

class AssetMCPServer:
    """MCP server cho asset management operations

    Cung cấp 5 tools:
    1. register_asset - Đăng ký asset vào CMDB
    2. get_asset_details - Lấy chi tiết asset
    3. list_asset_exposures - Liệt kê các exposures của asset
    4. update_asset_remediation - Cập nhật trạng thái remediation
    5. get_asset_risk_score - Tính risk score cho asset
    """

    def __init__(self, repository: ThreatKnowledgeRepository):
        """Khởi tạo Asset MCP server

        Args:
            repository: Threat knowledge repository
        """
        self.repository = repository
        self.memory_engine = ThreatMemoryEngine()
        self.cmdb_path = os.path.join(os.path.dirname(__file__), "..", "data", "cmdb_devices.json")
        self._load_cmdb()

    def _load_cmdb(self):
        """Load CMDB from file"""
        try:
            with open(self.cmdb_path, "r", encoding="utf-8") as f:
                self.cmdb = json.load(f)
        except FileNotFoundError:
            logger.warning(f"CMDB file not found at {self.cmdb_path}, using empty CMDB")
            self.cmdb = []
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse CMDB JSON at {self.cmdb_path}")
            self.cmdb = []

    def _save_cmdb(self):
        """Save CMDB to file"""
        try:
            os.makedirs(os.path.dirname(self.cmdb_path), exist_ok=True)
            with open(self.cmdb_path, "w", encoding="utf-8") as f:
                json.dump(self.cmdb, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save CMDB: {str(e)}")

    # ============================================================
    # TOOL 1: REGISTER ASSET
    # ============================================================

    async def register_asset(
        self,
        asset_id: str,
        hostname: str,
        asset_type: str,
        software: List[Dict[str, str]],
        os: str,
        ip_address: Optional[str] = None,
        criticality: str = "medium"
    ) -> AssetMCPResponse:
        """Đăng ký asset mới vào CMDB

        Args:
            asset_id: Asset identifier (ASSET-001, SRV-APP-01)
            hostname: Device hostname
            asset_type: server, workstation, appliance, network_device
            software: List of installed software [{"name": "Apache", "version": "2.4.41"}]
            os: Operating system (Linux, Windows, macOS)
            ip_address: IP address (optional)
            criticality: low, medium, high, critical

        Returns:
            AssetMCPResponse with registered asset details
        """
        try:
            start_time = datetime.utcnow()

            # Validate asset_type
            valid_types = ["server", "workstation", "appliance", "network_device"]
            if asset_type.lower() not in valid_types:
                return AssetMCPResponse(
                    success=False,
                    error=f"Invalid asset_type: {asset_type}. Valid: {valid_types}"
                )

            # Validate criticality
            valid_criticality = ["low", "medium", "high", "critical"]
            if criticality.lower() not in valid_criticality:
                return AssetMCPResponse(
                    success=False,
                    error=f"Invalid criticality: {criticality}. Valid: {valid_criticality}"
                )

            # Check if asset already exists
            for device in self.cmdb:
                if device.get("asset_id") == asset_id:
                    return AssetMCPResponse(
                        success=False,
                        error=f"Asset {asset_id} already exists in CMDB"
                    )

            # Create new asset
            new_asset = {
                "asset_id": asset_id,
                "hostname": hostname,
                "asset_type": asset_type.lower(),
                "software": software,
                "os": os,
                "ip_address": ip_address,
                "criticality": criticality.lower(),
                "first_seen": datetime.utcnow().isoformat(),
                "last_seen": datetime.utcnow().isoformat()
            }

            self.cmdb.append(new_asset)
            self._save_cmdb()

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Asset MCP] Registered asset: {asset_id} ({hostname})")

            return AssetMCPResponse(
                success=True,
                data={
                    "asset_id": asset_id,
                    "hostname": hostname,
                    "asset_type": asset_type.lower(),
                    "software_count": len(software),
                    "criticality": criticality.lower(),
                    "ip_address": ip_address,
                    "status": "registered"
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Asset MCP] Error registering asset: {str(e)}")
            return AssetMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 2: GET ASSET DETAILS
    # ============================================================

    async def get_asset_details(
        self,
        asset_id: str,
        include_cves: bool = True
    ) -> AssetMCPResponse:
        """Lấy chi tiết asset từ CMDB

        Args:
            asset_id: Asset identifier
            include_cves: Include affecting CVEs

        Returns:
            AssetMCPResponse with asset details
        """
        try:
            start_time = datetime.utcnow()

            # Find asset in CMDB
            asset = None
            for device in self.cmdb:
                if device.get("asset_id") == asset_id:
                    asset = device
                    break

            if not asset:
                return AssetMCPResponse(
                    success=False,
                    error=f"Asset {asset_id} not found in CMDB"
                )

            # Get memory information
            asset_memory = self.memory_engine.get_asset_memory(asset_id)

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Asset MCP] Retrieved asset details: {asset_id}")

            response_data = {
                **asset,
                "last_retrieved": datetime.utcnow().isoformat(),
                "exposure_history": {
                    "exposure_count": asset_memory.exposure_count if asset_memory else 0,
                    "is_currently_exposed": asset_memory.is_currently_exposed if asset_memory else False,
                    "exposure_frequency": asset_memory.exposure_frequency if asset_memory else 0.0,
                    "exposure_trend": asset_memory.exposure_trend if asset_memory else "unknown"
                } if asset_memory else None
            }

            if include_cves and asset_memory:
                response_data["cves_affecting_count"] = len(asset_memory.exposures)

            return AssetMCPResponse(
                success=True,
                data=response_data,
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Asset MCP] Error getting asset details: {str(e)}")
            return AssetMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 3: LIST ASSET EXPOSURES
    # ============================================================

    async def list_asset_exposures(
        self,
        asset_id: str,
        exposure_type: Optional[str] = None,
        min_severity: str = "MEDIUM"
    ) -> AssetMCPResponse:
        """Liệt kê tất cả exposures của asset

        Args:
            asset_id: Asset identifier
            exposure_type: cve, ioc_detected, malware, anomaly (optional)
            min_severity: Minimum severity (LOW, MEDIUM, HIGH, CRITICAL)

        Returns:
            AssetMCPResponse with exposure list
        """
        try:
            start_time = datetime.utcnow()

            # Validate min_severity
            valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if min_severity.upper() not in valid_severities:
                return AssetMCPResponse(
                    success=False,
                    error=f"Invalid min_severity: {min_severity}. Valid: {valid_severities}"
                )

            # Get asset memory
            asset_memory = self.memory_engine.get_asset_memory(asset_id)

            if not asset_memory:
                return AssetMCPResponse(
                    success=True,
                    data={
                        "asset_id": asset_id,
                        "exposure_count": 0,
                        "exposures": [],
                        "status": "no_exposures_recorded"
                    },
                    execution_time_ms=0.0
                )

            # Filter exposures
            exposures = []
            for exposure in asset_memory.exposures:
                # Filter by type
                if exposure_type and exposure.exposure_type != exposure_type.lower():
                    continue

                # Filter by severity (if provided)
                severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
                exp_severity = exposure.cve_id.split("-")[0] if exposure.cve_id else "MEDIUM"
                if severity_order.get(exp_severity, 1) < severity_order.get(min_severity.upper(), 1):
                    continue

                exposures.append({
                    "date": exposure.date.isoformat(),
                    "exposure_type": exposure.exposure_type,
                    "cve_id": exposure.cve_id,
                    "ioc_id": exposure.ioc_id,
                    "exposure_duration_days": exposure.exposure_duration_days,
                    "remediation_action": exposure.remediation_action,
                    "remediation_date": exposure.remediation_date.isoformat() if exposure.remediation_date else None
                })

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Asset MCP] Listed exposures for asset: {asset_id} ({len(exposures)} found)")

            return AssetMCPResponse(
                success=True,
                data={
                    "asset_id": asset_id,
                    "exposure_count": len(exposures),
                    "exposures": exposures,
                    "first_exposure": asset_memory.first_exposure.isoformat() if asset_memory.first_exposure else None,
                    "last_exposure": asset_memory.last_exposure.isoformat() if asset_memory.last_exposure else None,
                    "exposure_frequency": asset_memory.exposure_frequency
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Asset MCP] Error listing exposures: {str(e)}")
            return AssetMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 4: UPDATE ASSET REMEDIATION
    # ============================================================

    async def update_asset_remediation(
        self,
        asset_id: str,
        exposure_duration_days: int,
        remediation_action: str,
        action_status: str = "completed"
    ) -> AssetMCPResponse:
        """Cập nhật trạng thái remediation cho asset exposure

        Args:
            asset_id: Asset identifier
            exposure_duration_days: How many days asset was exposed
            remediation_action: Description of remediation action taken
            action_status: completed, in_progress, planned, failed

        Returns:
            AssetMCPResponse with remediation update
        """
        try:
            start_time = datetime.utcnow()

            # Validate action_status
            valid_statuses = ["completed", "in_progress", "planned", "failed"]
            if action_status.lower() not in valid_statuses:
                return AssetMCPResponse(
                    success=False,
                    error=f"Invalid action_status: {action_status}. Valid: {valid_statuses}"
                )

            # Record remediation
            asset_memory = self.memory_engine.record_asset_remediation(
                asset_id=asset_id,
                exposure_duration_days=exposure_duration_days,
                action=remediation_action
            )

            if not asset_memory:
                return AssetMCPResponse(
                    success=False,
                    error=f"No exposures found for asset {asset_id} to remediate"
                )

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Asset MCP] Updated remediation for asset: {asset_id}")

            return AssetMCPResponse(
                success=True,
                data={
                    "asset_id": asset_id,
                    "action_status": action_status.lower(),
                    "remediation_action": remediation_action,
                    "exposure_duration_days": exposure_duration_days,
                    "is_currently_exposed": asset_memory.is_currently_exposed,
                    "average_exposure_duration": asset_memory.average_exposure_duration_days
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Asset MCP] Error updating remediation: {str(e)}")
            return AssetMCPResponse(
                success=False,
                error=str(e)
            )

    # ============================================================
    # TOOL 5: GET ASSET RISK SCORE
    # ============================================================

    async def get_asset_risk_score(
        self,
        asset_id: str,
        include_trend: bool = True
    ) -> AssetMCPResponse:
        """Tính risk score cho asset

        Args:
            asset_id: Asset identifier
            include_trend: Include risk trend analysis

        Returns:
            AssetMCPResponse with risk score breakdown
        """
        try:
            start_time = datetime.utcnow()

            # Find asset in CMDB
            asset = None
            for device in self.cmdb:
                if device.get("asset_id") == asset_id:
                    asset = device
                    break

            if not asset:
                return AssetMCPResponse(
                    success=False,
                    error=f"Asset {asset_id} not found in CMDB"
                )

            # Get asset memory
            asset_memory = self.memory_engine.get_asset_memory(asset_id)

            # Calculate risk components
            base_score = 0.0
            criticality_weights = {"low": 0.2, "medium": 0.4, "high": 0.7, "critical": 1.0}
            criticality_factor = criticality_weights.get(asset.get("criticality", "medium").lower(), 0.5)

            # Exposure-based risk
            exposure_risk = 0.0
            if asset_memory:
                exposure_risk = min(1.0, asset_memory.exposure_frequency * 0.5)
                base_score += exposure_risk * 0.4

            # Criticality-based risk
            base_score += criticality_factor * 0.4

            # Software complexity risk
            software_count = len(asset.get("software", []))
            complexity_risk = min(1.0, software_count / 10.0)
            base_score += complexity_risk * 0.2

            # Final score (0.0-10.0)
            risk_score = base_score * 10.0

            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(f"[Asset MCP] Calculated risk score for asset: {asset_id} = {risk_score:.1f}")

            return AssetMCPResponse(
                success=True,
                data={
                    "asset_id": asset_id,
                    "risk_score": round(risk_score, 2),
                    "risk_level": _get_risk_level(risk_score),
                    "components": {
                        "exposure_risk": round(exposure_risk, 3),
                        "criticality_risk": round(criticality_factor, 3),
                        "complexity_risk": round(complexity_risk, 3)
                    },
                    "exposure_count": asset_memory.exposure_count if asset_memory else 0,
                    "is_currently_exposed": asset_memory.is_currently_exposed if asset_memory else False,
                    "exposure_trend": asset_memory.exposure_trend if asset_memory else "unknown",
                    "recommendation": _get_risk_recommendation(risk_score)
                },
                execution_time_ms=elapsed
            )
        except Exception as e:
            logger.error(f"[Asset MCP] Error calculating risk score: {str(e)}")
            return AssetMCPResponse(
                success=False,
                error=str(e)
            )


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def _get_risk_level(score: float) -> str:
    """Get risk level from score"""
    if score >= 8.0:
        return "CRITICAL"
    elif score >= 6.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def _get_risk_recommendation(score: float) -> str:
    """Get recommendation based on risk score"""
    if score >= 8.0:
        return "IMMEDIATE ACTION REQUIRED: Apply critical patches, isolate if necessary"
    elif score >= 6.0:
        return "HIGH PRIORITY: Schedule patching immediately, increase monitoring"
    elif score >= 4.0:
        return "MEDIUM PRIORITY: Plan patching in next maintenance window"
    else:
        return "LOW PRIORITY: Monitor for updates, schedule routine patching"


# ============================================================
# SINGLETON INSTANCE
# ============================================================

_asset_mcp_instance: Optional[AssetMCPServer] = None


def get_asset_mcp_server(repository: ThreatKnowledgeRepository) -> AssetMCPServer:
    """Lấy singleton instance của Asset MCP server

    Args:
        repository: Threat knowledge repository

    Returns:
        AssetMCPServer instance
    """
    global _asset_mcp_instance
    if _asset_mcp_instance is None:
        _asset_mcp_instance = AssetMCPServer(repository)
    return _asset_mcp_instance
