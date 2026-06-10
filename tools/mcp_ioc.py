"""
tools/mcp_ioc.py - IOC Management MCP Server

Cung cấp giao diện công cụ cho IOC/Indicator operations:
- IOC lookup và validation
- Pattern matching và correlation
- IOC lifecycle management
- Threat association analysis
- IOC enrichment từ multiple sources

Tái sử dụng:
- tools/ioc_correlation.py (pattern matching)
- tools/opencti_client.py (external intelligence)
- core/threat_memory.py (persistence)
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from dataclasses import dataclass
import logging
import re

from tools.ioc_correlation import IOCCorrelationEngine
from tools.opencti_client import fetch_opencti_indicators
from core.threat_memory import ThreatMemoryEngine
from core.threat_repository import ThreatKnowledgeRepository

logger = logging.getLogger(__name__)


# ============================================================
# RESPONSE MODELS
# ============================================================

@dataclass
class IOCMCPResponse:
    """Response wrapper cho IOC MCP operations"""
    success: bool
    data: Any = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0


# ============================================================
# IOC MCP SERVER
# ============================================================

class IOCMCPServer:
    """MCP server cho IOC/Indicator management operations

    Cung cấp 5 tools:
    1. lookup_ioc - Tìm IOC và lấy thông tin chi tiết
    2. classify_ioc - Phân loại IOC (malware, C2, phishing, etc)
    3. correlate_iocs - Tìm liên hệ giữa các IOC
    4. get_ioc_context - Lấy context & threat associations
    5. record_ioc_sighting - Ghi nhận IOC sighting cho tracking
    """

    def __init__(self, repository: ThreatKnowledgeRepository):
        """Khởi tạo IOC MCP server

        Args:
            repository: Threat knowledge repository
        """
        self.repository = repository
        self.memory_engine = ThreatMemoryEngine()
        self.correlation_engine = IOCCorrelationEngine()

    # ============================================================
    # TOOL 1: LOOKUP IOC
    # ============================================================

    async def lookup_ioc(
        self,
        ioc_value: str,
        ioc_type: Optional[str] = None,
        include_reputation: bool = True,
        include_related: bool = True
    ) -> IOCMCPResponse:
        """Tìm kiếm IOC và lấy thông tin chi tiết

        Args:
            ioc_value: IOC value (IP, domain, hash, URL, email)
            ioc_type: Optional type hint (ip, domain, hash, url, email)
            include_reputation: Include reputation scores
            include_related: Include related IOCs

        Returns:
            IOCMCPResponse with IOC details
        """
        try:
            start_time = datetime.utcnow()

            # Auto-detect IOC type nếu không được cung cấp
            if not ioc_type:
                ioc_type = self._detect_ioc_type(ioc_value)
                if not ioc_type:
                    return IOCMCPResponse(
                        success=False,
                        error=f"Could not detect IOC type for: {ioc_value}"
                    )

            # Validate IOC value
            if not self._validate_ioc_value(ioc_value, ioc_type):
                return IOCMCPResponse(
                    success=False,
                    error=f"Invalid {ioc_type} format: {ioc_value}"
                )

            # Query repository for local records
            local_records = self.repository.find_ioc(ioc_value)

            # Query OpenCTI for external intelligence
            external_records = await fetch_opencti_indicators(ioc_value)

            # Combine và merge
            data = {
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "local_records": local_records or [],
                "external_records": external_records or [],
                "reputation": None,
                "related_iocs": []
            }

            if include_reputation:
                data["reputation"] = self._calculate_reputation(
                    local_records, external_records
                )

            if include_related:
                data["related_iocs"] = self.correlation_engine.find_related_iocs(
                    ioc_value
                )

            # Record memory
            await self.memory_engine.record_ioc_occurrence(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                source="lookup_ioc",
                context={"include_reputation": include_reputation}
            )

            execution_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

            return IOCMCPResponse(
                success=True,
                data=data,
                execution_time_ms=execution_time_ms
            )

        except Exception as e:
            logger.error(f"Error in lookup_ioc: {str(e)}")
            return IOCMCPResponse(
                success=False,
                error=f"lookup_ioc failed: {str(e)}"
            )

    # ============================================================
    # TOOL 2: CLASSIFY IOC
    # ============================================================

    async def classify_ioc(
        self,
        ioc_value: str,
        ioc_type: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> IOCMCPResponse:
        """Phân loại IOC theo malware, C2, phishing, etc

        Args:
            ioc_value: IOC value
            ioc_type: Optional type hint
            context: Additional context (campaign, threat_actor, etc)

        Returns:
            IOCMCPResponse with classification
        """
        try:
            start_time = datetime.utcnow()

            # Auto-detect type
            if not ioc_type:
                ioc_type = self._detect_ioc_type(ioc_value)
                if not ioc_type:
                    return IOCMCPResponse(
                        success=False,
                        error=f"Could not detect IOC type"
                    )

            # Classification logic based on patterns
            classification = self._classify_ioc_internal(
                ioc_value, ioc_type, context
            )

            # Get threat associations
            threat_associations = self.correlation_engine.find_threat_associations(
                ioc_value
            )

            data = {
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "classification": classification,
                "threat_level": self._determine_threat_level(classification),
                "threat_associations": threat_associations or [],
                "confidence": classification.get("confidence", 0)
            }

            execution_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

            return IOCMCPResponse(
                success=True,
                data=data,
                execution_time_ms=execution_time_ms
            )

        except Exception as e:
            logger.error(f"Error in classify_ioc: {str(e)}")
            return IOCMCPResponse(
                success=False,
                error=f"classify_ioc failed: {str(e)}"
            )

    # ============================================================
    # TOOL 3: CORRELATE IOCS
    # ============================================================

    async def correlate_iocs(
        self,
        ioc_values: List[str],
        correlation_type: str = "infrastructure",
        max_results: int = 50
    ) -> IOCMCPResponse:
        """Tìm liên hệ giữa các IOC (infrastructure, campaign, actor)

        Args:
            ioc_values: List của IOC values để correlate
            correlation_type: infrastructure, campaign, actor, malware
            max_results: Số lượng kết quả (1-500)

        Returns:
            IOCMCPResponse with correlation analysis
        """
        try:
            start_time = datetime.utcnow()

            # Validate max_results
            if not (1 <= max_results <= 500):
                return IOCMCPResponse(
                    success=False,
                    error=f"max_results must be 1-500, got {max_results}"
                )

            # Validate correlation_type
            valid_types = ["infrastructure", "campaign", "actor", "malware"]
            if correlation_type not in valid_types:
                return IOCMCPResponse(
                    success=False,
                    error=f"Invalid correlation_type: {correlation_type}"
                )

            # Validate IOC values
            if not ioc_values or len(ioc_values) == 0:
                return IOCMCPResponse(
                    success=False,
                    error="ioc_values cannot be empty"
                )

            # Find correlations
            correlations = self.correlation_engine.correlate_iocs(
                ioc_values, correlation_type, max_results
            )

            # Analyze patterns
            patterns = self.correlation_engine.detect_patterns(ioc_values)

            data = {
                "input_iocs": ioc_values,
                "correlation_type": correlation_type,
                "correlations": correlations or [],
                "correlation_count": len(correlations) if correlations else 0,
                "detected_patterns": patterns or [],
                "relationships": self._build_relationship_graph(
                    ioc_values, correlations
                )
            }

            execution_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

            return IOCMCPResponse(
                success=True,
                data=data,
                execution_time_ms=execution_time_ms
            )

        except Exception as e:
            logger.error(f"Error in correlate_iocs: {str(e)}")
            return IOCMCPResponse(
                success=False,
                error=f"correlate_iocs failed: {str(e)}"
            )

    # ============================================================
    # TOOL 4: GET IOC CONTEXT
    # ============================================================

    async def get_ioc_context(
        self,
        ioc_value: str,
        ioc_type: Optional[str] = None,
        include_campaigns: bool = True,
        include_actors: bool = True,
        include_timeline: bool = True
    ) -> IOCMCPResponse:
        """Lấy context đầy đủ: campaigns, threat actors, timeline

        Args:
            ioc_value: IOC value
            ioc_type: Optional type hint
            include_campaigns: Include campaign associations
            include_actors: Include threat actor associations
            include_timeline: Include historical timeline

        Returns:
            IOCMCPResponse with full context
        """
        try:
            start_time = datetime.utcnow()

            # Auto-detect type
            if not ioc_type:
                ioc_type = self._detect_ioc_type(ioc_value)
                if not ioc_type:
                    return IOCMCPResponse(
                        success=False,
                        error="Could not detect IOC type"
                    )

            context = {
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "campaigns": [],
                "threat_actors": [],
                "timeline": []
            }

            if include_campaigns:
                context["campaigns"] = self.correlation_engine.find_campaigns(
                    ioc_value
                )

            if include_actors:
                context["threat_actors"] = self.correlation_engine.find_threat_actors(
                    ioc_value
                )

            if include_timeline:
                context["timeline"] = self.memory_engine.get_ioc_timeline(
                    ioc_value
                )

            # Get historical analysis
            historical_context = self.correlation_engine.get_historical_context(
                ioc_value
            )
            context["historical_analysis"] = historical_context

            execution_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

            return IOCMCPResponse(
                success=True,
                data=context,
                execution_time_ms=execution_time_ms
            )

        except Exception as e:
            logger.error(f"Error in get_ioc_context: {str(e)}")
            return IOCMCPResponse(
                success=False,
                error=f"get_ioc_context failed: {str(e)}"
            )

    # ============================================================
    # TOOL 5: RECORD IOC SIGHTING
    # ============================================================

    async def record_ioc_sighting(
        self,
        ioc_value: str,
        ioc_type: Optional[str] = None,
        source: str = "unknown",
        context: Optional[Dict[str, Any]] = None
    ) -> IOCMCPResponse:
        """Ghi nhận IOC sighting cho tracking & analysis

        Args:
            ioc_value: IOC value
            ioc_type: Optional type hint
            source: Source của sighting (network_sensor, email_gateway, endpoint, etc)
            context: Additional context (timestamp, location, etc)

        Returns:
            IOCMCPResponse with confirmation
        """
        try:
            start_time = datetime.utcnow()

            # Auto-detect type
            if not ioc_type:
                ioc_type = self._detect_ioc_type(ioc_value)
                if not ioc_type:
                    return IOCMCPResponse(
                        success=False,
                        error="Could not detect IOC type"
                    )

            # Validate source
            valid_sources = [
                "network_sensor", "email_gateway", "endpoint", "dns_log",
                "http_log", "firewall", "ips_ids", "siem", "unknown"
            ]
            if source not in valid_sources:
                source = "unknown"

            # Record to memory
            await self.memory_engine.record_ioc_occurrence(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                source=source,
                context=context or {}
            )

            # Persist to repository
            sighting_record = {
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "source": source,
                "timestamp": datetime.utcnow().isoformat(),
                "context": context or {}
            }
            self.repository.save_ioc_sighting(sighting_record)

            # Get updated stats
            stats = self.repository.get_ioc_stats(ioc_value)

            data = {
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "sighting_recorded": True,
                "source": source,
                "timestamp": sighting_record["timestamp"],
                "total_sightings": stats.get("total_sightings", 1),
                "first_seen": stats.get("first_seen", None),
                "last_seen": stats.get("last_seen", None)
            }

            execution_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

            return IOCMCPResponse(
                success=True,
                data=data,
                execution_time_ms=execution_time_ms
            )

        except Exception as e:
            logger.error(f"Error in record_ioc_sighting: {str(e)}")
            return IOCMCPResponse(
                success=False,
                error=f"record_ioc_sighting failed: {str(e)}"
            )

    # ============================================================
    # HELPER METHODS
    # ============================================================

    def _detect_ioc_type(self, value: str) -> Optional[str]:
        """Detect IOC type based on value pattern"""
        if not value:
            return None

        value = value.strip().lower()

        # Hash detection (MD5=32, SHA-1=40, SHA-256=64 hex chars)
        if re.match(r'^[a-f0-9]{32}$', value):
            return "hash_md5"
        if re.match(r'^[a-f0-9]{40}$', value):
            return "hash_sha1"
        if re.match(r'^[a-f0-9]{64}$', value):
            return "hash_sha256"

        # IPv4 address
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value):
            parts = value.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                return "ipv4"

        # IPv6 address
        if ':' in value and re.match(r'^[\da-f:]+$', value):
            return "ipv6"

        # Email address
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return "email"

        # URL
        if value.startswith(('http://', 'https://', 'ftp://')):
            return "url"

        # Domain
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', value):
            return "domain"

        return None

    def _validate_ioc_value(self, value: str, ioc_type: str) -> bool:
        """Validate IOC value format"""
        if not value:
            return False

        if ioc_type in ["hash_md5", "hash_sha1", "hash_sha256"]:
            return re.match(r'^[a-f0-9]+$', value.lower()) is not None

        if ioc_type == "ipv4":
            parts = value.split('.')
            return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts if p.isdigit())

        if ioc_type == "email":
            return '@' in value and '.' in value

        return True

    def _calculate_reputation(self, local_records: Any, external_records: Any) -> Dict[str, Any]:
        """Calculate reputation score from records"""
        reputation = {
            "malicious_votes": 0,
            "suspicious_votes": 0,
            "clean_votes": 0,
            "overall_score": 0.0,
            "verdict": "unknown"
        }

        # Count votes from local records
        if local_records:
            if isinstance(local_records, list):
                for record in local_records:
                    if record.get("threat_level") == "critical":
                        reputation["malicious_votes"] += 2
                    elif record.get("threat_level") == "high":
                        reputation["suspicious_votes"] += 1

        # Count votes from external records
        if external_records:
            if isinstance(external_records, list):
                reputation["malicious_votes"] += len([r for r in external_records if r.get("malicious")])
                reputation["suspicious_votes"] += len([r for r in external_records if r.get("suspicious")])

        # Calculate score
        total_votes = reputation["malicious_votes"] + reputation["suspicious_votes"] + reputation["clean_votes"]
        if total_votes > 0:
            reputation["overall_score"] = (reputation["malicious_votes"] * 2 + reputation["suspicious_votes"]) / (total_votes * 2)

        # Determine verdict
        if reputation["overall_score"] >= 0.7:
            reputation["verdict"] = "malicious"
        elif reputation["overall_score"] >= 0.4:
            reputation["verdict"] = "suspicious"
        elif reputation["overall_score"] > 0:
            reputation["verdict"] = "unknown"
        else:
            reputation["verdict"] = "clean"

        return reputation

    def _classify_ioc_internal(self, ioc_value: str, ioc_type: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """Internal classification logic"""
        classification = {
            "categories": [],
            "threat_type": "unknown",
            "confidence": 0.0,
            "indicators": []
        }

        # Check against known patterns
        if "malware" in str(context or {}).lower():
            classification["categories"].append("malware")
            classification["threat_type"] = "malware"

        if ioc_type in ["ipv4", "ipv6", "domain"]:
            # Could be C2, phishing, etc
            classification["categories"].append("infrastructure")

        if ioc_type == "hash_md5" or ioc_type == "hash_sha256":
            classification["categories"].append("file_hash")
            classification["threat_type"] = "file"

        if ioc_type == "email":
            classification["categories"].append("phishing")

        if not classification["categories"]:
            classification["categories"].append("indicator")

        # Set confidence based on available context
        classification["confidence"] = 0.5 if context else 0.3

        return classification

    def _determine_threat_level(self, classification: Dict[str, Any]) -> str:
        """Determine threat level from classification"""
        if not classification:
            return "unknown"

        threat_type = classification.get("threat_type", "unknown")
        confidence = classification.get("confidence", 0.0)

        if threat_type == "malware" and confidence > 0.7:
            return "critical"
        elif threat_type in ["infrastructure", "phishing"] and confidence > 0.7:
            return "high"
        elif confidence > 0.5:
            return "medium"
        else:
            return "low"

    def _build_relationship_graph(self, iocs: List[str], correlations: Any) -> List[Dict[str, Any]]:
        """Build relationship graph from IOCs and correlations"""
        relationships = []

        if not correlations:
            return relationships

        if isinstance(correlations, list):
            for corr in correlations:
                relationships.append({
                    "source": iocs[0] if iocs else "unknown",
                    "target": corr.get("ioc_value") if isinstance(corr, dict) else str(corr),
                    "relationship_type": "correlated",
                    "strength": 0.7
                })

        return relationships


# ============================================================
# SINGLETON INSTANCE
# ============================================================

_instance = None


def get_ioc_mcp_server(repository: ThreatKnowledgeRepository) -> IOCMCPServer:
    """Get or create IOC MCP server singleton"""
    global _instance
    if _instance is None:
        _instance = IOCMCPServer(repository)
    return _instance
