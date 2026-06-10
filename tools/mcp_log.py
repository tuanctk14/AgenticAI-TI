"""
tools/mcp_log.py - Log Management MCP Server

Cung cấp giao diện công cụ cho log operations:
- Log collection và parsing
- Security event detection
- Alert generation và escalation
- Log pattern analysis
- Threat detection from logs

Tái sử dụng:
- core/threat_memory.py (persistence)
- core/pattern_detection.py (pattern analysis)
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from dataclasses import dataclass
import logging
import re

from core.threat_memory import ThreatMemoryEngine
from core.threat_repository import ThreatKnowledgeRepository

logger = logging.getLogger(__name__)


# ============================================================
# RESPONSE MODELS
# ============================================================

@dataclass
class LogMCPResponse:
    """Response wrapper cho Log MCP operations"""
    success: bool
    data: Any = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0


# ============================================================
# LOG MCP SERVER
# ============================================================

class LogMCPServer:
    """MCP server cho Log management operations

    Cung cấp 5 tools:
    1. collect_logs - Thu thập logs từ multiple sources
    2. detect_security_events - Phát hiện security events
    3. generate_alert - Tạo alerts từ events
    4. analyze_log_patterns - Phân tích mô hình logs
    5. correlate_log_events - Tương quan events giữa các sources
    """

    def __init__(self, repository: ThreatKnowledgeRepository):
        """Khởi tạo Log MCP server

        Args:
            repository: Threat knowledge repository
        """
        self.repository = repository
        self.memory_engine = ThreatMemoryEngine()

    # ============================================================
    # TOOL 1: COLLECT LOGS
    # ============================================================

    async def collect_logs(
        self,
        log_source: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        filter_severity: Optional[str] = None,
        max_results: int = 100
    ) -> LogMCPResponse:
        """Thu thập logs từ source

        Args:
            log_source: Log source (syslog, windows_event, apache, firewall, etc)
            start_time: ISO format timestamp để filter
            end_time: ISO format timestamp để filter
            filter_severity: INFO, WARNING, ERROR, CRITICAL
            max_results: Số lượng logs (1-1000)

        Returns:
            LogMCPResponse with logs
        """
        try:
            start_time_dt = datetime.utcnow()

            # Validate max_results
            if not (1 <= max_results <= 1000):
                return LogMCPResponse(
                    success=False,
                    error=f"max_results must be 1-1000, got {max_results}"
                )

            # Validate log_source
            valid_sources = [
                "syslog", "windows_event", "apache", "nginx",
                "firewall", "ids_ids", "proxy", "dns", "email",
                "database", "application", "custom"
            ]
            if log_source not in valid_sources:
                return LogMCPResponse(
                    success=False,
                    error=f"Invalid log_source: {log_source}"
                )

            # Validate severity
            if filter_severity:
                valid_severities = ["INFO", "WARNING", "ERROR", "CRITICAL"]
                if filter_severity not in valid_severities:
                    return LogMCPResponse(
                        success=False,
                        error=f"Invalid severity: {filter_severity}"
                    )

            # Collect logs (stub - thực tế sẽ query repository)
            logs = self._collect_logs_internal(
                log_source, start_time, end_time, filter_severity, max_results
            )

            data = {
                "log_source": log_source,
                "logs": logs,
                "total_count": len(logs),
                "filter_severity": filter_severity,
                "time_range": {
                    "start": start_time,
                    "end": end_time
                }
            }

            execution_time_ms = (datetime.utcnow() - start_time_dt).total_seconds() * 1000

            return LogMCPResponse(
                success=True,
                data=data,
                execution_time_ms=execution_time_ms
            )

        except Exception as e:
            logger.error(f"Error in collect_logs: {str(e)}")
            return LogMCPResponse(
                success=False,
                error=f"collect_logs failed: {str(e)}"
            )

    # ============================================================
    # TOOL 2: DETECT SECURITY EVENTS
    # ============================================================

    async def detect_security_events(
        self,
        log_data: List[Dict[str, Any]],
        detection_rules: Optional[List[str]] = None,
        include_context: bool = True
    ) -> LogMCPResponse:
        """Phát hiện security events từ logs

        Args:
            log_data: List của log entries
            detection_rules: Optional list của rule names
            include_context: Include surrounding logs

        Returns:
            LogMCPResponse with detected events
        """
        try:
            start_time = datetime.utcnow()

            # Validate log_data
            if not log_data or len(log_data) == 0:
                return LogMCPResponse(
                    success=False,
                    error="log_data cannot be empty"
                )

            # Detect events
            events = self._detect_events_internal(log_data, detection_rules)

            # Add context if requested
            if include_context:
                for event in events:
                    event["context_logs"] = self._get_context_logs(
                        log_data, event
                    )

            data = {
                "total_logs": len(log_data),
                "detected_events": events,
                "event_count": len(events),
                "detection_rules_applied": detection_rules or ["default"],
                "threat_level": self._calculate_threat_level(events)
            }

            execution_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

            return LogMCPResponse(
                success=True,
                data=data,
                execution_time_ms=execution_time_ms
            )

        except Exception as e:
            logger.error(f"Error in detect_security_events: {str(e)}")
            return LogMCPResponse(
                success=False,
                error=f"detect_security_events failed: {str(e)}"
            )

    # ============================================================
    # TOOL 3: GENERATE ALERT
    # ============================================================

    async def generate_alert(
        self,
        event_type: str,
        severity: str,
        description: str,
        source: Optional[str] = None,
        affected_assets: Optional[List[str]] = None,
        actions: Optional[List[str]] = None
    ) -> LogMCPResponse:
        """Tạo alert từ event

        Args:
            event_type: Event type (intrusion, malware, policy_violation, etc)
            severity: CRITICAL, HIGH, MEDIUM, LOW
            description: Alert description
            source: Source của alert
            affected_assets: Assets bị ảnh hưởng
            actions: Recommended actions

        Returns:
            LogMCPResponse with alert confirmation
        """
        try:
            start_time = datetime.utcnow()

            # Validate severity
            valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            if severity not in valid_severities:
                return LogMCPResponse(
                    success=False,
                    error=f"Invalid severity: {severity}"
                )

            # Create alert
            alert = {
                "alert_id": self._generate_alert_id(),
                "event_type": event_type,
                "severity": severity,
                "description": description,
                "source": source or "unknown",
                "timestamp": datetime.utcnow().isoformat(),
                "affected_assets": affected_assets or [],
                "recommended_actions": actions or [],
                "status": "open"
            }

            # Record to memory
            await self.memory_engine.record_ioc_occurrence(
                ioc_value=alert["alert_id"],
                ioc_type="alert",
                source="alert_engine",
                context={"alert": alert}
            )

            # Persist to repository
            self.repository.save_alert(alert)

            # Determine escalation
            escalation_required = severity in ["CRITICAL", "HIGH"]

            data = {
                "alert_created": True,
                "alert_id": alert["alert_id"],
                "severity": severity,
                "event_type": event_type,
                "timestamp": alert["timestamp"],
                "escalation_required": escalation_required,
                "escalation_level": 1 if severity == "CRITICAL" else (2 if severity == "HIGH" else 3)
            }

            execution_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

            return LogMCPResponse(
                success=True,
                data=data,
                execution_time_ms=execution_time_ms
            )

        except Exception as e:
            logger.error(f"Error in generate_alert: {str(e)}")
            return LogMCPResponse(
                success=False,
                error=f"generate_alert failed: {str(e)}"
            )

    # ============================================================
    # TOOL 4: ANALYZE LOG PATTERNS
    # ============================================================

    async def analyze_log_patterns(
        self,
        log_data: List[Dict[str, Any]],
        pattern_type: str = "frequency",
        time_window: int = 3600
    ) -> LogMCPResponse:
        """Phân tích mô hình logs

        Args:
            log_data: List của log entries
            pattern_type: frequency, anomaly, cluster
            time_window: Time window in seconds

        Returns:
            LogMCPResponse with pattern analysis
        """
        try:
            start_time = datetime.utcnow()

            # Validate log_data
            if not log_data or len(log_data) == 0:
                return LogMCPResponse(
                    success=False,
                    error="log_data cannot be empty"
                )

            # Validate pattern_type
            valid_types = ["frequency", "anomaly", "cluster"]
            if pattern_type not in valid_types:
                return LogMCPResponse(
                    success=False,
                    error=f"Invalid pattern_type: {pattern_type}"
                )

            # Analyze patterns
            patterns = self._analyze_patterns_internal(
                log_data, pattern_type, time_window
            )

            data = {
                "total_logs": len(log_data),
                "pattern_type": pattern_type,
                "time_window_seconds": time_window,
                "patterns": patterns,
                "pattern_count": len(patterns),
                "anomaly_score": self._calculate_anomaly_score(patterns)
            }

            execution_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

            return LogMCPResponse(
                success=True,
                data=data,
                execution_time_ms=execution_time_ms
            )

        except Exception as e:
            logger.error(f"Error in analyze_log_patterns: {str(e)}")
            return LogMCPResponse(
                success=False,
                error=f"analyze_log_patterns failed: {str(e)}"
            )

    # ============================================================
    # TOOL 5: CORRELATE LOG EVENTS
    # ============================================================

    async def correlate_log_events(
        self,
        log_sources: List[str],
        correlation_window: int = 300,
        include_chain_analysis: bool = True
    ) -> LogMCPResponse:
        """Tương quan events giữa các log sources

        Args:
            log_sources: List của log sources để correlate
            correlation_window: Time window in seconds
            include_chain_analysis: Include attack chain analysis

        Returns:
            LogMCPResponse with correlations
        """
        try:
            start_time = datetime.utcnow()

            # Validate log_sources
            if not log_sources or len(log_sources) == 0:
                return LogMCPResponse(
                    success=False,
                    error="log_sources cannot be empty"
                )

            # Validate correlation_window
            if not (60 <= correlation_window <= 3600):
                return LogMCPResponse(
                    success=False,
                    error=f"correlation_window must be 60-3600 seconds"
                )

            # Correlate events
            correlations = self._correlate_events_internal(
                log_sources, correlation_window
            )

            # Analyze attack chain
            chain_analysis = None
            if include_chain_analysis:
                chain_analysis = self._analyze_attack_chain(correlations)

            data = {
                "log_sources": log_sources,
                "correlation_window": correlation_window,
                "correlations": correlations,
                "correlation_count": len(correlations),
                "attack_chain": chain_analysis,
                "severity_summary": self._get_severity_summary(correlations)
            }

            execution_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

            return LogMCPResponse(
                success=True,
                data=data,
                execution_time_ms=execution_time_ms
            )

        except Exception as e:
            logger.error(f"Error in correlate_log_events: {str(e)}")
            return LogMCPResponse(
                success=False,
                error=f"correlate_log_events failed: {str(e)}"
            )

    # ============================================================
    # HELPER METHODS
    # ============================================================

    def _collect_logs_internal(
        self, log_source: str, start_time: str, end_time: str,
        severity: str, max_results: int
    ) -> List[Dict[str, Any]]:
        """Internal log collection"""
        # Stub implementation
        return []

    def _detect_events_internal(
        self, log_data: List[Dict], rules: Optional[List[str]]
    ) -> List[Dict[str, Any]]:
        """Internal event detection"""
        events = []

        for log in log_data:
            # Simple pattern detection
            message = str(log.get("message", "")).lower()

            if any(keyword in message for keyword in ["error", "fail", "denied", "blocked"]):
                events.append({
                    "type": "security_event",
                    "message": log.get("message"),
                    "severity": "HIGH" if "denied" in message else "MEDIUM",
                    "timestamp": log.get("timestamp"),
                    "source": log.get("source")
                })

        return events

    def _get_context_logs(self, all_logs: List[Dict], event: Dict) -> List[Dict]:
        """Get surrounding context logs"""
        return all_logs[:2] if len(all_logs) > 2 else all_logs

    def _calculate_threat_level(self, events: List[Dict]) -> str:
        """Calculate overall threat level"""
        if not events:
            return "LOW"

        critical_count = len([e for e in events if e.get("severity") == "CRITICAL"])
        high_count = len([e for e in events if e.get("severity") == "HIGH"])

        if critical_count > 0:
            return "CRITICAL"
        elif high_count > 2:
            return "HIGH"
        elif high_count > 0:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_alert_id(self) -> str:
        """Generate unique alert ID"""
        import uuid
        return f"ALERT-{uuid.uuid4().hex[:8].upper()}"

    def _analyze_patterns_internal(
        self, log_data: List[Dict], pattern_type: str, time_window: int
    ) -> List[Dict[str, Any]]:
        """Analyze log patterns"""
        patterns = []

        if pattern_type == "frequency":
            # Count message frequency
            message_counts = {}
            for log in log_data:
                msg = str(log.get("message", ""))
                message_counts[msg] = message_counts.get(msg, 0) + 1

            for msg, count in sorted(message_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                if count > 1:
                    patterns.append({
                        "pattern": msg,
                        "type": "frequency",
                        "occurrence": count,
                        "percentage": (count / len(log_data)) * 100
                    })

        elif pattern_type == "anomaly":
            # Detect anomalies
            if len(log_data) > 10:
                patterns.append({
                    "pattern": "Unusual spike detected",
                    "type": "anomaly",
                    "score": 0.6
                })

        elif pattern_type == "cluster":
            # Cluster logs
            if len(log_data) > 5:
                patterns.append({
                    "pattern": "Log cluster identified",
                    "type": "cluster",
                    "size": len(log_data) // 5
                })

        return patterns

    def _calculate_anomaly_score(self, patterns: List[Dict]) -> float:
        """Calculate anomaly score"""
        if not patterns:
            return 0.0

        score = 0.0
        for pattern in patterns:
            if pattern.get("type") == "anomaly":
                score += pattern.get("score", 0.3)

        return min(score / len(patterns), 1.0)

    def _correlate_events_internal(
        self, sources: List[str], window: int
    ) -> List[Dict[str, Any]]:
        """Correlate events from multiple sources"""
        correlations = []

        # Simple correlation - in reality would match events
        if len(sources) > 1:
            for i in range(len(sources) - 1):
                correlations.append({
                    "source1": sources[i],
                    "source2": sources[i + 1],
                    "correlation_type": "temporal",
                    "events_matched": 0,
                    "confidence": 0.5
                })

        return correlations

    def _analyze_attack_chain(self, correlations: List[Dict]) -> Dict[str, Any]:
        """Analyze potential attack chain"""
        return {
            "chain_detected": len(correlations) > 0,
            "stages": len(correlations),
            "confidence": 0.5 if len(correlations) > 0 else 0.0
        }

    def _get_severity_summary(self, correlations: List[Dict]) -> Dict[str, int]:
        """Get severity summary"""
        return {
            "critical": 0,
            "high": len(correlations),
            "medium": 0,
            "low": 0
        }


# ============================================================
# SINGLETON INSTANCE
# ============================================================

_instance = None


def get_log_mcp_server(repository: ThreatKnowledgeRepository) -> LogMCPServer:
    """Get or create Log MCP server singleton"""
    global _instance
    if _instance is None:
        _instance = LogMCPServer(repository)
    return _instance
