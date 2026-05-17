"""
core/system_health.py - System Health Monitoring & Optimization

Production system health tracking:
- Component health status monitoring
- Performance metrics collection
- Resource utilization tracking
- System bottleneck detection
- Optimization recommendations
"""

from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from enum import Enum
import time


class HealthStatus(Enum):
    """System health status levels."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    WARNING = "warning"
    CRITICAL = "critical"


class ComponentType(Enum):
    """System component types."""
    SCHEMA = "schema"
    REPOSITORY = "repository"
    ADAPTERS = "adapters"
    FUSION = "fusion"
    MEMORY = "memory"
    TEMPORAL = "temporal"
    PATTERN_DETECTION = "pattern_detection"
    HISTORICAL = "historical"
    GRAPH = "graph"
    ANALYTICS = "analytics"
    AUTOMATION = "automation"


class SystemHealthMonitor:
    """Monitor and optimize system health."""

    def __init__(self):
        """Initialize system health monitor."""
        self.component_stats = {}
        self.performance_history = []
        self.alerts = []
        self.last_check = datetime.utcnow()

    def register_component(self, name: str, component_type: ComponentType) -> None:
        """Register system component for monitoring.

        Args:
            name: Component name
            component_type: Type of component
        """
        self.component_stats[name] = {
            "type": component_type.value,
            "status": HealthStatus.HEALTHY.value,
            "response_time_ms": 0.0,
            "error_count": 0,
            "success_count": 0,
            "last_check": datetime.utcnow(),
            "uptime_hours": 0.0,
        }

    def record_operation(
        self,
        component: str,
        duration_ms: float,
        success: bool,
        error_msg: Optional[str] = None
    ) -> None:
        """Record component operation metrics.

        Args:
            component: Component name
            duration_ms: Operation duration in milliseconds
            success: Whether operation succeeded
            error_msg: Error message if failed
        """
        if component not in self.component_stats:
            return

        stats = self.component_stats[component]
        stats["last_check"] = datetime.utcnow()
        stats["response_time_ms"] = duration_ms

        if success:
            stats["success_count"] += 1
        else:
            stats["error_count"] += 1
            if error_msg:
                self.alerts.append({
                    "timestamp": datetime.utcnow(),
                    "component": component,
                    "message": error_msg,
                    "severity": "ERROR",
                })

        # Update health status based on error rate
        total = stats["success_count"] + stats["error_count"]
        if total > 0:
            error_rate = stats["error_count"] / total
            if error_rate > 0.5:
                stats["status"] = HealthStatus.CRITICAL.value
            elif error_rate > 0.25:
                stats["status"] = HealthStatus.WARNING.value
            elif error_rate > 0.1:
                stats["status"] = HealthStatus.DEGRADED.value
            else:
                stats["status"] = HealthStatus.HEALTHY.value

    def get_component_health(self, component: str) -> Dict[str, Any]:
        """Get health status for component.

        Args:
            component: Component name

        Returns:
            Health metrics
        """
        if component not in self.component_stats:
            return {}

        stats = self.component_stats[component]
        total_ops = stats["success_count"] + stats["error_count"]

        return {
            "component": component,
            "status": stats["status"],
            "response_time_ms": round(stats["response_time_ms"], 2),
            "success_rate": (
                stats["success_count"] / total_ops * 100
                if total_ops > 0 else 100.0
            ),
            "error_count": stats["error_count"],
            "success_count": stats["success_count"],
            "last_check": stats["last_check"],
        }

    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health status.

        Returns:
            System health report
        """
        if not self.component_stats:
            return {
                "status": HealthStatus.HEALTHY.value,
                "components": 0,
                "healthy_components": 0,
                "degraded_components": 0,
                "warning_components": 0,
                "critical_components": 0,
            }

        statuses = [s["status"] for s in self.component_stats.values()]
        healthy = statuses.count(HealthStatus.HEALTHY.value)
        degraded = statuses.count(HealthStatus.DEGRADED.value)
        warning = statuses.count(HealthStatus.WARNING.value)
        critical = statuses.count(HealthStatus.CRITICAL.value)

        # Overall status: worst of any component
        if critical > 0:
            overall = HealthStatus.CRITICAL.value
        elif warning > 0:
            overall = HealthStatus.WARNING.value
        elif degraded > 0:
            overall = HealthStatus.DEGRADED.value
        else:
            overall = HealthStatus.HEALTHY.value

        return {
            "status": overall,
            "timestamp": datetime.utcnow(),
            "components": len(self.component_stats),
            "healthy_components": healthy,
            "degraded_components": degraded,
            "warning_components": warning,
            "critical_components": critical,
            "component_details": [
                self.get_component_health(name)
                for name in self.component_stats.keys()
            ],
        }

    def detect_bottlenecks(self) -> List[Dict[str, Any]]:
        """Detect system performance bottlenecks.

        Returns:
            List of bottleneck findings
        """
        bottlenecks = []

        if not self.component_stats:
            return bottlenecks

        # Find slow components (top 20% by response time)
        response_times = [
            (name, stats["response_time_ms"])
            for name, stats in self.component_stats.items()
        ]
        response_times.sort(key=lambda x: x[1], reverse=True)

        threshold_idx = max(1, len(response_times) // 5)
        slow_components = response_times[:threshold_idx]

        for component, response_time in slow_components:
            if response_time > 1000:  # More than 1 second
                bottlenecks.append({
                    "type": "slow_component",
                    "component": component,
                    "response_time_ms": round(response_time, 2),
                    "severity": "HIGH" if response_time > 5000 else "MEDIUM",
                    "recommendation": f"Profile and optimize {component}",
                })

        # Find high-error components
        for name, stats in self.component_stats.items():
            total = stats["success_count"] + stats["error_count"]
            if total > 0:
                error_rate = stats["error_count"] / total
                if error_rate > 0.1:
                    bottlenecks.append({
                        "type": "high_error_rate",
                        "component": name,
                        "error_rate": round(error_rate * 100, 2),
                        "error_count": stats["error_count"],
                        "severity": "HIGH" if error_rate > 0.25 else "MEDIUM",
                        "recommendation": f"Investigate failures in {name}",
                    })

        return bottlenecks

    def get_optimization_recommendations(self) -> List[Dict[str, Any]]:
        """Generate system optimization recommendations.

        Returns:
            List of optimization recommendations
        """
        recommendations = []
        bottlenecks = self.detect_bottlenecks()

        for bottleneck in bottlenecks:
            if bottleneck["type"] == "slow_component":
                recommendations.append({
                    "priority": "HIGH" if bottleneck["severity"] == "HIGH" else "MEDIUM",
                    "action": f"Optimize {bottleneck['component']}",
                    "reason": f"Response time {bottleneck['response_time_ms']}ms exceeds threshold",
                    "steps": [
                        "Profile component execution",
                        "Identify hotspots",
                        "Apply caching where applicable",
                        "Consider async operations",
                    ],
                })
            elif bottleneck["type"] == "high_error_rate":
                recommendations.append({
                    "priority": "HIGH" if bottleneck["severity"] == "HIGH" else "MEDIUM",
                    "action": f"Debug {bottleneck['component']}",
                    "reason": f"Error rate {bottleneck['error_rate']}% is elevated",
                    "steps": [
                        "Review recent error logs",
                        "Check for dependency issues",
                        "Add comprehensive error handling",
                        "Implement retry logic if appropriate",
                    ],
                })

        # Memory efficiency recommendation
        if len(self.component_stats) > 20:
            recommendations.append({
                "priority": "MEDIUM",
                "action": "Review data structure efficiency",
                "reason": f"System managing {len(self.component_stats)} components",
                "steps": [
                    "Audit in-memory data structures",
                    "Implement caching layers",
                    "Consider lazy loading",
                    "Profile memory usage",
                ],
            })

        return recommendations

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary metrics.

        Returns:
            Performance summary
        """
        if not self.component_stats:
            return {
                "avg_response_time_ms": 0.0,
                "max_response_time_ms": 0.0,
                "total_operations": 0,
                "total_errors": 0,
            }

        response_times = [s["response_time_ms"] for s in self.component_stats.values()]
        error_counts = [s["error_count"] for s in self.component_stats.values()]
        success_counts = [s["success_count"] for s in self.component_stats.values()]

        return {
            "avg_response_time_ms": round(
                sum(response_times) / len(response_times) if response_times else 0, 2
            ),
            "max_response_time_ms": round(max(response_times) if response_times else 0, 2),
            "min_response_time_ms": round(min(response_times) if response_times else 0, 2),
            "total_operations": sum(success_counts),
            "total_errors": sum(error_counts),
            "overall_success_rate": (
                sum(success_counts) / (sum(success_counts) + sum(error_counts)) * 100
                if (sum(success_counts) + sum(error_counts)) > 0
                else 100.0
            ),
        }

    def get_alerts(self, severity: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get system alerts.

        Args:
            severity: Filter by severity level
            limit: Maximum alerts to return

        Returns:
            List of alerts
        """
        alerts = self.alerts
        if severity:
            alerts = [a for a in alerts if a.get("severity") == severity]

        return sorted(
            alerts,
            key=lambda x: x.get("timestamp", datetime.utcnow()),
            reverse=True
        )[:limit]

    def get_health_trend(self, hours: int = 24) -> Dict[str, Any]:
        """Get health trend over time.

        Args:
            hours: Number of hours to analyze

        Returns:
            Health trend analysis
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        recent_alerts = [a for a in self.alerts if a.get("timestamp", datetime.utcnow()) > cutoff]

        error_count_by_hour = {}
        for alert in recent_alerts:
            hour_key = alert.get("timestamp", datetime.utcnow()).strftime("%Y-%m-%d %H:00")
            error_count_by_hour[hour_key] = error_count_by_hour.get(hour_key, 0) + 1

        return {
            "period_hours": hours,
            "total_alerts": len(recent_alerts),
            "alerts_by_hour": error_count_by_hour,
            "trend": self._analyze_trend(list(error_count_by_hour.values())),
        }

    def _analyze_trend(self, values: List[int]) -> str:
        """Analyze trend in values.

        Args:
            values: List of values over time

        Returns:
            Trend description
        """
        if len(values) < 2:
            return "insufficient_data"

        first_half = values[: len(values) // 2]
        second_half = values[len(values) // 2 :]

        if not first_half or not second_half:
            return "insufficient_data"

        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)

        if avg_second > avg_first * 1.2:
            return "worsening"
        elif avg_second < avg_first * 0.8:
            return "improving"
        else:
            return "stable"

    def to_dict(self) -> Dict[str, Any]:
        """Convert monitor state to dictionary.

        Returns:
            Dict representation
        """
        return {
            "timestamp": datetime.utcnow(),
            "health": self.get_system_health(),
            "performance": self.get_performance_summary(),
            "alerts": self.get_alerts(limit=20),
            "bottlenecks": self.detect_bottlenecks(),
            "recommendations": self.get_optimization_recommendations(),
            "trend": self.get_health_trend(),
        }
