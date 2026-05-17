"""
tests/test_week5_system_health.py - System Health Monitoring Tests

Tests for:
- Component health registration and monitoring
- Performance metrics collection
- Bottleneck detection
- Health status classification
- Optimization recommendations
- Alert management
"""

import pytest
from datetime import datetime, timedelta

from core.system_health import (
    SystemHealthMonitor,
    HealthStatus,
    ComponentType,
)


class TestComponentRegistration:
    """Test component registration and monitoring."""

    def test_register_component(self):
        """Test registering system component."""
        monitor = SystemHealthMonitor()
        monitor.register_component("parser", ComponentType.SCHEMA)

        assert "parser" in monitor.component_stats
        assert monitor.component_stats["parser"]["type"] == "schema"
        assert monitor.component_stats["parser"]["status"] == HealthStatus.HEALTHY.value

    def test_register_multiple_components(self):
        """Test registering multiple components."""
        monitor = SystemHealthMonitor()

        for i in range(5):
            monitor.register_component(f"component-{i}", ComponentType.FUSION)

        assert len(monitor.component_stats) == 5

    def test_component_initial_state(self):
        """Test component initial health state."""
        monitor = SystemHealthMonitor()
        monitor.register_component("test", ComponentType.REPOSITORY)

        stats = monitor.component_stats["test"]
        assert stats["status"] == HealthStatus.HEALTHY.value
        assert stats["success_count"] == 0
        assert stats["error_count"] == 0


class TestOperationMetrics:
    """Test recording operation metrics."""

    def test_record_successful_operation(self):
        """Test recording successful operation."""
        monitor = SystemHealthMonitor()
        monitor.register_component("api", ComponentType.ADAPTERS)

        monitor.record_operation("api", 150.5, True)

        stats = monitor.component_stats["api"]
        assert stats["success_count"] == 1
        assert stats["error_count"] == 0
        assert stats["response_time_ms"] == 150.5

    def test_record_failed_operation(self):
        """Test recording failed operation."""
        monitor = SystemHealthMonitor()
        monitor.register_component("api", ComponentType.ADAPTERS)

        monitor.record_operation("api", 200.0, False, "Connection timeout")

        stats = monitor.component_stats["api"]
        assert stats["success_count"] == 0
        assert stats["error_count"] == 1

    def test_record_multiple_operations(self):
        """Test recording multiple operations."""
        monitor = SystemHealthMonitor()
        monitor.register_component("db", ComponentType.REPOSITORY)

        for i in range(10):
            success = i % 2 == 0  # 5 successes, 5 failures
            monitor.record_operation("db", 100.0 + i * 10, success)

        stats = monitor.component_stats["db"]
        assert stats["success_count"] == 5
        assert stats["error_count"] == 5

    def test_health_status_updates_on_errors(self):
        """Test health status changes with error rate."""
        monitor = SystemHealthMonitor()
        monitor.register_component("service", ComponentType.FUSION)

        # Record 100 successes
        for i in range(100):
            monitor.record_operation("service", 50.0, True)

        assert monitor.component_stats["service"]["status"] == HealthStatus.HEALTHY.value

        # Record 15 failures (15% error rate)
        for i in range(15):
            monitor.record_operation("service", 50.0, False)

        assert monitor.component_stats["service"]["status"] == HealthStatus.DEGRADED.value

        # Record 20 more failures (reach 26% error rate)
        for i in range(20):
            monitor.record_operation("service", 50.0, False)

        assert monitor.component_stats["service"]["status"] == HealthStatus.WARNING.value


class TestHealthStatus:
    """Test health status reporting."""

    def test_get_component_health(self):
        """Test getting component health status."""
        monitor = SystemHealthMonitor()
        monitor.register_component("comp1", ComponentType.MEMORY)

        monitor.record_operation("comp1", 100.0, True)
        monitor.record_operation("comp1", 120.0, True)
        monitor.record_operation("comp1", 110.0, False)

        health = monitor.get_component_health("comp1")

        assert health["component"] == "comp1"
        assert health["success_count"] == 2
        assert health["error_count"] == 1
        assert health["success_rate"] > 60.0

    def test_get_system_health(self):
        """Test getting overall system health."""
        monitor = SystemHealthMonitor()

        monitor.register_component("healthy", ComponentType.SCHEMA)
        monitor.register_component("warning", ComponentType.ADAPTERS)

        monitor.record_operation("healthy", 50.0, True)
        monitor.record_operation("healthy", 50.0, True)

        for i in range(30):
            monitor.record_operation("warning", 50.0, False if i < 10 else True)

        health = monitor.get_system_health()

        assert health["components"] == 2
        assert health["healthy_components"] >= 1

    def test_system_health_worst_component(self):
        """Test system health reflects worst component."""
        monitor = SystemHealthMonitor()

        monitor.register_component("good", ComponentType.TEMPORAL)
        monitor.register_component("bad", ComponentType.PATTERN_DETECTION)

        monitor.record_operation("good", 50.0, True)
        monitor.record_operation("good", 50.0, True)

        for i in range(100):
            monitor.record_operation("bad", 50.0, False)

        health = monitor.get_system_health()
        assert health["status"] == HealthStatus.CRITICAL.value


class TestBottleneckDetection:
    """Test performance bottleneck detection."""

    def test_detect_slow_component(self):
        """Test detecting slow components."""
        monitor = SystemHealthMonitor()
        monitor.register_component("slow", ComponentType.GRAPH)
        monitor.register_component("fast", ComponentType.ANALYTICS)

        monitor.record_operation("slow", 2000.0, True)  # 2 seconds
        monitor.record_operation("fast", 50.0, True)

        bottlenecks = monitor.detect_bottlenecks()

        slow_bottlenecks = [b for b in bottlenecks if b.get("component") == "slow"]
        assert len(slow_bottlenecks) > 0
        assert slow_bottlenecks[0]["type"] == "slow_component"

    def test_detect_high_error_rate(self):
        """Test detecting high error rates."""
        monitor = SystemHealthMonitor()
        monitor.register_component("failing", ComponentType.AUTOMATION)

        for i in range(50):
            monitor.record_operation("failing", 50.0, False)
        for i in range(10):
            monitor.record_operation("failing", 50.0, True)

        bottlenecks = monitor.detect_bottlenecks()

        error_bottlenecks = [b for b in bottlenecks if b.get("type") == "high_error_rate"]
        assert len(error_bottlenecks) > 0

    def test_detect_multiple_bottlenecks(self):
        """Test detecting multiple bottlenecks."""
        monitor = SystemHealthMonitor()

        monitor.register_component("slow1", ComponentType.SCHEMA)
        monitor.register_component("slow2", ComponentType.REPOSITORY)
        monitor.register_component("error1", ComponentType.ADAPTERS)

        monitor.record_operation("slow1", 6000.0, True)
        monitor.record_operation("slow2", 5500.0, True)

        for i in range(100):
            monitor.record_operation("error1", 50.0, False if i < 40 else True)

        bottlenecks = monitor.detect_bottlenecks()

        # Should detect slow1 and error1 at minimum
        assert len(bottlenecks) >= 2


class TestOptimizationRecommendations:
    """Test optimization recommendations."""

    def test_recommend_component_optimization(self):
        """Test recommending component optimization."""
        monitor = SystemHealthMonitor()
        monitor.register_component("slow", ComponentType.GRAPH)

        monitor.record_operation("slow", 3000.0, True)

        recs = monitor.get_optimization_recommendations()

        optimization_recs = [r for r in recs if "Optimize" in r.get("action", "")]
        assert len(optimization_recs) > 0

    def test_recommend_error_debugging(self):
        """Test recommending error debugging."""
        monitor = SystemHealthMonitor()
        monitor.register_component("buggy", ComponentType.ANALYTICS)

        for i in range(100):
            monitor.record_operation("buggy", 50.0, False if i < 30 else True)

        recs = monitor.get_optimization_recommendations()

        debug_recs = [r for r in recs if "Debug" in r.get("action", "")]
        assert len(debug_recs) > 0

    def test_recommendations_include_steps(self):
        """Test recommendations include implementation steps."""
        monitor = SystemHealthMonitor()
        monitor.register_component("slow", ComponentType.FUSION)

        monitor.record_operation("slow", 2500.0, True)

        recs = monitor.get_optimization_recommendations()

        assert len(recs) > 0
        assert all("steps" in r for r in recs)
        assert all(len(r.get("steps", [])) > 0 for r in recs)


class TestAlertManagement:
    """Test alert management."""

    def test_create_alert_on_failure(self):
        """Test alerts created on operation failure."""
        monitor = SystemHealthMonitor()
        monitor.register_component("service", ComponentType.TEMPORAL)

        monitor.record_operation("service", 100.0, False, "Database connection failed")

        alerts = monitor.get_alerts()
        assert len(alerts) > 0
        assert "Database connection failed" in alerts[0]["message"]

    def test_filter_alerts_by_severity(self):
        """Test filtering alerts by severity."""
        monitor = SystemHealthMonitor()
        monitor.register_component("comp", ComponentType.PATTERN_DETECTION)

        monitor.record_operation("comp", 100.0, False, "Error 1")
        monitor.record_operation("comp", 100.0, False, "Error 2")

        error_alerts = monitor.get_alerts(severity="ERROR")
        assert len(error_alerts) == 2

    def test_alert_limit(self):
        """Test alert retrieval limit."""
        monitor = SystemHealthMonitor()
        monitor.register_component("comp", ComponentType.HISTORICAL)

        for i in range(50):
            monitor.record_operation("comp", 100.0, False, f"Error {i}")

        alerts = monitor.get_alerts(limit=10)
        assert len(alerts) == 10


class TestPerformanceSummary:
    """Test performance summary metrics."""

    def test_performance_summary(self):
        """Test getting performance summary."""
        monitor = SystemHealthMonitor()
        monitor.register_component("api", ComponentType.ADAPTERS)

        monitor.record_operation("api", 100.0, True)
        monitor.record_operation("api", 200.0, True)
        monitor.record_operation("api", 150.0, False)

        summary = monitor.get_performance_summary()

        assert summary["total_operations"] == 2
        assert summary["total_errors"] == 1
        assert summary["avg_response_time_ms"] > 0
        assert summary["overall_success_rate"] < 100

    def test_performance_summary_empty(self):
        """Test performance summary with no data."""
        monitor = SystemHealthMonitor()
        summary = monitor.get_performance_summary()

        assert summary["total_operations"] == 0
        assert summary["total_errors"] == 0
        assert summary.get("overall_success_rate", 100.0) == 100.0


class TestHealthTrend:
    """Test health trend analysis."""

    def test_health_trend_analysis(self):
        """Test analyzing health trend."""
        monitor = SystemHealthMonitor()
        monitor.register_component("service", ComponentType.MEMORY)

        # Simulate improving trend
        for i in range(5):
            monitor.record_operation("service", 100.0, True)
        for i in range(2):
            monitor.record_operation("service", 100.0, False)

        trend = monitor.get_health_trend(hours=24)

        assert trend["period_hours"] == 24
        assert trend["total_alerts"] >= 0

    def test_trend_classification(self):
        """Test trend classification."""
        monitor = SystemHealthMonitor()

        # Test worsening trend
        values = [1, 1, 1, 5, 8, 10]
        trend = monitor._analyze_trend(values)
        assert trend == "worsening"

        # Test improving trend
        values = [10, 8, 5, 1, 1, 1]
        trend = monitor._analyze_trend(values)
        assert trend == "improving"


class TestIntegration:
    """Test complete health monitoring workflow."""

    def test_complete_monitoring_workflow(self):
        """Test complete system monitoring."""
        monitor = SystemHealthMonitor()

        # Register components
        for comp_type in ComponentType:
            monitor.register_component(f"comp_{comp_type.value}", comp_type)

        # Simulate operations
        for comp_name in monitor.component_stats.keys():
            if "schema" in comp_name:
                for i in range(50):
                    monitor.record_operation(comp_name, 100.0, True)
            elif "repo" in comp_name:
                for i in range(30):
                    monitor.record_operation(comp_name, 200.0, i > 20)
            else:
                for i in range(20):
                    monitor.record_operation(comp_name, 150.0, i < 10)

        # Get full monitoring report
        report = monitor.to_dict()

        assert report["timestamp"]
        assert report["health"]["components"] > 0
        assert "performance" in report
        assert "bottlenecks" in report
        assert "recommendations" in report
        assert "trend" in report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
