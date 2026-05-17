"""
tests/test_week6_integration.py - Full Integration Testing

End-to-end threat intelligence workflow:
- Complete threat entity lifecycle
- Cross-component data flow
- Multi-source threat correlation
- Knowledge graph integration
- Analytics pipeline
- Response automation
"""

import pytest
from datetime import datetime, timedelta

from core.threat_schema import (
    Vulnerability,
    IOC,
    Campaign,
    ThreatActor,
    Infrastructure,
    SeverityLevel,
    IOCType,
)
from core.threat_fusion import ThreatFusionEngine
from core.knowledge_graph import KnowledgeGraph, NodeType, EdgeType
from core.graph_integration import GraphIntegrationEngine
from core.advanced_analytics import AnalyticsEngine
from core.response_automation import ResponseAutomationEngine
from core.system_health import SystemHealthMonitor, ComponentType


class TestEndToEndWorkflow:
    """Test complete end-to-end threat intelligence workflow."""

    def test_threat_entities_creation(self):
        """Test creating threat entities."""
        vuln = Vulnerability(
            id="CVE-2024-12345",
            description="Critical authentication bypass",
        )
        campaign = Campaign(id="campaign-APT-001", name="Operation Stealth")
        actor = ThreatActor(id="actor-APT-28", name="Fancy Bear")
        ioc = IOC(
            id="ioc-ip-001",
            ioc_type=IOCType.IP,
            value="192.168.1.100",
            severity=SeverityLevel.HIGH,
        )

        assert vuln.id == "CVE-2024-12345"
        assert campaign.id == "campaign-APT-001"
        assert actor.id == "actor-APT-28"
        assert ioc.value == "192.168.1.100"

    def test_graph_integration_workflow(self):
        """Test graph integration with multiple entity types."""
        engine = GraphIntegrationEngine()

        vuln = Vulnerability(id="CVE-2024-001", description="Test")
        campaign = Campaign(id="c1", name="Campaign")
        actor = ThreatActor(id="a1", name="Actor")
        ioc = IOC(
            id="ioc-001",
            ioc_type=IOCType.IP,
            value="10.0.0.1",
            severity=SeverityLevel.HIGH,
        )
        infra = Infrastructure(id="i1", node_type="domain", value="evil.com")

        vuln_id = engine.populate_vulnerability(vuln)
        camp_id = engine.populate_campaign(campaign)
        actor_id = engine.populate_actor(actor)
        ioc_id = engine.populate_ioc(ioc)
        infra_id = engine.populate_infrastructure(infra)

        engine.add_relationship(vuln_id, camp_id, "exploits", weight=0.95)
        engine.add_relationship(actor_id, camp_id, "attributed_to", weight=0.90)
        engine.add_relationship(ioc_id, infra_id, "communicates_with", weight=0.85)
        engine.add_relationship(camp_id, ioc_id, "uses", weight=0.80)

        intelligence = engine.get_graph_intelligence()

        assert intelligence["graph_stats"]["total_nodes"] == 5
        assert intelligence["graph_stats"]["total_edges"] == 4

    def test_analytics_pipeline(self):
        """Test complete analytics pipeline."""
        analytics = AnalyticsEngine()

        now = datetime.utcnow()
        threat_events = [{"timestamp": now - timedelta(days=i)} for i in range(20)]

        timeline = analytics.analyze_threat_timeline(threat_events)
        assert timeline["activity_count"] == 20

        vulns = [{"id": "CVE-1", "cwe_ids": ["CWE-79"]}]
        campaigns = [{"id": "camp-1", "techniques": ["CWE-79"]}]
        correlation = analytics.correlate_threat_layers(vulns, [], campaigns, [])
        assert correlation["correlation_count"] > 0

        predictions = analytics.predict_threat_vectors(
            [{"target_sectors": ["finance"]}],
            [],
            [{"techniques": ["T1234"]}],
        )
        assert predictions["prediction_count"] > 0

        risk = analytics.aggregate_risk(
            {"entity1": 0.7},
            correlation["correlation_density"],
            timeline["escalation_level"],
        )
        assert risk["risk_level"] in ["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def test_response_automation_integration(self):
        """Test response automation with threat data."""
        engine = ResponseAutomationEngine()

        engine.create_playbook("pb-financial", "Financial Sector Defense", "campaign")
        engine.add_playbook_action("pb-financial", "block", "192.168.1.0/24")
        engine.add_playbook_action("pb-financial", "alert", "financial-sector-emails")
        engine.add_playbook_action("pb-financial", "investigate", "suspicious-accounts")

        workflow = engine.execute_playbook("pb-financial", "threat-financial-001", "campaign")
        assert workflow is not None
        assert len(workflow.actions) == 3

        results = engine.execute_workflow(workflow.workflow_id)
        assert results["actions_executed"] == 3
        assert results["actions_succeeded"] > 0

        metrics = engine.get_workflow_metrics()
        assert metrics["total_workflows"] >= 1

    def test_system_health_monitoring_integration(self):
        """Test system health monitoring across components."""
        monitor = SystemHealthMonitor()

        components = [
            ("schema_parser", ComponentType.SCHEMA),
            ("threat_repo", ComponentType.REPOSITORY),
            ("nvd_adapter", ComponentType.ADAPTERS),
            ("fusion_engine", ComponentType.FUSION),
            ("graph_engine", ComponentType.GRAPH),
            ("analytics_engine", ComponentType.ANALYTICS),
        ]

        for name, comp_type in components:
            monitor.register_component(name, comp_type)

        for i in range(100):
            for name, _ in components:
                success = (i + hash(name)) % 100 > 10
                monitor.record_operation(name, 50.0 + i % 100, success)

        health = monitor.get_system_health()
        assert health["components"] == len(components)

        perf = monitor.get_performance_summary()
        assert perf["total_operations"] > 0
        assert perf["overall_success_rate"] > 80.0


class TestCrossComponentIntegration:
    """Test integration between major components."""

    def test_graph_analytics_integration(self):
        """Test graph and analytics integration."""
        graph_engine = GraphIntegrationEngine()
        analytics = AnalyticsEngine()

        vuln = Vulnerability(id="CVE-2024-888", description="Graph test")
        campaign = Campaign(id="camp-graph", name="Graph test")

        vuln_id = graph_engine.populate_vulnerability(vuln)
        camp_id = graph_engine.populate_campaign(campaign)
        graph_engine.add_relationship(vuln_id, camp_id, "exploits")

        intelligence = graph_engine.get_graph_intelligence()
        threat_events = [{"timestamp": datetime.utcnow()}]
        analysis = analytics.analyze_threat_timeline(threat_events)

        assert intelligence["graph_stats"]["total_nodes"] == 2
        assert analysis["activity_count"] >= 0

    def test_automation_monitoring_integration(self):
        """Test automation and monitoring integration."""
        automation = ResponseAutomationEngine()
        monitor = SystemHealthMonitor()

        monitor.register_component("automation_engine", ComponentType.AUTOMATION)

        automation.create_playbook("pb-monitor", "Monitored Playbook", "ioc")
        automation.add_playbook_action("pb-monitor", "block", "10.0.0.0/8")

        workflow = automation.execute_playbook("pb-monitor", "threat-001", "ioc")

        for action in workflow.actions:
            monitor.record_operation(
                "automation_engine",
                100.0,
                action.status.value == "executing",
            )

        health = monitor.get_component_health("automation_engine")
        assert health is not None


class TestDataFlow:
    """Test data flow through system."""

    def test_threat_analysis_flow(self):
        """Test threat analysis flow."""
        analytics = AnalyticsEngine()

        now = datetime.utcnow()
        events = [{"timestamp": now - timedelta(hours=i)} for i in range(48)]

        timeline = analytics.analyze_threat_timeline(events, window_days=2)
        predictions = analytics.predict_threat_vectors([], [], [])
        risk = analytics.aggregate_risk(
            {"threat1": 0.5},
            0.3,
            timeline["escalation_level"],
        )
        recs = analytics.generate_recommendations(timeline, risk, [])

        assert recs["recommendation_count"] >= 0

    def test_graph_threat_flow(self):
        """Test graph-based threat flow."""
        engine = GraphIntegrationEngine()

        vuln = Vulnerability(id="CVE-2024-flow", description="Flow test")
        campaign = Campaign(id="camp-flow", name="Flow")
        actor = ThreatActor(id="actor-flow", name="Threat")

        vuln_id = engine.populate_vulnerability(vuln)
        camp_id = engine.populate_campaign(campaign)
        actor_id = engine.populate_actor(actor)

        engine.add_relationship(vuln_id, camp_id, "exploits")
        engine.add_relationship(actor_id, camp_id, "attributed_to")

        intelligence = engine.get_graph_intelligence()
        assert intelligence["graph_stats"]["total_nodes"] == 3
        assert intelligence["graph_stats"]["total_edges"] == 2


class TestErrorHandling:
    """Test error handling across components."""

    def test_invalid_relationship_handling(self):
        """Test handling of invalid relationships."""
        graph = KnowledgeGraph()

        edge = graph.add_edge("nonexistent1", "nonexistent2", EdgeType.EXPLOITS)
        assert edge is None

    def test_component_operation_failure_handling(self):
        """Test handling of component operation failures."""
        monitor = SystemHealthMonitor()
        monitor.register_component("failing_component", ComponentType.ADAPTERS)

        for i in range(10):
            monitor.record_operation(
                "failing_component",
                100.0,
                False,
                f"Failure {i}",
            )

        health = monitor.get_component_health("failing_component")
        assert health["error_count"] == 10
        assert health["success_rate"] == 0.0

    def test_empty_analytics_handling(self):
        """Test handling of empty analytics data."""
        analytics = AnalyticsEngine()

        timeline = analytics.analyze_threat_timeline([])
        assert timeline["activity_count"] == 0

        correlation = analytics.correlate_threat_layers([], [], [], [])
        assert correlation["correlation_count"] == 0


class TestCompleteWorkflow:
    """Test complete integrated workflow."""

    def test_full_threat_intelligence_pipeline(self):
        """Test full threat intelligence pipeline."""
        vuln = Vulnerability(id="CVE-2024-full", description="Full pipeline test")
        campaign = Campaign(id="campaign-full", name="Full pipeline")
        ioc = IOC(
            id="ioc-full",
            ioc_type=IOCType.IP,
            value="192.0.2.100",
            severity=SeverityLevel.CRITICAL,
        )

        graph_engine = GraphIntegrationEngine()
        vuln_id = graph_engine.populate_vulnerability(vuln)
        camp_id = graph_engine.populate_campaign(campaign)
        ioc_id = graph_engine.populate_ioc(ioc)

        graph_engine.add_relationship(vuln_id, camp_id, "exploits")
        graph_engine.add_relationship(camp_id, ioc_id, "uses")

        analytics = AnalyticsEngine()
        threat_data = [{"timestamp": datetime.utcnow() - timedelta(hours=i)} for i in range(10)]
        timeline = analytics.analyze_threat_timeline(threat_data)

        automation = ResponseAutomationEngine()
        automation.create_playbook("pb-full", "Full Pipeline Playbook", "campaign")
        automation.add_playbook_action("pb-full", "block", "192.0.2.100")
        automation.add_playbook_action("pb-full", "alert", "critical-vuln-team")

        workflow = automation.execute_playbook("pb-full", campaign.id, "campaign")
        results = automation.execute_workflow(workflow.workflow_id)

        monitor = SystemHealthMonitor()
        for comp_type in ComponentType:
            monitor.register_component(f"comp_{comp_type.value}", comp_type)

        monitor.record_operation("comp_graph", 50.0, True)
        monitor.record_operation("comp_analytics", 100.0, True)
        monitor.record_operation("comp_automation", 75.0, True)

        health = monitor.get_system_health()

        graph_intel = graph_engine.get_graph_intelligence()
        assert graph_intel["graph_stats"]["total_nodes"] >= 3
        assert timeline["activity_count"] == 10
        assert results["actions_executed"] == 2
        assert health["components"] == len(list(ComponentType))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
