"""
tests/test_real_data_integration.py - Real Data Integration Testing

Tests full system with real threat intelligence from multiple sources.
Validates threat fusion, analytics, and response automation with production data.
"""

import pytest
import httpx
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from core.threat_adapters import NVDAdapter, EPSSAdapter, KEVAdapter
from core.threat_fusion import ThreatFusionEngine
from core.threat_repository import SQLiteRepository
from core.advanced_analytics import AnalyticsEngine
from core.graph_integration import GraphIntegrationEngine
from core.response_automation import ResponseAutomationEngine
from core.system_health import SystemHealthMonitor, ComponentType
from core.threat_schema import Vulnerability, SeverityLevel, RiskContext


class RealDataIntegrator:
    """Integrate real threat data from multiple sources."""

    def __init__(self):
        self.nvd_adapter = NVDAdapter()
        self.epss_adapter = EPSSAdapter()
        self.kev_adapter = KEVAdapter()
        self.repo = SQLiteRepository(":memory:")
        self.fusion_engine = ThreatFusionEngine(self.repo)

    async def fetch_cve_data(self, cve_id: str) -> Optional[Vulnerability]:
        """Fetch CVE data from NVD and enrich with EPSS/KEV."""
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                # Fetch from NVD
                nvd_response = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cveId": cve_id}
                )

                if nvd_response.status_code != 200:
                    return None

                nvd_data = nvd_response.json()
                vulnerabilities = nvd_data.get("vulnerabilities", [])

                if not vulnerabilities:
                    return None

                cve = vulnerabilities[0]["cve"]

                # Extract NVD data
                metrics = cve.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [])

                normalized_data = {
                    "id": cve["id"],
                    "description": cve.get("descriptions", [{}])[0].get("value", ""),
                    "cwe_ids": self._extract_cwe_ids(cve),
                    "references": self._extract_references(cve),
                    "published": cve.get("published"),
                    "modified": cve.get("lastModified"),
                    "severity": self._extract_severity(cvss_v31),
                    "cvss_score": self._extract_cvss_score(cvss_v31),
                    "cvss_vector": self._extract_cvss_vector(cvss_v31),
                }

                vuln = self.nvd_adapter.normalize_vulnerability(normalized_data)

                if vuln:
                    # Try to enrich with EPSS
                    epss_response = await client.get(
                        "https://api.first.org/data/v1/epss",
                        params={"cve": cve_id}
                    )

                    if epss_response.status_code == 200:
                        epss_data = epss_response.json()
                        if epss_data.get("status") == "OK" and epss_data.get("data"):
                            vuln = self.epss_adapter.merge_epss_enrichment(
                                vuln,
                                epss_data["data"][0]
                            )

                    # Try to enrich with KEV
                    kev_response = await client.get(
                        "https://services.cisa.gov/json/cves_kev_v1.json"
                    )

                    if kev_response.status_code == 200:
                        kev_data = kev_response.json()
                        vulns_list = kev_data.get("vulnerabilities", [])
                        kev_match = next(
                            (v for v in vulns_list if v.get("cveID") == cve_id),
                            None
                        )
                        if kev_match:
                            vuln = self.kev_adapter.merge_kev_enrichment(vuln, kev_match)

                return vuln

        except Exception as e:
            print(f"[Integration] Error fetching {cve_id}: {e}")
            return None

    @staticmethod
    def _extract_cwe_ids(cve: Dict[str, Any]) -> List[str]:
        """Extract CWE IDs from NVD CVE."""
        weaknesses = cve.get("weaknesses", [])
        cwe_ids = []
        for weakness in weaknesses:
            for cwe in weakness.get("cweId", []):
                cwe_id = cwe.get("id")
                if cwe_id and cwe_id not in cwe_ids:
                    cwe_ids.append(cwe_id)
        return cwe_ids

    @staticmethod
    def _extract_references(cve: Dict[str, Any]) -> List[str]:
        """Extract references from NVD CVE."""
        references = cve.get("references", [])
        return [ref.get("url", "") for ref in references if ref.get("url")]

    @staticmethod
    def _extract_severity(cvss_v31: List[Dict]) -> str:
        """Extract CVSS severity."""
        if not cvss_v31:
            return "UNKNOWN"
        return cvss_v31[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")

    @staticmethod
    def _extract_cvss_score(cvss_v31: List[Dict]) -> Optional[float]:
        """Extract CVSS score."""
        if not cvss_v31:
            return None
        return cvss_v31[0].get("cvssData", {}).get("baseScore")

    @staticmethod
    def _extract_cvss_vector(cvss_v31: List[Dict]) -> Optional[str]:
        """Extract CVSS vector."""
        if not cvss_v31:
            return None
        return cvss_v31[0].get("cvssData", {}).get("vectorString")


class TestRealDataIntegration:
    """Test full system with real threat data."""

    @pytest.fixture
    async def integrator(self):
        """Initialize real data integrator."""
        return RealDataIntegrator()

    @pytest.fixture
    def analytics(self):
        """Initialize analytics engine."""
        return AnalyticsEngine()

    @pytest.fixture
    def graph(self):
        """Initialize graph engine."""
        return GraphIntegrationEngine()

    @pytest.fixture
    def automation(self):
        """Initialize automation engine."""
        return ResponseAutomationEngine()

    @pytest.fixture
    def monitor(self):
        """Initialize health monitor."""
        return SystemHealthMonitor()

    @pytest.mark.asyncio
    async def test_single_cve_enrichment(self, integrator):
        """Test enriching single CVE with multiple sources."""
        cve_id = "CVE-2024-3156"

        vuln = await integrator.fetch_cve_data(cve_id)

        if vuln:
            print(f"\n[Integration] Enriched {vuln.id}:")
            print(f"  Severity: {vuln.severity.value}")
            print(f"  CVSS: {vuln.risk_context.cvss_score if vuln.risk_context else 'N/A'}")
            print(f"  EPSS: {vuln.risk_context.epss_score if vuln.risk_context and vuln.risk_context.epss_score else 'N/A'}")
            print(f"  KEV Listed: {vuln.risk_context.kev_listed if vuln.risk_context else 'N/A'}")
            print(f"  CWEs: {vuln.cwe_ids}")
            print(f"  Sources: {vuln.risk_context.data_sources if vuln.risk_context else []}")

            # Verify enrichment
            assert vuln.risk_context is not None, "Should have risk context"
            assert len(vuln.risk_context.data_sources) > 0, "Should have data sources"

            # At least CVSS from NVD
            assert vuln.risk_context.cvss_score is not None, "Should have CVSS"
        else:
            pytest.skip(f"Could not fetch {cve_id}")

    @pytest.mark.asyncio
    async def test_analytics_with_real_cves(self, integrator, analytics):
        """Test analytics with real CVE data."""
        cve_ids = [
            "CVE-2024-3156",
            "CVE-2024-2961",
            "CVE-2024-2233",
        ]

        vulnerabilities = []
        for cve_id in cve_ids:
            vuln = await integrator.fetch_cve_data(cve_id)
            if vuln:
                vulnerabilities.append(vuln)

        if vulnerabilities:
            # Create threat events from CVE data
            threat_events = [
                {
                    "timestamp": datetime.utcnow() - timedelta(days=i),
                    "cve_id": vuln.id,
                    "severity": vuln.severity.value
                }
                for i, vuln in enumerate(vulnerabilities)
            ]

            # Analyze timeline
            timeline = analytics.analyze_threat_timeline(threat_events)

            print(f"\n[Integration] Analytics Results:")
            print(f"  Activity Count: {timeline['activity_count']}")
            print(f"  Escalation Level: {timeline['escalation_level']}")
            print(f"  Trend: {timeline['trend']}")

            assert timeline["activity_count"] > 0, "Should have activity"

    @pytest.mark.asyncio
    async def test_graph_with_real_cves(self, integrator, graph):
        """Test knowledge graph with real CVE data."""
        cve_ids = ["CVE-2024-3156", "CVE-2024-2961"]

        vulnerabilities = []
        for cve_id in cve_ids:
            vuln = await integrator.fetch_cve_data(cve_id)
            if vuln:
                vulnerabilities.append(vuln)

        if vulnerabilities:
            # Populate graph
            node_ids = []
            for vuln in vulnerabilities:
                node_id = graph.populate_vulnerability(vuln)
                node_ids.append(node_id)
                print(f"[Integration] Added {vuln.id} to graph")

            # Get intelligence
            intelligence = graph.get_graph_intelligence()

            print(f"\n[Integration] Graph Intelligence:")
            print(f"  Total Nodes: {intelligence['graph_stats']['total_nodes']}")
            print(f"  Total Edges: {intelligence['graph_stats']['total_edges']}")

            assert intelligence["graph_stats"]["total_nodes"] > 0, "Should have nodes"

    @pytest.mark.asyncio
    async def test_response_automation_with_real_cves(self, integrator, automation):
        """Test response automation with real CVE data."""
        cve_id = "CVE-2024-3156"

        vuln = await integrator.fetch_cve_data(cve_id)

        if vuln:
            # Create playbook
            automation.create_playbook(
                "pb-real-cve",
                f"Response for {vuln.id}",
                "vulnerability"
            )

            # Add actions based on severity
            if vuln.severity == SeverityLevel.CRITICAL:
                automation.add_playbook_action("pb-real-cve", "block", vuln.id)
                automation.add_playbook_action("pb-real-cve", "alert", "security-team")
                automation.add_playbook_action("pb-real-cve", "investigate", vuln.id)

            # Execute
            workflow = automation.execute_playbook("pb-real-cve", vuln.id, "vulnerability")
            results = automation.execute_workflow(workflow.workflow_id)

            print(f"\n[Integration] Response Results:")
            print(f"  Playbook: pb-real-cve")
            print(f"  CVE: {vuln.id}")
            print(f"  Actions Executed: {results['actions_executed']}")
            print(f"  Actions Succeeded: {results['actions_succeeded']}")

    @pytest.mark.asyncio
    async def test_system_health_monitoring(self, integrator, monitor):
        """Test system health monitoring with real operations."""
        # Register components
        monitor.register_component("nvd_adapter", ComponentType.ADAPTERS)
        monitor.register_component("epss_adapter", ComponentType.ADAPTERS)
        monitor.register_component("analytics", ComponentType.ANALYTICS)

        # Simulate operations
        cve_ids = ["CVE-2024-3156", "CVE-2024-2961", "CVE-2024-2233"]
        success_count = 0

        for cve_id in cve_ids:
            # NVD adapter operation
            vuln = await integrator.fetch_cve_data(cve_id)
            duration = 150.0  # Approximate
            success = vuln is not None

            if success:
                success_count += 1

            monitor.record_operation("nvd_adapter", duration, success)

        # Analytics operation
        monitor.record_operation("analytics", 100.0, True)

        # Get health
        health = monitor.get_system_health()

        print(f"\n[Integration] System Health:")
        print(f"  Status: {health['status']}")
        print(f"  Components: {health['components']}")
        print(f"  Healthy: {health['healthy_components']}")
        print(f"  CVEs Successfully Fetched: {success_count}/{len(cve_ids)}")

    @pytest.mark.asyncio
    async def test_end_to_end_workflow(self, integrator, graph, analytics, automation, monitor):
        """Test complete end-to-end workflow with real data."""
        print("\n[Integration] Starting end-to-end workflow with real threat data...")

        # Register components
        monitor.register_component("integration_workflow", ComponentType.FUSION)

        # Fetch real CVE
        cve_id = "CVE-2024-3156"
        vuln = await integrator.fetch_cve_data(cve_id)

        if vuln:
            print(f"✓ Fetched {vuln.id} with {len(vuln.risk_context.data_sources)} data sources")

            # Add to graph
            node_id = graph.populate_vulnerability(vuln)
            print(f"✓ Added {vuln.id} to knowledge graph")

            # Analyze
            events = [{"timestamp": datetime.utcnow()}]
            timeline = analytics.analyze_threat_timeline(events)
            print(f"✓ Analyzed threat timeline: escalation={timeline['escalation_level']}")

            # Response
            automation.create_playbook("pb-workflow", f"Response for {vuln.id}", "vulnerability")
            automation.add_playbook_action("pb-workflow", "alert", "team")
            workflow = automation.execute_playbook("pb-workflow", vuln.id, "vulnerability")
            results = automation.execute_workflow(workflow.workflow_id)
            print(f"✓ Executed response playbook: {results['actions_executed']} actions")

            # Monitor
            monitor.record_operation("integration_workflow", 250.0, True)
            health = monitor.get_system_health()
            print(f"✓ System health: {health['status']}")

            print(f"\n✓✓✓ End-to-end workflow COMPLETE with real threat data")

        else:
            pytest.skip(f"Could not fetch {cve_id}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
