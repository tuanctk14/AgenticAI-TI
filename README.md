# Agentic Threat Intelligence (ATI) System

A comprehensive threat intelligence platform combining canonical threat schema modeling, multi-source fusion, relationship correlation, temporal analysis, knowledge graph reasoning, advanced analytics, and response automation.

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/ATI-AgenticThreatIntelligence.git
cd ATI-AgenticThreatIntelligence

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running Tests

```bash
# All tests (430 total)
pytest tests/ -v

# Specific phase
pytest tests/test_week4_advanced_analytics.py -v

# With coverage
pytest --cov=core tests/ -v
```

### Quick Example

```python
from core.advanced_analytics import AnalyticsEngine
from core.graph_integration import GraphIntegrationEngine
from core.threat_schema import Vulnerability, Campaign
from datetime import datetime, timedelta

# Initialize components
analytics = AnalyticsEngine()
graph = GraphIntegrationEngine()

# Analyze threat timeline
now = datetime.utcnow()
events = [{"timestamp": now - timedelta(days=i)} for i in range(30)]
timeline = analytics.analyze_threat_timeline(events)

# Populate graph with entities
vuln = Vulnerability(id="CVE-2024-001", description="Test")
campaign = Campaign(id="c1", name="Campaign")
vuln_id = graph.populate_vulnerability(vuln)
camp_id = graph.populate_campaign(campaign)
graph.add_relationship(vuln_id, camp_id, "exploits")

# Get intelligence
intelligence = graph.get_graph_intelligence()
print(f"Nodes: {intelligence['graph_stats']['total_nodes']}")
print(f"Edges: {intelligence['graph_stats']['total_edges']}")

# Aggregate risk
risk = analytics.aggregate_risk(
    {"vuln1": 0.8},
    0.5,
    timeline["escalation_level"]
)
print(f"Risk level: {risk['risk_level']}")
```

## System Architecture

### 7-Layer Architecture

1. **Foundation (Week 1)**
   - Canonical threat schema (Pydantic models)
   - Repository pattern abstraction
   - Pluggable source adapters (NVD, EPSS, KEV, Vulners, OpenCTI)

2. **Fusion & Correlation (Week 1-2)**
   - Multi-source threat intelligence fusion
   - Semantic deduplication
   - Threat relationship discovery

3. **Temporal & Pattern Analysis (Week 2-3)**
   - Threat memory with recurrence tracking
   - Timeline enrichment
   - Pattern detection
   - Historical context and actor profiling

4. **Knowledge Graph (Week 3-4)**
   - Graph-based threat reasoning
   - Entity relationship mapping
   - Path finding and centrality analysis
   - Community detection and actor profiling

5. **Analytics & Reasoning (Week 4)**
   - Threat timeline analysis
   - Cross-layer correlation
   - Predictive threat vectors
   - Risk aggregation with escalation multipliers

6. **Response & Monitoring (Week 4-5)**
   - Threat-driven playbook execution
   - Component health monitoring
   - Bottleneck detection
   - Optimization recommendations

7. **Integration (Week 6)**
   - End-to-end workflow testing
   - Cross-component validation
   - Error handling and resilience

## Key Features

### Threat Schema
- **Vulnerability:** CVE-based threat data with CWE mappings
- **IOC:** Indicators of compromise (IPs, domains, hashes, emails, URLs)
- **Campaign:** Organized threat activity with temporal bounds
- **ThreatActor:** Threat group profiles with activity levels
- **Infrastructure:** Malicious hosting infrastructure
- **Asset:** System/organization assets with criticality

### Analytics Engine
- **Timeline Analysis:** Detect rising/stable/declining trends
- **Escalation Prediction:** Dormant → Emerging → Active → Critical
- **Cross-Layer Correlation:** Link vulnerabilities, IOCs, campaigns, actors
- **Predictive Vectors:** Forecast likely target sectors and techniques
- **Risk Aggregation:** Multi-factor scoring with escalation multipliers
- **Executive Reports:** C-level intelligence summaries with confidence scores

### Knowledge Graph
- **8 Node Types:** vulnerability, ioc, campaign, actor, infrastructure, asset, malware, technique
- **9 Edge Types:** exploits, targets, uses, part_of, communicates_with, infrastructure, attributed_to, similar_to, related_to
- **Path Finding:** Discover attack chains and threat propagation
- **Centrality Analysis:** Identify key infrastructure and threat influencers
- **Community Detection:** Cluster related threat actors and campaigns

### Response Automation
- Threat-type-driven playbook execution
- 5 action types: block, alert, investigate, patch, isolate
- Workflow execution with success/failure tracking
- Audit trail and metrics collection
- **No SIEM/EDR integration** (standalone system)

### System Health
- Per-component performance monitoring
- Bottleneck detection (slow components, high error rates)
- Optimization recommendations with implementation steps
- Health trend analysis (improving, stable, worsening)
- Alert management with severity filtering

## API Reference

### AnalyticsEngine

```python
engine = AnalyticsEngine()

# Timeline analysis
timeline = engine.analyze_threat_timeline(threat_events, window_days=30)
# Returns: activity_count, trend, escalation_level, avg_daily_events

# Threat correlation
correlation = engine.correlate_threat_layers(vulns, iocs, campaigns, actors)
# Returns: correlation_count, correlation_density, vuln_exploit_links, etc.

# Predictive analysis
predictions = engine.predict_threat_vectors(historical_data, iocs, trends)
# Returns: prediction_count, predictions (with confidence scores)

# Risk aggregation
risk = engine.aggregate_risk(entity_risks, correlation_density, escalation_level)
# Returns: aggregated_risk, risk_level, escalation_multiplier

# Recommendations
recs = engine.generate_recommendations(threat_timeline, risk_assessment, assets)
# Returns: recommendation_count, recommendations, review_frequency

# Executive report
report = engine.generate_executive_report(threat, risk, recommendations, stats)
# Returns: executive_summary, critical_actions, key_metrics, confidence score
```

### GraphIntegrationEngine

```python
graph = GraphIntegrationEngine()

# Populate entities
vuln_id = graph.populate_vulnerability(vulnerability_obj)
ioc_id = graph.populate_ioc(ioc_obj)
campaign_id = graph.populate_campaign(campaign_obj)
actor_id = graph.populate_actor(actor_obj)
infra_id = graph.populate_infrastructure(infrastructure_obj)

# Create relationships
graph.add_relationship(vuln_id, campaign_id, "exploits", weight=0.95)
graph.add_relationship(actor_id, campaign_id, "attributed_to", weight=0.90)

# Query graph
intelligence = graph.get_graph_intelligence()
# Returns: graph_stats, threat_landscape, attack_chains, clusters

landscape = graph.get_threat_landscape()
# Returns: active_entities, threat_density, critical_relationships

chains = graph.find_attack_chain(start_entity)
# Returns: attack_path sequences with risk scores

clusters = graph.detect_threat_clusters()
# Returns: connected components with entity groupings
```

### ResponseAutomationEngine

```python
automation = ResponseAutomationEngine()

# Create playbook
automation.create_playbook("pb-critical", "Critical Response", "campaign")

# Add actions
automation.add_playbook_action("pb-critical", "block", "192.168.1.0/24")
automation.add_playbook_action("pb-critical", "alert", "security-team")
automation.add_playbook_action("pb-critical", "investigate", "suspicious-accounts")

# Execute workflow
workflow = automation.execute_playbook("pb-critical", threat_id, "campaign")
results = automation.execute_workflow(workflow.workflow_id)
# Returns: actions_executed, actions_succeeded, timestamp

# Get metrics
metrics = automation.get_workflow_metrics()
# Returns: total_workflows, avg_success_rate, action_breakdown
```

### SystemHealthMonitor

```python
monitor = SystemHealthMonitor()

# Register component
monitor.register_component("analytics", ComponentType.ANALYTICS)

# Record metrics
monitor.record_operation("analytics", duration_ms=150.0, success=True)
monitor.record_operation("analytics", duration_ms=200.0, success=False, error_msg="Timeout")

# Query health
health = monitor.get_component_health("analytics")
# Returns: status, response_time_ms, success_rate, error_count

system_health = monitor.get_system_health()
# Returns: overall_status, healthy_components, warning_components, critical_components

# Detect issues
bottlenecks = monitor.detect_bottlenecks()
# Returns: list of slow components and high-error components

# Get recommendations
recs = monitor.get_optimization_recommendations()
# Returns: priority, action, reason, implementation steps
```

## Data Models

### Threat Entity Classes

```python
from core.threat_schema import (
    Vulnerability,
    IOC,
    Campaign,
    ThreatActor,
    Infrastructure,
    Asset,
    SeverityLevel,
    IOCType,
)

# Create vulnerability
vuln = Vulnerability(
    id="CVE-2024-12345",
    description="Critical authentication bypass",
    severity=SeverityLevel.CRITICAL,
    cwe_ids=["CWE-79", "CWE-89"],
    attack_vectors=["NETWORK", "ADJACENT_NETWORK"]
)

# Create IOC
ioc = IOC(
    id="ioc-ip-001",
    ioc_type=IOCType.IP,
    value="192.168.1.100",
    severity=SeverityLevel.HIGH,
    confidence=0.95
)

# Create campaign
campaign = Campaign(
    id="campaign-apt-001",
    name="Operation Stealth",
    sectors=["Finance", "Healthcare"],
    techniques=["T1234", "T5678"]
)

# Create threat actor
actor = ThreatActor(
    id="actor-apt-28",
    name="Fancy Bear",
    activity_level="high",
    attribution_confidence=0.85
)

# Create infrastructure
infra = Infrastructure(
    id="infra-001",
    node_type="domain",
    value="evil.com",
    hosted_by="HostProvider-XYZ"
)
```

## Documentation

- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Installation, configuration, deployment, troubleshooting
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture, data models, workflows, testing strategy

## Testing

### Test Coverage
- **430 total tests** across 6 phases and 1 week of integration
- **35 tests:** Foundation (schema, repository, adapters)
- **21 tests:** Fusion & correlation
- **31 tests:** Temporal & pattern analysis
- **119 tests:** Graph intelligence & analytics
- **50 tests:** Response automation & health monitoring
- **13 tests:** End-to-end integration
- **161 tests:** Additional phase tests

### Running Specific Tests
```bash
# Foundation
pytest tests/test_week1_schema.py -v

# Fusion
pytest tests/test_week2_fusion.py tests/test_week2_relationship.py -v

# Temporal
pytest tests/test_week3_temporal.py tests/test_week3_pattern.py -v

# Graph & Analytics
pytest tests/test_week4_*.py -v

# System Health
pytest tests/test_week5_system_health.py -v

# Integration
pytest tests/test_week6_integration.py -v
```

## Performance

### Component Performance
- Schema parsing: O(1) - Pydantic validation
- Repository queries: O(n) - SQLite index-backed
- Fusion engine: O(n²) - Semantic similarity
- Graph path finding: O(n+e) - BFS
- Analytics: O(n log n) - Sorting and grouping
- Risk aggregation: O(n) - Single pass

### Scalability
- **10K-100K** vulnerabilities
- **100K-1M** IOCs
- **100-10K** campaigns
- **100K-10M** relationships
- **1K-100K** knowledge graph nodes

## Support

- **Issues:** Create GitHub issue with system health output
- **Questions:** Contact development team
- **Documentation:** See DEPLOYMENT.md and ARCHITECTURE.md

## License

Copyright (c) 2026 ATI Development Team. All rights reserved.

---

**Status:** ✅ Week 6 Complete - 430 Tests Passing  
**Total Code:** 8,950+ LOC  
**Last Updated:** 2026-05-17  
**Version:** 1.0.0
