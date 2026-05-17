# ATI System - Deployment Guide

## System Requirements

### Runtime Environment
- **Python:** 3.9 or later
- **Operating System:** Windows, macOS, Linux
- **Memory:** Minimum 4GB RAM (8GB recommended for concurrent analytics)
- **Storage:** 2GB for application + database files

### Core Dependencies
```
pydantic>=2.0.0          # Data validation and schema
sqlalchemy>=2.0.0        # Database ORM
sqlite3                  # Built-in SQLite support
networkx>=3.0            # Graph algorithms
httpx>=0.24.0            # Async HTTP client for adapters
python-dateutil>=2.8.2   # Date/time utilities
requests>=2.31.0         # HTTP client for OpenCTI integration
```

## Installation

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/ATI-AgenticThreatIntelligence.git
cd ATI-AgenticThreatIntelligence
```

### 2. Create Virtual Environment
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Verify Installation
```bash
pytest tests/ -v
```

## Configuration

### SQLite Database Setup
```python
from core.threat_repository import SQLiteRepository

# In-memory (testing/development)
repo = SQLiteRepository(":memory:")

# File-based (production)
repo = SQLiteRepository("threats.db")
```

### External Data Source Configuration

#### NVD Adapter
```python
from core.threat_adapters import NVDAdapter

nvd = NVDAdapter()
# Fetches from https://services.nvd.nist.gov/rest/json/cves/2.0
```

#### EPSS Adapter
```python
from core.threat_adapters import EPSSAdapter

epss = EPSSAdapter()
# Fetches EPSS scores from https://api.first.org/data/v1/epss
```

#### KEV Adapter
```python
from core.threat_adapters import KEVAdapter

kev = KEVAdapter()
# Fetches CISA Known Exploited Vulnerabilities
```

#### OpenCTI Adapter
```python
from core.threat_adapters import OpenCTIAdapter

opencti = OpenCTIAdapter(api_url="http://localhost:4000", api_token="YOUR_TOKEN")
# Connects to OpenCTI instance for IOC enrichment
```

## System Deployment

### Development Environment
```python
from core.threat_repository import SQLiteRepository
from core.threat_fusion import ThreatFusionEngine
from core.system_health import SystemHealthMonitor, ComponentType

# Initialize repository
repo = SQLiteRepository("dev.db")

# Initialize fusion engine
fusion_engine = ThreatFusionEngine(repo)

# Initialize health monitoring
monitor = SystemHealthMonitor()
monitor.register_component("fusion_engine", ComponentType.FUSION)

# Start using system
vulnerability = repo.get_vulnerability("CVE-2024-12345")
```

### Production Environment

#### 1. Database Deployment
```bash
# Initialize production database
python -c "
from core.threat_repository import SQLiteRepository
repo = SQLiteRepository('/var/lib/ati/threats.db')
print('Database initialized at /var/lib/ati/threats.db')
"
```

#### 2. Backup Strategy
```bash
# Daily backup
cp /var/lib/ati/threats.db /var/backups/ati/threats_$(date +%Y%m%d).db

# Weekly archive
tar -czf /var/backups/ati/threats_week_$(date +%Y%m%d).tar.gz /var/lib/ati/
```

#### 3. Health Monitoring Integration
```python
from core.system_health import SystemHealthMonitor
import logging

monitor = SystemHealthMonitor()

# Log system health every 5 minutes
def check_health():
    health = monitor.get_system_health()
    if health["status"] != "healthy":
        logging.warning(f"System health: {health}")
    
    bottlenecks = monitor.detect_bottlenecks()
    if bottlenecks:
        logging.error(f"Bottlenecks detected: {bottlenecks}")
```

## Running Tests

### All Tests
```bash
pytest tests/ -v
```

### By Phase
```bash
# Week 1 - Basic Schema and Repository
pytest tests/test_week1_schema.py -v

# Week 2 - Fusion Engine and Correlation
pytest tests/test_week2_fusion.py -v
pytest tests/test_week2_relationship.py -v

# Week 3 - Temporal and Pattern Detection
pytest tests/test_week3_temporal.py -v
pytest tests/test_week3_pattern.py -v

# Week 4 - Graph and Analytics
pytest tests/test_week4_graph.py -v
pytest tests/test_week4_advanced_analytics.py -v

# Week 5 - System Health
pytest tests/test_week5_system_health.py -v

# Week 6 - Integration
pytest tests/test_week6_integration.py -v
```

### Coverage Report
```bash
pytest --cov=core --cov=tests --cov-report=html tests/
# Open htmlcov/index.html to view coverage
```

## API Usage Examples

### Threat Analysis Pipeline
```python
from core.threat_repository import SQLiteRepository
from core.threat_fusion import ThreatFusionEngine
from core.advanced_analytics import AnalyticsEngine
from core.system_health import SystemHealthMonitor, ComponentType
from datetime import datetime, timedelta

# Initialize components
repo = SQLiteRepository(":memory:")
fusion = ThreatFusionEngine(repo)
analytics = AnalyticsEngine()
monitor = SystemHealthMonitor()

# Register monitoring
monitor.register_component("analytics", ComponentType.ANALYTICS)

# Analyze threat timeline
now = datetime.utcnow()
threat_events = [
    {"timestamp": now - timedelta(days=i)} for i in range(30)
]
timeline = analytics.analyze_threat_timeline(threat_events)

# Correlate threat layers
vulns = [{"id": "CVE-2024-001", "cwe_ids": ["CWE-79"]}]
campaigns = [{"id": "campaign-1", "techniques": ["CWE-79"]}]
correlation = analytics.correlate_threat_layers(vulns, [], campaigns, [])

# Aggregate risk
risk = analytics.aggregate_risk(
    {"vuln1": 0.8},
    correlation["correlation_density"],
    timeline["escalation_level"]
)

# Record metrics
monitor.record_operation("analytics", 150.0, True)

# Generate report
health = monitor.get_system_health()
print(f"System health: {health['status']}")
```

### Response Automation
```python
from core.response_automation import ResponseAutomationEngine

automation = ResponseAutomationEngine()

# Create playbook
automation.create_playbook(
    "pb-critical",
    "Critical Threat Response",
    "campaign"
)

# Add actions
automation.add_playbook_action("pb-critical", "block", "192.168.1.0/24")
automation.add_playbook_action("pb-critical", "alert", "security-team")
automation.add_playbook_action("pb-critical", "investigate", "suspicious-accounts")

# Execute workflow
workflow = automation.execute_playbook("pb-critical", "threat-001", "campaign")
results = automation.execute_workflow(workflow.workflow_id)

print(f"Actions executed: {results['actions_executed']}")
print(f"Actions succeeded: {results['actions_succeeded']}")
```

### Knowledge Graph Queries
```python
from core.graph_integration import GraphIntegrationEngine
from core.threat_schema import Vulnerability, Campaign, IOC, IOCType, SeverityLevel

graph = GraphIntegrationEngine()

# Populate entities
vuln = Vulnerability(id="CVE-2024-001", description="Test")
campaign = Campaign(id="c1", name="Campaign")
ioc = IOC(id="ioc-001", ioc_type=IOCType.IP, value="10.0.0.1", severity=SeverityLevel.HIGH)

vuln_id = graph.populate_vulnerability(vuln)
camp_id = graph.populate_campaign(campaign)
ioc_id = graph.populate_ioc(ioc)

# Create relationships
graph.add_relationship(vuln_id, camp_id, "exploits", weight=0.95)
graph.add_relationship(camp_id, ioc_id, "uses", weight=0.80)

# Query intelligence
intelligence = graph.get_graph_intelligence()
print(f"Total nodes: {intelligence['graph_stats']['total_nodes']}")
print(f"Total edges: {intelligence['graph_stats']['total_edges']}")
```

## Performance Tuning

### Database Optimization
```python
from core.threat_repository import SQLiteRepository

repo = SQLiteRepository("threats.db")

# Optimize for read-heavy workloads
repo.execute("PRAGMA query_only = ON")
repo.execute("PRAGMA synchronous = NORMAL")
repo.execute("PRAGMA cache_size = 10000")
```

### Analytics Caching
```python
from core.advanced_analytics import AnalyticsEngine

analytics = AnalyticsEngine()

# Analyze timeline once, reuse results
threat_timeline = analytics.analyze_threat_timeline(events)
risk_result = analytics.aggregate_risk(
    entity_risks,
    correlation_density,
    threat_timeline["escalation_level"]
)
```

## Troubleshooting

### Database Locks
**Error:** `sqlite3.OperationalError: database is locked`

**Solution:**
```python
from core.threat_repository import SQLiteRepository
import time

repo = SQLiteRepository("threats.db")

# Add retry logic
for attempt in range(3):
    try:
        repo.add_vulnerability(vuln)
        break
    except Exception as e:
        time.sleep(1)
        if attempt == 2:
            raise
```

### Memory Issues
**Error:** `MemoryError` during large graph analysis

**Solution:**
```python
# Process in batches
from core.graph_integration import GraphIntegrationEngine

graph = GraphIntegrationEngine()

batch_size = 1000
for i in range(0, len(vulnerabilities), batch_size):
    batch = vulnerabilities[i:i+batch_size]
    for vuln in batch:
        graph.populate_vulnerability(vuln)
```

### Performance Bottlenecks
```python
from core.system_health import SystemHealthMonitor

monitor = SystemHealthMonitor()

# Detect slowdowns
bottlenecks = monitor.detect_bottlenecks()
for bottleneck in bottlenecks:
    print(f"Bottleneck: {bottleneck}")

# Get optimization recommendations
recs = monitor.get_optimization_recommendations()
for rec in recs:
    print(f"Action: {rec['action']}")
    print(f"Steps: {rec['steps']}")
```

## Logging

```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ati.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
logger.info("ATI System initialized")
```

## Support and Maintenance

### Regular Maintenance Tasks
1. **Daily:** Monitor system health logs
2. **Weekly:** Backup threat database
3. **Monthly:** Review performance bottlenecks and optimize
4. **Quarterly:** Update threat intelligence adapters

### Updating Dependencies
```bash
pip install --upgrade -r requirements.txt
pytest tests/ -v  # Verify after update
```

## Contact and Support
- Documentation: See [ARCHITECTURE.md](ARCHITECTURE.md)
- Issues: Create GitHub issue with system health output
- Questions: Contact development team
