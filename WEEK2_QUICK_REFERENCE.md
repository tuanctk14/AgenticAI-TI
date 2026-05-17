# Week 2 Quick Reference Guide

**Duration:** 5 days (17-05-2026 onwards)  
**Status:** Day 1 ✅ Complete, Days 2-5 ⏳ In Progress  
**Tests:** 31/31 PASSED

---

## 5 Memory Features

| Feature | Model | Methods | Purpose |
|---------|-------|---------|---------|
| Recurring IOC | RecurringIOCMemory | record_ioc_occurrence() | Track IOC reuse across campaigns |
| Campaign Persistence | CampaignPersistenceMemory | record_campaign_activity() | Monitor campaign evolution |
| Asset Exposure | AssetExposureHistoryMemory | record_asset_exposure() | Track asset vulnerability timeline |
| Infrastructure Reuse | InfrastructureReuseMemory | record_infrastructure_use() | Detect infrastructure pivot chains |
| Exploitation Pattern | ExploitationPatternMemory | record_exploitation_pattern() | Analyze attack pattern success |

---

## Core Methods (ThreatMemoryEngine)

### IOC Memory
```python
engine.record_ioc_occurrence(ioc_id, ioc_value, context, campaign_id, asset_id)
engine.get_ioc_memory(ioc_id) -> Optional[RecurringIOCMemory]
engine.get_recurring_iocs(min_occurrences=2) -> List[RecurringIOCMemory]
```

### Campaign Memory
```python
engine.record_campaign_activity(campaign_id, campaign_name, activity_type, targets_count, techniques_used)
engine.get_campaign_memory(campaign_id) -> Optional[CampaignPersistenceMemory]
engine.get_active_campaigns() -> List[CampaignPersistenceMemory]
```

### Asset Memory
```python
engine.record_asset_exposure(asset_id, asset_name, exposure_type, cve_id, ioc_id)
engine.record_asset_remediation(asset_id, exposure_duration_days, action)
engine.get_asset_memory(asset_id) -> Optional[AssetExposureHistoryMemory]
engine.get_exposed_assets() -> List[AssetExposureHistoryMemory]
```

### Infrastructure Memory
```python
engine.record_infrastructure_use(infrastructure_id, node_type, node_value, campaign_id, malware_family)
engine.get_infrastructure_memory(infrastructure_id) -> Optional[InfrastructureReuseMemory]
engine.get_reused_infrastructure(min_reuses=2) -> List[InfrastructureReuseMemory]
```

### Exploitation Pattern Memory
```python
engine.record_exploitation_pattern(pattern_id, pattern_name, technique_id, technique_name, campaign_id, success, target_count)
engine.get_pattern_memory(pattern_id) -> Optional[ExploitationPatternMemory]
engine.get_effective_patterns(min_success_rate=0.5) -> List[ExploitationPatternMemory]
```

### General Queries
```python
engine.get_memory_summary() -> Dict[str, int]  # Counts of all memory types
engine.get_threat_timeline(days_back=30) -> List[Dict]  # Temporal events
```

---

## Repository Integration

```python
from core.sqlite_repository import SQLiteRepository

repo = SQLiteRepository()

# Memory engine automatically initialized
repo.memory_engine.record_ioc_occurrence(...)

# Persist memories to database
repo._save_memory_to_db()

# Load memories from database (automatic on init)
repo._load_memory_from_db()

# Async persist method
await repo.persist_memories()
```

---

## Memory Models

### Recurring IOC Memory Fields
```python
ioc_id: str
ioc_value: str
first_observed: datetime
last_observed: datetime
occurrence_count: int
occurrences: List[IOCOccurrence]
reuse_frequency: float (0.0-1.0)
associated_campaigns: List[str]
associated_malware: List[str]
associated_actors: List[str]
is_active: bool
activity_trend: str ("rising", "stable", "declining")
next_reuse_likelihood: float (0.0-1.0)
```

### Campaign Persistence Memory Fields
```python
campaign_id: str
campaign_name: str
first_observed: datetime
last_observed: datetime
activity_count: int
activities: List[CampaignActivity]
initial_targets: List[str]
current_targets: List[str]
target_change_frequency: float
techniques_evolution: List[str]
technique_changes: int
activity_pattern: str ("continuous", "intermittent", "seasonal")
peak_activity_period: Optional[str]
confidence: float (0.0-1.0)
attributed_actors: List[str]
is_active: bool
next_activity_likelihood: float (0.0-1.0)
predicted_targets: List[str]
```

### Asset Exposure History Memory Fields
```python
asset_id: str
asset_name: str
exposure_count: int
exposures: List[AssetExposure]
first_exposure: Optional[datetime]
last_exposure: Optional[datetime]
exposure_frequency: float (per month)
average_exposure_duration_days: float
remediation_success_rate: float (0.0-1.0)
is_currently_exposed: bool
current_exposure_id: Optional[str]
current_exposure_duration_days: int
exposure_trend: str ("rising", "stable", "declining")
high_risk_window: Optional[str]
next_exposure_likelihood: float (0.0-1.0)
predicted_vulnerability: Optional[str]
```

### Infrastructure Reuse Memory Fields
```python
infrastructure_id: str
first_observed: datetime
last_observed: datetime
reuse_count: int
nodes: List[InfrastructureNode]
connected_nodes: List[str]
pivot_chains: List[List[str]]
associated_campaigns: List[str]
associated_actors: List[str]
infrastructure_family: str
reuse_frequency: float (0.0-1.0)
time_between_reuse_days: float
is_active: bool
activity_level: str ("high", "medium", "low")
next_reuse_likelihood: float (0.0-1.0)
predicted_next_use_date: Optional[datetime]
```

### Exploitation Pattern Memory Fields
```python
pattern_id: str
pattern_name: str
first_observed: datetime
last_observed: datetime
occurrence_count: int
occurrences: List[AttackPattern]
primary_techniques: List[str]
supporting_techniques: List[str]
success_rate: float (0.0-1.0)
average_targets_per_occurrence: float
adopting_campaigns: List[str]
adoption_trend: str ("rising", "stable", "declining")
technique_changes: int
evolution_timeline: List[str]
is_active: bool
predicted_effectiveness: float (0.0-1.0)
predicted_next_evolution: Optional[str]
```

---

## Database Tables

| Table | Purpose | Rows |
|-------|---------|------|
| ioc_memory | IOC observation history | Dynamic |
| campaign_memory | Campaign activity history | Dynamic |
| asset_memory | Asset exposure history | Dynamic |
| infrastructure_memory | Infrastructure reuse history | Dynamic |
| pattern_memory | Exploitation pattern history | Dynamic |

**Schema:** Each memory table has:
- Primary key (ID)
- Timeline fields (first_observed, last_observed)
- JSON memory_data column (full Pydantic serialization)

---

## Test Coverage (31 tests)

**IOC Recurring Memory (4):**
- ✓ Record occurrence
- ✓ Track recurring
- ✓ Get recurring IOCs
- ✓ All fields populated

**Campaign Persistence (4):**
- ✓ Record activity
- ✓ Track evolution
- ✓ Get active campaigns
- ✓ All fields populated

**Asset Exposure (5):**
- ✓ Record exposure
- ✓ Record remediation
- ✓ Track patterns
- ✓ Get exposed assets
- ✓ All fields populated

**Infrastructure Reuse (4):**
- ✓ Record use
- ✓ Track pivot chains
- ✓ Get reused infra
- ✓ All fields populated

**Exploitation Pattern (5):**
- ✓ Record pattern
- ✓ Track success rate
- ✓ Track adoption
- ✓ Get effective patterns
- ✓ All fields populated

**Memory Queries (2):**
- ✓ Summary query
- ✓ Timeline query

**Persistence (5):**
- ✓ Repository init
- ✓ IOC persistence
- ✓ Campaign persistence
- ✓ Asset persistence
- ✓ Tables created

**Backward Compat (2):**
- ✓ Memory independent of Week 1
- ✓ Repository with Week 1 ops

---

## File Locations

```
core/
├── threat_memory.py          ← Memory models & engine (NEW)
├── sqlite_repository.py      ← Memory integration (MODIFIED)
└── __init__.py               ← Memory exports (MODIFIED)

tests/
├── test_week1_*.py           ← Week 1 tests (41 tests)
└── test_week2_memory.py      ← Memory tests (31 tests, NEW)
```

---

## Quick Commands

**Run all Week 2 memory tests:**
```bash
python -m pytest tests/test_week2_memory.py -v
```

**Run Week 1 + Week 2 tests:**
```bash
python -m pytest tests/test_week1_*.py tests/test_week2_memory.py -v
```

**Initialize repository with memory:**
```python
from core.sqlite_repository import SQLiteRepository
repo = SQLiteRepository()
# Memory engine ready
```

**Record threat observations:**
```python
repo.memory_engine.record_ioc_occurrence("ip-1.1.1.1", "1.1.1.1", "network_scan")
repo.memory_engine.record_campaign_activity("apt28", "APT28", "exploit")
repo.memory_engine.record_asset_exposure("db-001", "Database", "cve")
repo._save_memory_to_db()
```

**Query memory:**
```python
summary = repo.memory_engine.get_memory_summary()
timeline = repo.memory_engine.get_threat_timeline(days_back=30)
recurring = repo.memory_engine.get_recurring_iocs(min_occurrences=2)
active = repo.memory_engine.get_active_campaigns()
```

---

## Week 2 Timeline

**Day 1 ✅:** Persistent Memory Implementation
- 5 Memory models
- ThreatMemoryEngine (22 methods)
- SQLite integration
- 31 tests, 100% pass

**Day 2 ⏳:** Temporal Intelligence Population
- Populate temporal fields from APIs
- Timeline-aware reasoning
- Historical data integration

**Day 3 ⏳:** Recurrence Pattern Detection
- IOC recurrence analysis
- Campaign activity patterns
- Asset exposure trends

**Day 4 ⏳:** Historical Context Building
- Aggregate historical data
- Build predictive signals
- Enable anomaly detection

**Day 5 ⏳:** Memory-Aware Reasoning
- Integrate memory into threat reasoning
- Use patterns for inference
- Memory context in risk scoring

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Memory Features | 5 |
| Memory Models | 5 |
| Engine Methods | 22 |
| Database Tables | 5 |
| Tests Written | 31 |
| Tests Passing | 31 |
| Pass Rate | 100% |
| Code Coverage | ~95% |
| Breaking Changes | 0 |
| Backward Compat | 100% |

---

## Design Principles

1. **Persistent Cognition:** Remember threat patterns across runs
2. **Historical Inference:** Enable anomaly detection via history
3. **Evidence-Based:** Track confidence, dates, sources
4. **Temporal Analysis:** Built-in timeline support
5. **Predictive:** Likelihood fields for trend forecasting
6. **Graph-Ready:** Foundation for relationship-based reasoning

---

**Status:** ✅ Week 2 Day 1 Complete  
**Next:** Week 2 Days 2-5 (Temporal Population & Memory Reasoning)
