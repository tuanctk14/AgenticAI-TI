# Week 1 Quick Reference Guide

**Duration:** 5 days (17-05-2026)  
**Status:** ✅ Complete  
**Tests:** 41/41 PASSED

---

## Files Modified

### core/threat_schema.py
- Added 6 new RelationshipType values (dòng 38-57)
- Added RelationshipMetadata model (dòng 62-104)
- Added 5 temporal fields to Vulnerability (dòng 207-214)
- Added 3 recurrence fields to IOC (dòng 222-224)
- Added 7 contextual fields to RiskContext (dòng 176-183)
- Added 3 lightweight entities: Campaign, ThreatActor, Infrastructure (dòng 407-521)

### core/__init__.py
- Added exports: RelationshipMetadata, Campaign, ThreatActor, Infrastructure

### core/sqlite_repository.py
- Imported MigrationManager
- Added _apply_migrations() method
- Called migrations in __init__

---

## Files Created

### core/relationship_builders.py
- RelationshipBuilder base class (abstract)
- 14 relationship builders with async build() pattern
- Factory method: create_relationship()
- ~650 LOC

### core/migrations/__init__.py
- Package initialization

### core/migrations/migration_001.py
- Temporal + relationships migration
- 7 migration steps (add columns, create tables, indexes)
- Upgrade/downgrade functions
- ~250 LOC

### core/migrations/manager.py
- MigrationManager class
- Discovery, apply, rollback functions
- Version tracking
- ~150 LOC

### tests/test_week1_relationships.py
- 26 tests for relationships
- Temporal fields, entities, builders
- Backward compatibility tests
- ~500 LOC

### tests/test_week1_migrations.py
- 15 tests for migrations
- SQLiteRepository integration
- Schema integrity validation
- ~400 LOC

---

## 16 Relationship Types

**Core (10):**
1. VULNERABLE_TO - Asset → CVE
2. LINKED_TO - IOC ↔ Malware
3. EXPLOITS - CVE → Asset capability
4. COMMUNICATES_WITH - Infrastructure ↔ Infrastructure
5. MAPPED_TO - CVE → CWE/ATT&CK
6. DETECTED_ON - IOC → Asset
7. REACHABLE_TO - Asset → Asset (network path)
8. EXPOSED_TO - Asset → Exposure type
9. USES - Entity → Tool/Software
10. OBSERVED_IN - IOC → Campaign

**New (6):**
11. USES_MALWARE - Campaign → Malware
12. LEADS_CAMPAIGN - ThreatActor → Campaign
13. OPERATES_INFRASTRUCTURE - ThreatActor → Infrastructure
14. TARGETS_SECTOR - Campaign → Sector
15. TARGETS_VICTIMOLOGY - Campaign → Victim type
16. FACES_EXPOSURE - Asset → Internet exposure

---

## Temporal Fields

**Vulnerability (5):**
- published_date (existing, used)
- kev_added_date (new)
- poc_published_date (new)
- exploit_evolution (new)
- first_seen_in_wild (new)
- last_exploited (new)

**IOC (3):**
- first_seen (existing, used)
- last_seen (existing, used)
- active_window (new)
- recurrence_count (new)
- recurrence_history (new)

**RiskContext (7):**
- attack_path_length (new)
- campaign_active (new)
- campaign_name (new)
- malware_family (new)
- threat_actor (new)
- historical_recurrence (new)
- exploitation_confidence (new)

---

## 14 Relationship Builders

1. CVEToMalwareBuilder
2. CVEToCampaignBuilder
3. CVEToThreatActorBuilder
4. CVEToATTACKBuilder
5. MalwareToCampaignBuilder
6. ThreatActorToCampaignBuilder
7. ThreatActorToInfraBuilder
8. InfraToC2Builder
9. CampaignToVictimologyBuilder
10. CampaignToSectorBuilder
11. AssetToAttackPathBuilder
12. AssetToReachabilityBuilder
13. IOCToMalwareBuilder
14. IOCToCampaignBuilder

**Pattern:**
```python
async def build(source_entity, target_entity) -> Optional[Relationship]:
    if not valid: return None
    return self.create_relationship(...)
```

---

## Test Coverage

**Relationship Tests (26):**
- 16 relationship types ✓
- RelationshipMetadata ✓
- Temporal fields ✓
- Contextual risk ✓
- Lightweight entities ✓
- Builders (5+) ✓
- Backward compat ✓
- Confidence scoring ✓
- Integration ✓

**Migration Tests (15):**
- MigrationManager ✓
- SQLiteRepository ✓
- Schema creation ✓
- Backward compat ✓
- Table schemas ✓

**Total:** 41 tests, 100% pass rate

---

## Quick Commands

**Run all tests:**
```bash
python -m pytest tests/test_week1_*.py -v
```

**Run relationship tests:**
```bash
python -m pytest tests/test_week1_relationships.py -v
```

**Run migration tests:**
```bash
python -m pytest tests/test_week1_migrations.py -v
```

**Verify schema:**
```bash
python -c "from core.threat_schema import RelationshipType; print(len(list(RelationshipType)))"
# Output: 16
```

**Initialize repository (applies migrations):**
```python
from core.sqlite_repository import SQLiteRepository
repo = SQLiteRepository()
```

---

## Breaking Changes

**Count:** 0 ❌

All changes are additive:
- New fields optional with defaults
- New tables created (not modified existing)
- New columns added (not removed existing)
- New methods added (not changed existing)
- Old code still works

---

## Next Week (Week 2)

**Focus:** Persistent Threat Memory

**Tasks:**
1. Implement memory engine
2. Populate temporal data
3. Track recurrence patterns
4. Build historical context
5. Enable memory-aware reasoning

**Dependencies:** ✅ All complete

---

## Key Files for Reference

- threat_schema.py - Data models
- relationship_builders.py - Relationship building logic
- migrations/migration_001.py - Schema changes
- migrations/manager.py - Migration system
- tests/test_week1_*.py - Test examples

---

## Documentation Index

| Doc | Content |
|-----|---------|
| WEEK1_DAY1_COMPLETION.md | Day 1 deliverables |
| WEEK1_DAY2_COMPLETION.md | Day 2 deliverables |
| WEEK1_DAY3_COMPLETION.md | Day 3 deliverables |
| WEEK1_DAY4_COMPLETION.md | Day 4 deliverables |
| WEEK1_DAY5_COMPLETION.md | Day 5 deliverables |
| WEEK1_FINAL_SUMMARY.md | Complete summary |
| WEEK1_QUICK_REFERENCE.md | This file |

---

**Status:** ✅ WEEK 1 COMPLETE  
**Quality:** Production-Ready  
**Next:** Week 2 - Persistent Memory
