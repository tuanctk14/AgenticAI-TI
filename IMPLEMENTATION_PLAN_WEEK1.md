# Week 1 Implementation Plan - Relationship & Schema Foundation

**Tuần:** Week 1 (5 ngày làm việc)  
**Priorities:** #1 (Relationship Expansion) + #6 (Schema Enhancement)  
**Mục Tiêu:** Relationship intelligence foundation + Schema upgrade  
**Kết Quả:** 16 relationships + Enhanced schema, ZERO breaking changes

---

## Day-by-Day Breakdown

### **Day 1: Relationship Expansion - Design & Schema**

#### Task 1.1: Analyze Current Relationship Model
- Read `core/threat_schema.py` - RelationshipType enum
- Current relationships: 10 types
- Plan: Add 6 new relationship types
- Time: 30 min

#### Task 1.2: Design 16 Relationship Types
```python
# Current (10):
VULNERABLE_TO = "vulnerable_to"
LINKED_TO = "linked_to"
EXPLOITS = "exploits"
COMMUNICATES_WITH = "communicates_with"
MAPPED_TO = "mapped_to"
DETECTED_ON = "detected_on"
REACHABLE_TO = "reachable_to"
EXPOSED_TO = "exposed_to"
USES = "uses"
OBSERVED_IN = "observed_in"

# New (6):
USES_MALWARE = "uses_malware"           # Campaign → Malware
LEADS_CAMPAIGN = "leads_campaign"       # ThreatActor → Campaign
OPERATES_INFRASTRUCTURE = "operates_infrastructure"  # ThreatActor → Infrastructure
TARGETS_SECTOR = "targets_sector"       # Campaign → Sector
TARGETS_VICTIMOLOGY = "targets_victimology"  # Campaign → Victimology
FACES_EXPOSURE = "faces_exposure"       # Asset → InternetExposure
```

**Time:** 1 hour

#### Task 1.3: Create Relationship Metadata Model
```python
class RelationshipMetadata(BaseModel):
    """Metadata cho mỗi relationship."""
    confidence: float              # 0-1, từ evidence
    evidence: List[str]            # ["cpe_match", "campaign_link", etc]
    first_observed: Optional[datetime]
    last_observed: Optional[datetime]
    active: bool = True
    source: str                    # "nvd", "opencti", "correlator"
    reasoning: Optional[str]       # Tại sao relationship này tồn tại
```

**Time:** 30 min

#### Task 1.4: Update RelationshipType Enum
- Add 6 new relationship types
- Update `core/threat_schema.py`
- Add relationship metadata structure
- Backward compatible (old relationships still work)

**Time:** 1 hour

**Deliverable:** Updated threat_schema.py with 16 relationship types + metadata

---

### **Day 2: Schema Enhancement - Temporal & Entity Fields**

#### Task 2.1: Add Temporal Fields to Vulnerability
```python
class Vulnerability(BaseModel):
    # Existing fields...
    
    # NEW: Temporal Intelligence
    published_date: Optional[datetime]      # NVD published
    kev_added_date: Optional[datetime]      # CISA KEV date
    poc_published_date: Optional[datetime]  # PoC released
    exploit_evolution: Optional[Dict]       # Timeline of exploit availability
    first_seen_in_wild: Optional[datetime]
    last_exploited: Optional[datetime]
```

**Time:** 1 hour

#### Task 2.2: Add Temporal Fields to IOC
```python
class IOC(BaseModel):
    # Existing fields...
    
    # NEW: Temporal Intelligence
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    active_window: Optional[str]            # "2024-01 to 2026-05"
    recurrence_count: int = 0               # Bao nhiêu lần thấy
    recurrence_history: List[Dict] = []     # Timeline of occurrences
```

**Time:** 45 min

#### Task 2.3: Create Lightweight Campaign Entity
```python
class Campaign(BaseModel):
    """Lightweight campaign entity cho relationship intelligence."""
    id: str                            # OpenCTI ID
    name: str                          # Campaign name
    aliases: List[str] = []            # Tên khác
    threat_actors: List[str] = []      # Attributed actors
    description: Optional[str]
    
    # Temporal
    start_date: Optional[datetime]
    end_date: Optional[datetime]
    active: bool = True
    
    # Intelligence
    victimology: List[str] = []        # Loại mục tiêu
    sectors: List[str] = []            # Ngành công nghiệp
    techniques: List[str] = []         # ATT&CK techniques
    malware: List[str] = []            # Associated malware
    
    # Context
    severity: SeverityLevel = SeverityLevel.UNKNOWN
    confidence: float = 0.0            # Attribution confidence
```

**Time:** 1.5 hours

#### Task 2.4: Create Lightweight ThreatActor Entity
```python
class ThreatActor(BaseModel):
    """Lightweight threat actor entity."""
    id: str                            # OpenCTI ID
    name: str
    aliases: List[str] = []
    description: Optional[str]
    
    # Links
    campaigns: List[str] = []          # Campaign IDs
    malware_used: List[str] = []       # Malware families
    infrastructure: List[str] = []     # Infrastructure node IDs
    
    # Intelligence
    techniques: List[str] = []         # MITRE ATT&CK
    target_sectors: List[str] = []
    
    # Activity
    active: bool = True
    last_seen: Optional[datetime]
    activity_level: str = "unknown"    # low, medium, high, critical
```

**Time:** 1 hour

#### Task 2.5: Create Lightweight Infrastructure Entity
```python
class Infrastructure(BaseModel):
    """Lightweight infrastructure node."""
    id: str                            # Unique ID
    node_type: str                     # "ip", "domain", "c2", "proxy"
    value: str                         # IP/domain value
    
    # Links
    c2_connections: List[str] = []     # Connected C2 nodes
    malware: List[str] = []            # Malware families using it
    campaigns: List[str] = []          # Campaigns using it
    threat_actors: List[str] = []
    
    # Temporal
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    active: bool = True
    
    # Intelligence
    severity: SeverityLevel = SeverityLevel.UNKNOWN
    confidence: float = 0.0
```

**Time:** 1 hour

#### Task 2.6: Enhance RiskContext with Contextual Fields
```python
class RiskContext(BaseModel):
    # Existing fields...
    
    # NEW: Contextual Intelligence Fields
    attack_path_exists: bool = False        # Từ graph analysis
    attack_path_length: Optional[int]       # Hops to asset
    campaign_active: bool = False           # Campaign đang hoạt động
    campaign_name: Optional[str]            # Campaign name
    malware_family: Optional[str]           # Associated malware
    threat_actor: Optional[str]             # Attributed actor
    
    # Reasoning context
    historical_recurrence: float = 0.0      # % lần xuất hiện
    lateral_movement_potential: bool = False
    exploitation_confidence: float = 0.0    # 0-1
```

**Time:** 1 hour

**Deliverable:** Enhanced threat_schema.py with temporal + entity + contextual fields

---

### **Day 3: Create Relationship Builders**

#### Task 3.1: Create RelationshipBuilder Base Class
```python
# File: core/relationship_builders.py

class RelationshipBuilder(ABC):
    """Base class cho tất cả relationship builders."""
    
    @abstractmethod
    async def build(self, source_entity, target_entity) -> Optional[Relationship]:
        """Build relationship from entities."""
        pass
    
    def create_relationship(
        self,
        source_id: str,
        source_type: EntityType,
        target_id: str,
        target_type: EntityType,
        rel_type: RelationshipType,
        confidence: float,
        evidence: List[str],
        metadata: Dict = None
    ) -> Relationship:
        """Factory method for relationship creation."""
        return Relationship(
            source_id=source_id,
            source_type=source_type,
            target_id=target_id,
            target_type=target_type,
            relationship_type=rel_type,
            confidence=confidence,
            evidence_sources=evidence,
            metadata=metadata or {}
        )
```

**Time:** 1 hour

#### Task 3.2: Implement 14 Relationship Builders

```python
1. CVEToMalwareBuilder           # CVE → Malware (from OpenCTI)
2. CVEToCampaignBuilder          # CVE → Campaign (from OpenCTI)
3. CVEToThreatActorBuilder       # CVE → ThreatActor (inferred)
4. CVEToATTACKBuilder            # CVE → ATT&CK (from CWE mapping)
5. MalwareToCampaignBuilder      # Malware → Campaign (from OpenCTI)
6. ThreatActorToCampaignBuilder  # ThreatActor → Campaign (from OpenCTI)
7. ThreatActorToInfraBuilder     # ThreatActor → Infrastructure (from OpenCTI)
8. InfraToC2Builder              # Infrastructure → C2 (graph traversal)
9. CampaignToVictimologyBuilder  # Campaign → Victimology (from OpenCTI)
10. CampaignToSectorBuilder      # Campaign → Sector (from OpenCTI)
11. AssetToAttackPathBuilder     # Asset → AttackPath (graph analysis)
12. AssetToReachabilityBuilder   # Asset → Reachability (network analysis)
13. IOCToMalwareBuilder          # IOC → Malware (correlation)
14. IOCToCampaignBuilder         # IOC → Campaign (from OpenCTI)
15. AssetToInternetExposureBuilder # NEW
16. CampaignToMalwareBuilder     # NEW
```

Each builder:
- Defines: source type, target type, relationship type
- Implements: async build() method
- Returns: Relationship with confidence + evidence
- Handles: missing data gracefully (returns None if not enough evidence)

**Time:** 4 hours (30 min per builder × 8 complex + 20 min per simple × 6)

**Deliverable:** core/relationship_builders.py with 14 builders + tests

---

### **Day 4: Integrate Schema Changes & Create Migrations**

#### Task 4.1: Create SQLite Schema Migration
```python
# core/migrations/001_temporal_and_relationships.py

def upgrade(repo: SQLiteRepository):
    """Add temporal + relationship fields."""
    # Add temporal columns to vulnerabilities table
    # Add temporal columns to iocs table
    # Create new tables: campaigns, threat_actors, infrastructure
    # Update relationships table schema
    # Create indexes for temporal fields
    pass

def downgrade(repo: SQLiteRepository):
    """Rollback schema changes."""
    pass
```

**Time:** 1.5 hours

#### Task 4.2: Update SQLiteRepository
- Add migration system
- Add methods to save Campaign, ThreatActor, Infrastructure
- Add methods to query relationships by type
- Add methods to update relationship metadata
- Backward compatible (old code still works)

**Time:** 2 hours

#### Task 4.3: Update Neo4jRepository
- Add Campaign, ThreatActor, Infrastructure nodes
- Add 14 relationship types
- Add temporal properties
- Cypher queries for new relationships

**Time:** 1.5 hours

**Deliverable:** Updated repositories with migration support

---

### **Day 5: Integration Testing & Validation**

#### Task 5.1: Create Test Suite
```python
# tests/test_relationships.py

test_cve_to_malware_builder()
test_cve_to_campaign_builder()
test_relationship_metadata()
test_temporal_fields()
test_campaign_entity()
test_threat_actor_entity()
test_infrastructure_entity()
test_schema_backward_compatibility()
test_relationship_persistence()
test_graph_relationship_queries()
```

**Time:** 2 hours

#### Task 5.2: Integration Testing
- Load real CVE data (CVE-2024-1086, CVE-2026-2652)
- Build relationships
- Verify relationship quality (confidence > 0.7)
- Check graph connectivity
- Validate temporal data

**Time:** 1.5 hours

#### Task 5.3: Documentation
- Relationship builder pattern documentation
- Schema migration guide
- Backward compatibility notes
- Graph reasoning guide for next phase

**Time:** 1 hour

#### Task 5.4: Performance Validation
- Relationship building speed (target: < 2s per CVE)
- Graph query performance (multi-hop traversal)
- Memory usage (no explosion)

**Time:** 1 hour

**Deliverable:** Test suite + validation report + documentation

---

## Deliverables by End of Week 1

### Code Changes
✅ `core/threat_schema.py`
  - 16 relationship types (was 10)
  - RelationshipMetadata model
  - Temporal fields (published_date, kev_added_date, poc_published_date, exploit_evolution, first_seen, last_seen, active_window)
  - Campaign, ThreatActor, Infrastructure entities (lightweight)
  - Enhanced RiskContext (attack_path_exists, campaign_active, malware_family, etc)

✅ `core/relationship_builders.py` (NEW)
  - RelationshipBuilder base class
  - 14 relationship builders (CVE→Malware, CVE→Campaign, etc)
  - Relationship factory methods
  - Evidence + confidence handling

✅ `core/sqlite_repository.py`
  - Migration system
  - Campaign storage methods
  - ThreatActor storage methods
  - Infrastructure storage methods
  - Relationship metadata queries

✅ `core/neo4j_repository.py`
  - Campaign nodes + properties
  - ThreatActor nodes + properties
  - Infrastructure nodes + properties
  - 14 relationship types in Cypher
  - Temporal property indexes

✅ `tests/test_relationships.py` (NEW)
  - 10+ relationship builder tests
  - Schema validation tests
  - Backward compatibility tests
  - Graph connectivity tests

✅ `core/migrations/001_temporal_and_relationships.py` (NEW)
  - SQLite schema changes
  - Upgrade/downgrade functions

### Documentation
✅ `UPGRADE_WEEK1_SUMMARY.md` - Week 1 completion summary
✅ `RELATIONSHIP_BUILDERS_GUIDE.md` - How to use builders
✅ `SCHEMA_MIGRATION_GUIDE.md` - Migration instructions

---

## Success Criteria

| Metric | Target | Status |
|--------|--------|--------|
| Relationship types | 16 | To implement |
| Relationship builders | 14 | To implement |
| Schema backward compatibility | 100% | To validate |
| Test coverage | >90% | To achieve |
| Graph relationship density | 5-7 per CVE | To measure |
| Performance | <2s per CVE | To validate |
| Breaking changes | 0 | To maintain |

---

## Risk Mitigation

### Risk 1: Schema Migration Breaking Changes
**Mitigation:** All changes are additive (new columns/tables). Old code still works.

### Risk 2: Relationship Explosion
**Mitigation:** 14 relationships only (not full ontology). Incremental, controlled growth.

### Risk 3: Performance Degradation
**Mitigation:** Monitor builder speed, graph query performance. Create indexes.

### Risk 4: Inconsistent Relationship Quality
**Mitigation:** Each builder validates confidence threshold before creating relationship.

---

## Next Phase Preparation

By end of Week 1:
- ✅ Relationship layer is stable and tested
- ✅ Schema supports temporal intelligence (Week 2)
- ✅ Foundation for persistent memory (Week 2)
- ✅ Ready for OpenCTI deep enrichment (Week 3)

---

## Summary

**Week 1 = Relationship Intelligence Foundation**

- Transform from: 1-2 relationships per entity
- Transform to: 5-7 relationships per entity
- Add: Temporal schema support
- Add: Lightweight entity models
- Add: Relationship builders (reusable pattern)
- Keep: 100% backward compatibility
- Maintain: Incremental, non-breaking implementation

**Output:** Solid foundation for Week 2-5 graph intelligence upgrades.

---

**Status:** Ready to start Day 1  
**Estimated Effort:** 40-50 hours  
**Risk Level:** Low (non-breaking, incremental)  
**Architecture Impact:** Minimal (extends, doesn't change)
