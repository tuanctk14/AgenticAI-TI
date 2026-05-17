# ATI System Upgrade Roadmap - Incremental Intelligence Enhancement

**Ngày:** 17-05-2026  
**Mục Tiêu:** Chuyển từ "Agent + Enrichment" → "AI-driven Threat Knowledge Intelligence"  
**Chiến Lược:** Incremental, Reasoning-Centric, Graph-Native

---

## Tóm Tắt Kế Hoạch

**Không:** Redesign, Rewrite architecture, Replace orchestration  
**Có:** Increase intelligence density, relationship intelligence, contextual reasoning, temporal intelligence, persistent memory

### Current State
- ✅ LangGraph + Supervisor + Specialist Agents
- ✅ Dynamic tool selection + Runtime reasoning
- ✅ Threat enrichment pipeline (NVD, EPSS, KEV, Vulners, OpenCTI)
- ✅ Canonical schema + Repository abstraction
- ✅ Threat fusion + Correlation engine
- ✅ Graph analyzer + Intelligence layer
- ✅ Menu system (4 menus operational)

### Target State
- Strong Architecture (hiện tại)
- **Strong Knowledge Intelligence** (cần upgrade)

---

## Implementation Priorities (Incremental Order)

### **PRIORITY #1: RELATIONSHIP EXPANSION LAYER** ⭐ MOST IMPORTANT

**Scope:** 10-15 medium-depth relationships (NOT full ontology)

**Required Relationships:**
```
CVE → Malware              (used_by, linked_to)
CVE → Campaign             (exploited_in, affected_by)
CVE → ThreatActor          (attributed_to)
CVE → ATT&CK              (mapped_to)

Malware → Campaign         (used_in)
ThreatActor → Campaign     (leads, executes)
ThreatActor → Infrastructure (operates)
Infrastructure → C2        (connects_to)

Campaign → Victimology     (targets)
Campaign → Sector          (targets_sector)

Asset → AttackPath         (vulnerable_via)
Asset → Reachability       (reachable_via)

IOC → Malware              (associated_with)
IOC → Campaign             (observed_in)
```

**Design Principle:**
- Relationship-centric, NOT entity-centric
- Each relationship has: confidence, evidence, temporal data
- Enable graph traversal for threat correlation

**Implementation Location:**
- core/threat_schema.py: Add relationship models
- core/threat_correlation.py: Add 14 relationship builders
- agents/: Update agent reasoning to use relationships

**Dependencies:** None (can start immediately)

---

### **PRIORITY #2: TEMPORAL INTELLIGENCE LAYER**

**Scope:** Basic timeline tracking (first_seen, last_seen, active_window)

**Required Fields:**
```
Vulnerability:
  - published_date (from NVD)
  - poc_released_date
  - kev_added_date
  - exploit_first_seen

IOC:
  - first_seen
  - last_seen
  - active_window

Campaign:
  - start_date
  - end_date
  - activity_timeline

Asset:
  - exposure_start
  - exposure_end
  - vulnerability_window
```

**Timeline Flow Example:**
```
CVE-2024-1086 published → 2024-01-31
  ↓
PoC released → 2024-02-01
  ↓
EPSS spike detected → 2024-02-02
  ↓
Campaign observed → 2024-02-03
  ↓
IOC detected in environment → 2024-02-04
  ↓
Asset exposure detected → 2024-02-05
  ↓
Attack path identified → 2024-02-06
```

**Implementation Location:**
- core/threat_schema.py: Add temporal fields to entities
- tools/enrichment: Fetch temporal data from OpenCTI, NVD
- agents/: Temporal-aware reasoning

**Dependencies:** Requires Priority #1 (relationships established)

---

### **PRIORITY #3: PERSISTENT THREAT MEMORY**

**Scope:** 4 core memory features

**Required Memory Capabilities:**

1. **Recurring IOC Memory**
   - Track IOC occurrences across time
   - Detect reused indicators
   - Build IOC recurrence patterns

2. **Campaign Persistence**
   - Historical campaign activities
   - Campaign evolution tracking
   - Recurring campaign patterns

3. **Asset Exposure History**
   - Asset vulnerability timeline
   - Exposure patterns
   - Historical remediation

4. **Exploitation Pattern Memory**
   - Recurring attack patterns
   - Malware behavior history
   - Attack technique evolution

**Implementation Location:**
- core/threat_memory.py: NEW - Persistent memory engine
- core/sqlite_repository.py: Add memory storage
- agents/: Query historical patterns for reasoning

**Dependencies:** Requires Priority #2 (temporal data in place)

---

### **PRIORITY #4: OPENCTI DEEP ENRICHMENT**

**Scope:** B+ level (Campaign + Malware lineage + ATT&CK expansion)

**Current State:** IOC retrieval only

**Upgrade Into:**

1. **Campaign Enrichment**
   - Campaign → ThreatActor relationships
   - Campaign → Victimology (targets)
   - Campaign → Sectors
   - Campaign timeline

2. **Malware Lineage**
   - Parent/child malware relationships
   - Malware family evolution
   - Variant tracking

3. **Light ATT&CK Expansion**
   - Malware → ATT&CK mapping
   - Campaign → ATT&CK tactics
   - Technique evolution

**Implementation Location:**
- tools/providers/opencti_provider.py: Expand queries
- core/threat_correlation.py: Build relationships from OpenCTI data
- core/threat_enrichment_pipeline.py: Integrate OpenCTI enrichment

**Dependencies:** Requires Priority #1 (relationships), Priority #2 (temporal)

---

### **PRIORITY #5: CONTEXTUAL THREAT REASONING**

**Scope:** Medium-high complexity (7 factors)

**Core Factors:**
```
1. EPSS score (exploitation probability)
2. KEV listed (known exploited)
3. Internet exposure (asset internet-facing)
4. Asset criticality (business importance)
5. Attack path existence (reachability)
6. Malware association (campaign linkage)
7. Campaign activity (active threats)
```

**Reasoning Example:**
```
IF
  KEV = true
  AND EPSS > 0.90
  AND Internet_Exposed = true
  AND AttackPath_Exists = true
  AND Malware_Ransomware = true
  AND Campaign_Active = true

THEN
  Risk_Priority = CRITICAL
  Action = IMMEDIATE_REMEDIATION
```

**Implementation Location:**
- core/threat_reasoning.py: NEW - Contextual reasoning engine
- agents/base.py: Update agent reasoning output
- core/risk_scoring.py: Semantic fusion for scoring

**Dependencies:** Requires Priority #1 (relationships), #3 (memory), #4 (OpenCTI)

---

### **PRIORITY #6: THREAT SCHEMA ENHANCEMENT**

**Scope:** Enhanced schema (NOT full ontology redesign)

**Required Additions:**

1. **Temporal Fields** (Priority #2)
   ```python
   first_seen: Optional[datetime]
   last_seen: Optional[datetime]
   active_window: Optional[str]
   ```

2. **Relationship Expansion** (Priority #1)
   ```python
   relationships: List[Relationship]  # Already have, expand usage
   relationship_context: Dict  # Confidence, evidence
   ```

3. **Lightweight Campaign Entity**
   ```python
   class Campaign(BaseModel):
     id: str
     name: str
     threat_actors: List[str]
     victimology: List[str]
     sectors: List[str]
     timeline: Dict
   ```

4. **Lightweight ThreatActor Entity**
   ```python
   class ThreatActor(BaseModel):
     id: str
     aliases: List[str]
     campaigns: List[str]
     techniques: List[str]
     infrastructure: List[str]
   ```

5. **Contextual Risk Fields**
   ```python
   attack_path_exists: bool
   attack_path_length: Optional[int]
   campaign_active: bool
   campaign_name: Optional[str]
   malware_family: Optional[str]
   ```

**Design Principle:** Reasoning-centric, NOT API-centric

**Implementation Location:**
- core/threat_schema.py: Add new entities + fields
- core/threat_repository.py: Update storage methods
- Migrations: SQLite schema updates

**Dependencies:** Can implement with Priority #1

---

### **PRIORITY #7: GRAPH REASONING DEPTH**

**Scope:** Graph-native threat reasoning (already have graph layer)

**Required Graph Capabilities:**

1. **Multi-hop Traversal**
   ```
   Asset → [VULNERABLE_TO] → CVE → [EXPLOITED_IN] → Campaign → [LED_BY] → ThreatActor
   ```

2. **Attack Path Reasoning**
   ```
   Find longest attack paths from internet to critical assets
   Rank by: (CVE severity * EPSS) + (Campaign activity) + (Malware type)
   ```

3. **Campaign Clustering**
   ```
   Identify campaign clusters by shared: victims, TTPs, infrastructure
   Infer: same actor, related campaigns, TTPs evolution
   ```

4. **Recurring IOC Correlation**
   ```
   Track IOC reuse across time
   Detect infrastructure reuse
   Build infrastructure graphs
   ```

5. **Graph-based Threat Scoring**
   ```
   Node centrality: How important is this entity?
   Path density: How vulnerable is this asset?
   Community threat level: Is threat actor active?
   ```

6. **Transitive Reasoning**
   ```
   CVE affects software X
   Asset runs software X
   Campaign uses CVE
   → Asset is likely target
   ```

**Implementation Location:**
- core/threat_graph_analyzer.py: Expand graph algorithms
- core/graph_intelligence_layer.py: Add reasoning methods
- agents/base.py: Integrate graph reasoning into output

**Dependencies:** Requires Priority #1 (relationships), #4 (OpenCTI)

---

### **PRIORITY #8: SEMANTIC THREAT FUSION**

**Scope:** Transform field merging into contextual synthesis

**Bad Approach:**
```json
{
  "epss": 0.97,
  "kev": true,
  "exploit_count": 125
}
```

**Good Approach:**
```
SYNTHESIS:
  high EPSS (0.97)
  + KEV confirmed
  + 125 public exploits
  + ransomware-linked campaign
  + internet-facing assets vulnerable
  + attack paths exist
  
→ INSIGHT: High probability of active exploitation
→ ACTION: Urgent remediation required
```

**Fusion Rules:**
- Combine: severity + exploitability + exposure + criticality + activity
- Infer: threat actor intent, campaign objectives
- Predict: likely next targets, techniques
- Recommend: tactical + strategic actions

**Implementation Location:**
- core/semantic_fusion.py: NEW - Fusion engine
- core/threat_reasoning.py: Semantic reasoning
- agents/base.py: Output synthesis

**Dependencies:** Requires Priority #5 (reasoning)

---

## Implementation Timeline

```
Phase 1 (Week 1-2):
  → Priority #1: Relationship Expansion
  → Priority #6: Schema Enhancement
  
Phase 2 (Week 2-3):
  → Priority #2: Temporal Intelligence
  → Priority #3: Persistent Memory
  
Phase 3 (Week 3-4):
  → Priority #4: OpenCTI Deep Enrichment
  → Priority #5: Contextual Reasoning
  
Phase 4 (Week 4-5):
  → Priority #7: Graph Reasoning Depth
  → Priority #8: Semantic Fusion
```

---

## Files to Create/Modify

### New Files
- `core/threat_memory.py` - Persistent memory engine
- `core/threat_reasoning.py` - Contextual reasoning
- `core/semantic_fusion.py` - Semantic fusion engine
- `core/relationship_builders.py` - 14 relationship builders

### Modified Files
- `core/threat_schema.py` - Add temporal fields, new entities, relationships
- `core/threat_correlation.py` - Extend relationship building
- `core/threat_enrichment_pipeline.py` - Integrate temporal + memory
- `core/threat_graph_analyzer.py` - Enhance graph reasoning
- `core/graph_intelligence_layer.py` - Graph-native reasoning
- `core/sqlite_repository.py` - Schema migrations
- `tools/providers/opencti_provider.py` - Deep enrichment queries
- `agents/base.py` - Update reasoning output
- `main.py` - Integrate new features into menu output

---

## Key Design Principles

### ✅ DO
- **Reasoning-centric**: Design around threat analysis, NOT API structure
- **Incremental**: Each priority builds on previous ones
- **Non-destructive**: Enhance existing architecture, don't replace
- **Persistent**: Data persists across runs
- **Graph-native**: Leverage relationship intelligence
- **Contextual**: Combine signals for semantic understanding
- **Temporal**: Timeline-aware reasoning

### ❌ DON'T
- **API-centric**: Don't design around API fields
- **Ontology explosion**: Don't implement full entity model yet
- **Massive ingestion**: Don't fetch all data, fetch high-value only
- **Monolithic redesign**: Don't rewrite existing systems
- **Duplicate logic**: Don't recreate existing reasoning
- **Schema drift**: Don't add random fields

---

## Success Metrics

| Metric | Before | After |
|--------|--------|-------|
| Relationships per CVE | 1-2 | 5-7 |
| Temporal context | None | Published → Exploited → Active |
| Memory persistence | No | Yes (IOC, Campaign, Asset history) |
| Reasoning factors | 2-3 | 7+ |
| Graph traversal depth | 1-hop | 3-5 hops |
| Semantic understanding | Field aggregation | Contextual synthesis |

---

## Questions for Confirmation

1. **Relationship Scope:** 10-15 relationships (Priority #1) - Confirm?
2. **Temporal Depth:** Basic timeline (Priority #2) - Confirm?
3. **Memory Features:** 4 core features (Priority #3) - Confirm?
4. **OpenCTI Scope:** B+ level (Priority #4) - Confirm?
5. **Reasoning Complexity:** 7 factors (Priority #5) - Confirm?
6. **Schema Approach:** Enhanced, NOT full redesign (Priority #6) - Confirm?
7. **Graph Capability:** Multi-hop + clustering (Priority #7) - Confirm?
8. **Fusion Style:** Semantic synthesis, NOT field merge (Priority #8) - Confirm?

---

**Status:** Ready for implementation  
**Architecture Impact:** Minimal - Incremental enhancement  
**Breaking Changes:** None - All backward compatible
