# ATI System Upgrade Strategy - CONFIRMED

**Ngày Phê Duyệt:** 17-05-2026  
**Mục Tiêu:** Transform từ "Agent + Enrichment" → "AI-driven Threat Knowledge Intelligence"  
**Phương Pháp:** Incremental, Reasoning-Centric, Graph-Native  
**Timeline:** 5 weeks, 8 priorities  
**Status:** ✅ CONFIRMED - Ready to start Week 1

---

## Confirmed Implementation Details

### ✅ Priority #1: Relationship Expansion (WEEK 1)

**16 Total Relationships:**

Current (10):
- VULNERABLE_TO, LINKED_TO, EXPLOITS, COMMUNICATES_WITH, MAPPED_TO, DETECTED_ON, REACHABLE_TO, EXPOSED_TO, USES, OBSERVED_IN

New (6):
- USES_MALWARE (Campaign → Malware)
- LEADS_CAMPAIGN (ThreatActor → Campaign)
- OPERATES_INFRASTRUCTURE (ThreatActor → Infrastructure)
- TARGETS_SECTOR (Campaign → Sector)
- TARGETS_VICTIMOLOGY (Campaign → Victimology)
- FACES_EXPOSURE (Asset → InternetExposure)

**Design Principle:**
- Relationship-centric, NOT entity-centric
- Each relationship: confidence, evidence, temporal data
- Enable graph traversal for threat correlation
- Controlled growth (NOT full ontology explosion)

**Deliverable:** core/relationship_builders.py with 14 builders

---

### ✅ Priority #2: Temporal Intelligence (WEEK 2)

**Medium-Depth Timeline:**

Vulnerability:
- published_date, kev_added_date, poc_published_date
- exploit_evolution (timeline of exploit availability)
- first_seen_in_wild, last_exploited

IOC:
- first_seen, last_seen, active_window
- recurrence_count, recurrence_history

Campaign:
- start_date, end_date, activity timeline

Asset:
- exposure_start, exposure_end, vulnerability_window

**NOT included (for later):**
- ransomware lineage evolution (deep)
- infrastructure reuse genealogy (complex)

**Design Principle:**
- Timeline-aware reasoning
- Evidence-based temporal relationships
- Historical pattern detection

---

### ✅ Priority #3: Persistent Threat Memory (WEEK 2)

**5 Memory Features (Priority Order):**

1. **Recurring IOC Memory** - Track IOC occurrences across time, detect reuse
2. **Campaign Persistence** - Historical campaign activities, evolution tracking
3. **Asset Exposure History** - Asset vulnerability timeline, exposure patterns
4. **Infrastructure Reuse History** - Track infrastructure reuse patterns
5. **Exploitation Pattern Memory** - Recurring attack patterns, technique evolution

**Design Principle:**
- Persistent threat cognition across runs
- Enable historical pattern inference
- Foundation for anomaly detection

---

### ✅ Priority #4: OpenCTI Deep Enrichment (WEEK 3)

**B+ Scope (NOT full exploration):**

Implement:
- Campaign relationship expansion (Campaign → ThreatActor, → Victimology, → Sector)
- Malware lineage (parent/child relationships)
- Light ATT&CK expansion (Malware → ATT&CK, Campaign → ATT&CK)
- Threat actor enrichment (light - attributes, aliases, activity)

NOT included (for later):
- Advanced attribution engine
- Infrastructure mega clustering
- Deep behavioral profiling

**Design Principle:**
- Contextual enrichment, NOT ingestion explosion
- Avoid data bloat
- Focus on high-value relationships

---

### ✅ Priority #5: Contextual Threat Reasoning (WEEK 3)

**9 Reasoning Factors:**

Core (7):
1. EPSS - Exploitation probability
2. KEV - Known exploited status
3. Internet exposure - Asset internet-facing
4. Asset criticality - Business importance
5. Attack path existence - Reachability
6. Malware association - Campaign linkage
7. Campaign activity - Active threats

Added (2):
8. Historical recurrence - % previous occurrences
9. Lateral movement potential - Internal spread risk

**Reasoning Example:**
```
IF KEV=true AND EPSS>0.90 AND Internet_Exposed=true 
   AND AttackPath_Exists=true AND Malware_Ransomware=true 
   AND Campaign_Active=true
THEN Risk_Priority=CRITICAL, Action=IMMEDIATE_REMEDIATION
```

**Design Principle:**
- Context-aware prioritization
- Multi-factor decision making
- Semantic understanding (NOT just field aggregation)

---

### ✅ Priority #6: Schema Enhancement (WEEK 1)

**Enhanced Approach (NOT full redesign):**

Add to threat_schema.py:
- Temporal fields (published_date, first_seen, last_seen, etc)
- Lightweight Campaign entity (OpenCTI relations)
- Lightweight ThreatActor entity (actors, techniques, campaigns)
- Lightweight Infrastructure entity (nodes, C2, malware, campaigns)
- Enhanced RiskContext (attack_path_exists, campaign_active, malware_family)
- Relationship metadata (confidence, evidence, source, reasoning)

Keep:
- Backward compatibility (NO breaking changes)
- Existing pipeline (NO disruption)
- Current entity models (just enhance)

**Design Principle:**
- Incremental enhancement
- Reasoning-centric ontology (NOT API-centric)
- Persistent backward compatibility

---

### ✅ Priority #7: Graph Reasoning Depth (WEEK 4)

**8 Graph Capabilities:**

1. Multi-hop traversal - Follow relationship chains
2. Attack path reasoning - Asset → CVE → Campaign chains
3. Campaign clustering - Identify related campaigns
4. Recurring IOC correlation - Detect IOC reuse
5. Graph-based threat scoring - Node centrality, path density
6. Transitive reasoning - Infer indirect relationships
7. Infrastructure reuse inference - Detect infrastructure patterns
8. Attack chain inference - Predict likely next steps

**Design Principle:**
- Graph-native intelligence reasoning
- Enable transitive threat analysis
- Relationship traversal for correlation

---

### ✅ Priority #8: Semantic Threat Fusion (WEEK 4-5)

**Transform Field Merging → Contextual Synthesis:**

Bad (field aggregation):
```json
{"epss": 0.97, "kev": true}
```

Good (semantic synthesis):
```
high EPSS (0.97)
+ KEV-listed
+ ransomware-linked campaign
+ exposed asset
+ reachable attack path
→ extremely high exploitation probability
→ immediate remediation required
```

**Design Principle:**
- Contextual intelligence synthesis
- Multi-signal semantic understanding
- AI-driven threat reasoning

---

## Timeline - 5 Weeks

```
WEEK 1: Relationship Expansion + Schema Enhancement
  └─ Days 1-5: Build 14 relationship builders + enhance schema
  └─ Output: Relationship intelligence foundation

WEEK 2: Temporal Intelligence + Persistent Memory
  └─ Days 6-10: Add temporal fields + memory system
  └─ Output: Timeline-aware reasoning + persistent context

WEEK 3: OpenCTI Deep Enrichment + Contextual Reasoning
  └─ Days 11-15: Deep OpenCTI integration + 9-factor reasoning
  └─ Output: Contextual threat prioritization

WEEK 4: Graph Reasoning + Semantic Fusion
  └─ Days 16-20: Graph algorithms + semantic synthesis
  └─ Output: Graph-native AI reasoning

WEEK 5: Optimization + Stabilization
  └─ Days 21-25: Performance tuning, testing, validation
  └─ Output: Production-ready AI-driven CTI platform
```

---

## Implementation Constraints (CRITICAL)

### ❌ DO NOT
- Redesign whole system
- Rewrite orchestration (LangGraph is fine)
- Replace current pipeline
- Add massive APIs
- Implement full ontology yet
- Create feature explosion
- Break backward compatibility
- Parallel implementations (wait for dependencies)

### ✅ DO
- Enhance incrementally
- Respect dependency chains
- Validate at each stage
- Keep reasoning-centric
- Maintain graph stability
- Test relationship quality
- Document everything
- Validate performance

---

## Critical Design Principles

### 1. Reasoning-Centric (NOT API-Centric)
```
WRONG:
  Schema mirrors API fields
  ("epss_score": 0.97)

RIGHT:
  Schema enables reasoning
  ("risk_context": {"epss": 0.97, "kev": true, "campaign_active": true})
```

### 2. Relationship Intelligence (NOT Entity Storage)
```
WRONG:
  Store entities independently
  Query: "Get CVE by ID"

RIGHT:
  Store relationships densely
  Query: "Find CVEs → Campaign → ThreatActor"
```

### 3. Incremental (NOT All-at-Once)
```
WRONG:
  Implement all 8 priorities in parallel
  Risk: schema drift, ontology conflicts

RIGHT:
  Week 1 → Week 2 → Week 3 → Week 4 → Week 5
  Each phase validated before next
```

### 4. Persistent Memory (NOT Session State)
```
WRONG:
  Forget relationships after run
  Re-discover same patterns each time

RIGHT:
  Remember recurring IOCs, campaigns, patterns
  Build knowledge across runs
```

### 5. Graph-Native (NOT Flat Queries)
```
WRONG:
  JOIN tables, aggregate fields
  Simple field searches

RIGHT:
  Graph traversal, multi-hop reasoning
  Native relationship queries
```

---

## Success Metrics

| Metric | Before | After | Target |
|--------|--------|-------|--------|
| Relationships per CVE | 1-2 | 5-7 | 5-7 |
| Temporal context | None | Timeline-aware | Full timeline |
| Memory persistence | No | Yes | Recurring patterns |
| Reasoning factors | 2-3 | 9 | 9+ |
| Graph depth | 1-hop | 3-5 hops | 3-5 hops |
| Semantic quality | Field merge | Context synthesis | High |
| Performance | Baseline | <2s per CVE | <2s |
| Breaking changes | N/A | 0 | 0 |

---

## Risk Management

### Low Risk (Well-Understood)
✅ Relationship builders - Pattern is clear
✅ Schema enhancement - All additive
✅ Temporal fields - Straightforward
✅ Database migrations - Standard process

### Medium Risk (Validation Needed)
⚠️ Graph performance - Needs monitoring
⚠️ Relationship density - Quality assurance required
⚠️ Memory persistence - Consistency checks needed

### Mitigation Strategy
- Daily validation after each task
- Performance benchmarks at Week 1 end
- Graph consistency checks throughout
- Regular code review cycles
- Backward compatibility testing

---

## Team Responsibilities

### Week 1 (Relationship + Schema)
- Core relationship builder pattern
- Schema migration system
- 14 relationship builders
- Initial relationship quality validation

### Week 2 (Temporal + Memory)
- Temporal field population
- Memory system architecture
- Historical data tracking
- Recurrence pattern detection

### Week 3 (Enrichment + Reasoning)
- OpenCTI deep integration
- Reasoning engine
- Multi-factor scoring
- Contextual prioritization

### Week 4-5 (Graph + Optimization)
- Graph algorithms
- Semantic fusion
- Performance tuning
- Production stabilization

---

## Validation Checkpoints

**End of Week 1:**
- ✅ 14 relationship builders implemented
- ✅ Schema backward compatible
- ✅ Relationship quality > 0.7 confidence
- ✅ Performance < 2s per CVE
- ✅ Zero breaking changes

**End of Week 2:**
- ✅ Temporal fields populated
- ✅ Memory system working
- ✅ Recurrence patterns detected
- ✅ Historical context available

**End of Week 3:**
- ✅ OpenCTI deeply integrated
- ✅ 9-factor reasoning implemented
- ✅ Prioritization logic validated
- ✅ Contextual recommendations working

**End of Week 4:**
- ✅ Graph algorithms operational
- ✅ Multi-hop traversal working
- ✅ Semantic fusion producing insights
- ✅ AI reasoning active

**End of Week 5:**
- ✅ Performance optimized
- ✅ All tests passing
- ✅ Relationships validated
- ✅ Production ready

---

## Final Output

By end of Week 5, system transforms from:

**Current State:**
```
"Agent + Enrichment"
- Orchestration: Strong
- Intelligence: Medium
- Relationships: Shallow (1-2 per entity)
- Memory: None
- Reasoning: Rule-based
```

**Target State:**
```
"AI-Driven Threat Knowledge Intelligence Platform"
- Orchestration: Strong (unchanged)
- Intelligence: Strong (upgraded)
- Relationships: Dense (5-7 per entity)
- Memory: Persistent (across runs)
- Reasoning: Context-aware (9 factors)
- Graph: Native reasoning (multi-hop)
- Fusion: Semantic (contextual synthesis)
```

---

## Next Steps

### Immediate (Today)
- ✅ Review confirmed strategy
- ✅ Setup Week 1 tasks
- ✅ Prepare development environment
- ✅ Schedule daily standups

### This Week
- Start Day 1: Relationship design & schema
- Complete 14 relationship builders
- Implement schema enhancements
- Create migration system

### Success Criteria
- Week 1 complete with 0 breaking changes
- Relationship quality validated
- Performance baseline established
- Ready for Week 2 (temporal + memory)

---

## Final Confirmation

**Strategy:** ✅ CONFIRMED
**Scope:** ✅ 14 relationships + schema enhancement (Week 1)
**Timeline:** ✅ 5 weeks incremental
**Risk:** ✅ Low (non-breaking, validated at each stage)
**Architecture:** ✅ Preserved (enhanced, not replaced)

**Status:** 🚀 READY TO START IMPLEMENTATION

---

**Approved By:** User confirmation of spec  
**Date Approved:** 17-05-2026  
**Implementation Start:** Now  
**Expected Completion:** 5 weeks from start  

**Goal Transformation:**
"Agent + Enrichment" → "AI-Driven Threat Knowledge Intelligence Platform"

🎯 **Ready to begin Week 1!**
