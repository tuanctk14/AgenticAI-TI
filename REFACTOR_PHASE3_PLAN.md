# PHASE 3: Architecture Refactor Plan

**Objective**: Consolidate 30+ overlapping files into clean, single-responsibility modules

---

## Overview

Current system has excessive duplication due to rapid development:

- **12 graph files** → consolidate to 3-4 unified files
- **7 enrichment files** → consolidate to 2 unified files  
- **10 relationship files** → consolidate to 2-3 unified files
- **2 CWE mappers** → consolidate to 1
- **2 OpenCTI clients** → consolidate to 1

**Total Impact**: 30+ files → 12 core files (60% reduction in service layer code)

---

## Strategy

### KEY PRINCIPLE
**Merge based on abstraction level, not just function grouping**:
- Keep abstract interfaces separate from implementations
- Keep business logic separate from infrastructure
- Repository pattern: single abstraction, single concrete implementation per storage backend

---

## 1. GRAPH LAYER CONSOLIDATION

### Current Files
```
core/graph.py                        (147 LOC) - LangGraph orchestration
core/neo4j_repository.py             (1200+ LOC) - Neo4j storage
core/sqlite_repository.py            (800+ LOC) - SQLite storage
core/threat_repository.py            (350+ LOC) - Repository abstraction
core/threat_graph_analyzer.py        (300+ LOC) - Graph analysis
core/graph_query_engine.py           (250+ LOC) - Query layer
core/knowledge_graph.py              (400+ LOC) - KG implementation
core/graph_intelligence_layer.py     (200+ LOC) - Intelligence layer
tools/neo4j_relationship_persister.py (250+ LOC) - Neo4j persistence
```

### Action Plan

#### 1.1 Keep & Clean: LangGraph Orchestration
**File**: `core/graph.py` ✓ (KEEP - core infrastructure)
- No changes needed
- This is the main workflow orchestration

#### 1.2 Create Unified: Repository Layer
**Target**: `core/repositories/base.py`
```python
# Abstract interface (from threat_repository.py)
class ThreatKnowledgeRepository(ABC):
    @abstractmethod
    async def get_vulnerability(...) -> Optional[Vulnerability]:
    @abstractmethod
    async def store_relationship(...) -> bool:
    # ...etc
```

**Target**: `core/repositories/neo4j.py`
- Merge: `neo4j_repository.py` + `neo4j_relationship_persister.py`
- Keep all Neo4j-specific logic
- Use abstract interface from base.py

**Target**: `core/repositories/sqlite.py`
- Merge: `sqlite_repository.py`
- Use abstract interface from base.py

**Result**: 3 files instead of 5 (saves 400+ LOC file overhead)

#### 1.3 Create Unified: Graph Intelligence
**Target**: `core/graph_analyzer.py`
- Merge: `threat_graph_analyzer.py` + `graph_query_engine.py` + `graph_intelligence_layer.py`
- Remove duplicate query logic
- Single interface: `GraphAnalyzer(repository: ThreatKnowledgeRepository)`

**Result**: 1 file instead of 3

#### 1.4 Remove Dead Code
**Delete**: `knowledge_graph.py`
- Duplicate of threat_graph_analyzer.py functionality
- No production code imports this

**Result**: Save 400 LOC

### Net Result for Graph Layer
- **Before**: 9 files (3700+ LOC)
- **After**: 4 files (2800 LOC)
- **Reduction**: 5 files, 900 LOC removed

---

## 2. ENRICHMENT LAYER CONSOLIDATION

### Current Files
```
core/threat_enrichment_pipeline.py   (500+ LOC) - Main orchestrator
tools/enrichment/orchestrator.py     (200+ LOC) - Wrapper (DUPLICATE)
tools/enrichment/cache.py            (150+ LOC) - Caching logic
tools/enrichment/schema.py           (100+ LOC) - Schema definitions
tools/opencti_relationship_enricher.py(400+ LOC) - OpenCTI integration
```

### Action Plan

#### 2.1 Keep & Enhance: Main Pipeline
**File**: `core/threat_enrichment_pipeline.py` ✓ (KEEP & MERGE)
- Already the main orchestrator
- Merge in `tools/enrichment/cache.py` (caching logic)
- Merge in `tools/enrichment/schema.py` (move to `core/enrichment_schema.py`)

**Action**:
```python
# core/threat_enrichment_pipeline.py becomes single orchestrator with:
- EnrichmentStrategy enum
- EnrichmentCache class
- EnrichmentSchema models
- ThreatEnrichmentPipeline orchestrator
```

#### 2.2 Delete: Duplicate Wrapper
**Delete**: `tools/enrichment/orchestrator.py`
- This is just a wrapper around threat_enrichment_pipeline.py
- No unique functionality
- No production code should import this

#### 2.3 Consolidate: OpenCTI Integration
**Target**: `tools/enrichment/opencti_enricher.py`
- Keep: `tools/opencti_relationship_enricher.py` (rename it)
- Remove: `tools/opencti_client.py` (merge into enricher)
- Single unified OpenCTI interface

**Result**: 1 file instead of 2

### Net Result for Enrichment Layer
- **Before**: 5 files (1350+ LOC)
- **After**: 2 files (950 LOC + imports structure)
- **Reduction**: 3 files, 400 LOC removed

---

## 3. RELATIONSHIP LAYER CONSOLIDATION

### Current Files
```
tools/cve_relationship_integrator.py      (65 LOC) - Wrapper
tools/cve_relationship_tool.py            (145 LOC) - Agent tool
tools/relationship_confidence_engine.py   (230+ LOC) - Scoring
tools/relationship_formatter.py           (210+ LOC) - Display
tools/relationship_validator.py           (320+ LOC) - Validation
tools/opencti_relationship_enricher.py    (400+ LOC) - OpenCTI ↔ Merge with enrichment
core/relationship_builders.py             (200+ LOC) - Building logic
tools/neo4j_relationship_persister.py     (250+ LOC) - Persistence ↔ Move to repositories
```

### Action Plan

#### 3.1 Create Unified: Relationship Pipeline
**Target**: `core/relationships/pipeline.py`
- Merge: `cve_relationship_integrator.py` (wrapper) + `cve_relationship_tool.py` (agent interface)
- Single entry point for agent: `enrich_cve_relationships(cve_id: str) -> dict`

#### 3.2 Create Unified: Confidence Scoring
**Target**: `core/relationships/confidence.py`
- Keep: `relationship_confidence_engine.py`
- Name: `ConfidenceEngine` (already good)
- Add: Multi-factor validation logic

#### 3.3 Create Unified: Relationship Display
**Target**: `core/relationships/formatter.py`
- Keep: `relationship_formatter.py`
- Name: `RelationshipFormatter` (already good)

#### 3.4 Create Unified: Relationship Validation  
**Target**: `core/relationships/validator.py`
- Keep: `relationship_validator.py`
- Name: `RelationshipValidator` (already good)

#### 3.5 Consolidate: Relationship Building
**Target**: `core/relationships/builders.py`
- Keep: `relationship_builders.py`
- Keep: Relationship construction logic

#### 3.6 Move: Persistence Logic
**Action**: Move Neo4j persistence to repositories layer
- `neo4j_relationship_persister.py` → merge into `core/repositories/neo4j.py`
- Create generic method: `repository.store_relationship(rel: Relationship) -> bool`

### Net Result for Relationship Layer
- **Before**: 8 files (1820+ LOC)
- **After**: 5 files in `core/relationships/` (1450 LOC)
- **Reduction**: 3 files, 370 LOC consolidated

---

## 4. CWE MAPPING CONSOLIDATION

### Current Files
```
tools/cwe_mapper.py           (195 LOC) - Main mapper
tools/cwe_mapper_expanded.py  (800+ LOC) - Data
```

### Action Plan

#### 4.1 Consolidate: CWE Mapper
**Target**: `tools/cwe_mapper.py`
- Keep: Main `CWEMapper` class
- Import: CWE data from `tools/cwe_mapper_expanded.py` (it's just a data dict)

**Delete**: `tools/cwe_mapper_expanded.py`
- Move CWE_TO_MITRE dict to `data/cwe_mappings.json`
- Lazy-load from JSON instead of Python dict

**Action**:
```python
# tools/cwe_mapper.py
def _load_cwe_mappings():
    with open('data/cwe_mappings.json') as f:
        return json.load(f)

CWE_TO_MITRE = _load_cwe_mappings()
```

### Net Result for CWE Layer
- **Before**: 2 files (995 LOC)
- **After**: 1 file + JSON data (195 LOC)
- **Reduction**: 1 file, 800 LOC eliminated

---

## 5. OPENCTI CLIENT CONSOLIDATION

### Current Files
```
tools/opencti_client.py                  (200+ LOC) - Generic client
tools/opencti_relationship_enricher.py   (400+ LOC) - Enricher
```

### Action Plan

#### 5.1 Consolidate: Single OpenCTI Interface
**Target**: `tools/openct/client.py`
- Keep: Unified OpenCTI client
- Merge: Generic client methods from `opencti_client.py`
- Merge: Enrichment-specific methods from `opencti_relationship_enricher.py`

**Result**: Single source of truth for OpenCTI integration

### Net Result for OpenCTI
- **Before**: 2 files (600+ LOC)
- **After**: 1 file (500 LOC)
- **Reduction**: 1 file, 100 LOC consolidated

---

## 6. PARSING UTILITIES

### Current Files
```
tools/cve_parser.py        (120 LOC)
tools/ioc_extractor.py     (150 LOC)
tools/product_extractor.py (100 LOC)
```

### Analysis

These are legitimately separate concerns:
- CVE parsing: NVD-specific format
- IOC extraction: Threat intel indicators (IP, hash, etc.)
- Product extraction: Software product identification

**Decision**: KEEP SEPARATE
- Each has distinct responsibility
- Minimal code duplication
- Low coupling to each other

---

## Summary of Consolidation

| Layer | Before | After | Reduction |
|-------|--------|-------|-----------|
| Graph | 9 files | 4 files | -5 files, -900 LOC |
| Enrichment | 5 files | 2 files | -3 files, -400 LOC |
| Relationships | 8 files | 5 files | -3 files, -370 LOC |
| CWE | 2 files | 1 file | -1 file, -800 LOC |
| OpenCTI | 2 files | 1 file | -1 file, -100 LOC |
| **TOTAL** | **26 files** | **13 files** | **-13 files, -2570 LOC** |

---

## Execution Order

### Safe to Do Immediately
1. Consolidate CWE mappings (isolated, no dependencies)
2. Delete duplicate enrichment orchestrator
3. Consolidate repository layer (abstraction clean)

### Requires Testing
4. Consolidate enrichment pipeline (touches agents)
5. Consolidate graph analyzer (touches agents)
6. Consolidate relationship engine (touches agents)
7. Consolidate OpenCTI client (touches enrichment)

### Post-Consolidation
8. Run full regression test suite
9. Test Menu 1, 2, 3, 4 workflows
10. Verify OpenCTI integration still works

---

## Implementation Notes

### Avoiding Import Issues
- Create new `__init__.py` files in consolidated modules
- Update all imports in agents/base.py, main.py
- Maintain backward compatibility shims if needed

### Database Migration
- Repository pattern ensures no database changes needed
- Both Neo4j and SQLite adapters will still work
- Graph intelligence layer still works with unified interface

### Agent Impacts
- Agents use tool interfaces (enrich_cve_relationships, etc.)
- Internal consolidation is transparent to agents
- No agent code changes needed

---

## Rollback Strategy

After each consolidation phase:
```bash
# Test specific menu workflow
python3 main.py  # Test Menu 1, 2, 3, 4 interactively

# Run regression tests
pytest tests/ -v -k "not real_data"

# If issues, rollback:
git reset --hard HEAD~1
```

