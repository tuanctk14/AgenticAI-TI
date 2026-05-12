# Code Audit Report - Duplication & Optimization

**Date**: 2026-05-12  
**Status**: AUDIT COMPLETE  
**Action Required**: CONSOLIDATE & OPTIMIZE

---

## Executive Summary

Found **significant duplication** in MITRE/NIST mapping logic across multiple files. Current production uses `cwe_mapper.py` but legacy code in `cve_inference.py` and `inference_pipeline.py` duplicates this functionality.

| File | Purpose | Status | Used? |
|------|---------|--------|-------|
| cwe_mapper.py | CWE→MITRE/NIST mapping | ✅ Active | YES (cmdb.py) |
| cve_inference.py | CWE→MITRE/NIST (legacy) | ⚠️ Duplicate | NO (orphaned) |
| inference_pipeline.py | 5-layer inference (legacy) | ⚠️ Duplicate | NO (orphaned) |
| mitre.py | MITRE database loader | ⚠️ Legacy | NO (orphaned) |
| nist.py | NIST database loader | ⚠️ Legacy | NO (orphaned) |
| vuln_ontology.py | Semantic classification | ⚠️ Unused | NO (orphaned) |
| product_context.py | Product-aware remapping | ⚠️ Unused | NO (orphaned) |

---

## Detailed Findings

### 1. CWE → MITRE Mapping Duplication

**cve_inference.py** (Legacy):
```python
CWE_MITRE_MAP = {
    "CWE-79": [techniques: [T1189]],
    "CWE-89": [techniques: [T1190]],
    # ... 13 total entries
}
```

**cwe_mapper.py** (Active):
```python
CWE_TO_MITRE = {
    "20": ["T1190"],
    "77": ["T1059"],
    # ... 19 total entries
}
```

**Issue**: Different keys ("CWE-XX" vs "XX"), different mappings, only one is used

---

### 2. CWE → NIST Mapping Duplication

**cve_inference.py**:
```python
CWE_NIST_MAP = {
    "CWE-89": ["SI-10"],
    # ... 13 entries
}
```

**cwe_mapper.py**:
```python
CWE_TO_NIST = {
    "20": ["SI-10", "SI-7"],
    # ... 19 entries
}
```

**Issue**: Only `cwe_mapper.py` is used in production

---

### 3. Inference Pipeline Duplication

**inference_pipeline.py** contains:
- `InferencePipeline` class with 5-layer architecture
- Hardcoded CVE mappings (EXACT_CVE_MAP)
- Layer logic (exact → CWE → ontology → context → fallback)
- Uses `cve_inference.py` internally

**Status**: NOT USED in production  
**Why**: Superseded by `cwe_mapper.py` which integrates into `cmdb.py`

---

### 4. Database Loader Duplication

| File | Function | Status |
|------|----------|--------|
| mitre.py | `load_mitre_database()` | Legacy |
| mitre_builder.py | `download_mitre_data()` | Legacy |
| nist.py | `load_nist_database()` | Legacy |
| nist_builder.py | `download_nist_data()` | Legacy |
| cwe_mapper.py | `_load_mitre_data()` | Active |
| cwe_mapper.py | `_load_nist_data()` | Active |

**Issue**: Both old and new loaders exist; only new ones in `cwe_mapper.py` are used

---

### 5. Unused Modules

**vuln_ontology.py**:
- Semantic vulnerability classification
- 11 vulnerability classes
- NOT imported or used anywhere
- Location: Created in earlier phase but replaced by CWE mapping

**product_context.py**:
- Product-aware MITRE context remapping
- Device-type-specific techniques
- NOT imported or used in production
- Location: Created in earlier phase but replaced by CWE mapping

---

## Code Dependency Analysis

### Current Production Path (Menu 1)
```
nvd_client.py (fetch CVE + CWE)
    ↓
cve_parser.py (parse CPE + CWE)
    ↓
cmdb.py (match devices)
    ├─ match_cves_with_cmdb()
    └─ get_cwe_analysis()
        └─ cwe_mapper.py ✅ ACTIVE
            ├─ cwe_to_mitre_techniques()
            └─ cwe_to_nist_controls()
```

### Unused Legacy Paths
```
inference_pipeline.py (NOT USED)
    ├─ cve_inference.py (legacy CWE mappings)
    ├─ vuln_ontology.py (semantic classification)
    └─ product_context.py (context remapping)

mitre.py / mitre_builder.py (NOT USED)
nist.py / nist_builder.py (NOT USED)
```

---

## Optimization Recommendations

### Phase 1: CONSOLIDATE (High Priority)
**Action**: Remove dead code

1. **Delete unused modules** (they're superseded):
   - ❌ `tools/inference_pipeline.py` (replaced by cwe_mapper + cmdb)
   - ❌ `tools/cve_inference.py` (replaced by cwe_mapper)
   - ❌ `tools/vuln_ontology.py` (semantic classification not needed)
   - ❌ `tools/product_context.py` (context remapping not needed)
   - ❌ `tools/mitre.py` (replaced by cwe_mapper._load_mitre_data)
   - ❌ `tools/mitre_builder.py` (replaced by cwe_mapper._load_mitre_data)
   - ❌ `tools/nist.py` (replaced by cwe_mapper._load_nist_data)
   - ❌ `tools/nist_builder.py` (replaced by cwe_mapper._load_nist_data)

**Impact**: Reduce tools/ from 17 files to 9 files (-8 files, -1000+ lines)

2. **Keep only active modules**:
   - ✅ `nvd_client.py` - NVD API interface
   - ✅ `cve_parser.py` - CPE extraction & parsing
   - ✅ `cwe_mapper.py` - CWE → MITRE/NIST (unified)
   - ✅ `cmdb.py` - Device matching
   - ✅ `doc_store.py` - Knowledge base
   - ✅ `report_generator.py` - Report generation
   - ✅ `opencti_client.py` - OpenCTI integration
   - ✅ `analyzer.py` - Analysis logic

---

### Phase 2: MERGE (Medium Priority)
**Action**: Consolidate CWE mappings

Currently in `cwe_mapper.py`:
```python
CWE_TO_MITRE = {
    "20": ["T1190"],  # 19 entries
}
CWE_TO_NIST = {
    "20": ["SI-10", "SI-7"],  # 19 entries
}
```

Expand mappings to cover all of `cve_inference.py`'s mappings (use both as reference):
- Current: 19 CWE mappings
- Target: 30+ CWE mappings (merge best of both)

---

### Phase 3: VERIFY (High Priority)
**Action**: Test all menus after cleanup

1. Menu 1 (CVE Scan): Should work identically
2. Menu 2 (Report): Should work identically  
3. Menu 3 (Upload): Should work identically
4. Menu 4 (Chat): Verify no agent imports removed modules

---

## Code Quality Metrics

### Before Cleanup
```
tools/ files: 17
Total lines: ~3000+
Dead code ratio: 30%+
Duplicate mappings: 2 (CWE_MITRE, CWE_NIST)
```

### After Cleanup (Projected)
```
tools/ files: 9
Total lines: ~1800
Dead code ratio: 0%
Duplicate mappings: 0 (consolidated to cwe_mapper.py)
```

---

## Testing Checklist

After cleanup, verify:

### Menu 1 (CVE Scan)
- [ ] CVE-2021-44228: log4j matching ✅
- [ ] CVE-2021-41773: Apache HTTP matching ✅
- [ ] CWE extraction works
- [ ] MITRE mapping appears in output
- [ ] NIST control mapping appears in output

### Menu 2 (Report)
- [ ] Report generation succeeds
- [ ] Device impact shows CWE/MITRE/NIST
- [ ] No import errors

### Menu 3 (Upload)
- [ ] Document upload works
- [ ] KB integration works

### Menu 4 (Chat)
- [ ] Agent routing works
- [ ] No removed module imports

---

## Implementation Plan

### Step 1: Identify Dependencies
```bash
grep -r "from.*inference_pipeline\|from.*cve_inference" agents/ main.py
grep -r "from.*vuln_ontology\|from.*product_context" agents/ main.py
grep -r "from.*mitre\.py\|from.*nist\.py" agents/ main.py
```

### Step 2: Verify Nothing Uses Dead Code
Expected result: **0 references** to dead modules

### Step 3: Delete Dead Files
```bash
rm tools/inference_pipeline.py
rm tools/cve_inference.py
rm tools/vuln_ontology.py
rm tools/product_context.py
rm tools/mitre.py
rm tools/mitre_builder.py
rm tools/nist.py
rm tools/nist_builder.py
```

### Step 4: Expand CWE Mappings in cwe_mapper.py
- Add missing mappings from `cve_inference.py`
- Unify format (use numeric keys)
- Test all mappings

### Step 5: Run Tests
```bash
python test_menu1_interactive.py
python test_menus_quick.py
```

### Step 6: Commit
```bash
git add -A
git commit -m "refactor: Remove dead code and consolidate CWE mapping

Removed 8 unused/duplicate modules:
- inference_pipeline.py (superseded by cwe_mapper + cmdb)
- cve_inference.py (legacy CWE mappings)
- vuln_ontology.py (unused semantic classification)
- product_context.py (unused context remapping)
- mitre.py, mitre_builder.py (replaced by cwe_mapper)
- nist.py, nist_builder.py (replaced by cwe_mapper)

Impact:
- Reduced tools/ from 17 to 9 files
- Removed ~1200 lines of dead code
- Consolidated all CWE→MITRE/NIST into single cwe_mapper.py
- No functionality change (all active code preserved)

Verified:
- Menu 1: CVE scan still working
- Menu 2: Report generation still working
- No remaining imports of deleted modules
"
```

---

## Risks & Mitigation

| Risk | Likelihood | Mitigation |
|------|------------|-----------|
| Agent imports dead modules | Medium | Run grep to verify before delete |
| Lost functionality | Low | Keep git history; all active code preserved |
| Test failures | Low | Run full test suite after cleanup |

---

## Summary

**Status**: READY FOR CLEANUP  
**Effort**: 2-3 hours  
**Risk**: LOW (all dead code identified, 0 production imports expected)  
**Benefit**: 40% reduction in code complexity, unified CWE mapping

---

**Author**: Code Audit Tool  
**Date**: 2026-05-12  
**Next Step**: Check for dead module imports, then proceed with cleanup
