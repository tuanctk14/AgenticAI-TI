# BƯỚC 2: GAP ANALYSIS — MAPPED CHI TIẾT

**Mục tiêu**: Liệt kê toàn bộ gaps từ BƯỚC 1 theo format chuẩn, so sánh với pipeline đích

---

## PIPELINE ĐÍC (MONG MUỐN)

```
CVE ID
  ↓ (NVD API 2.0)
{CWE[], CPE[], CVSS, refs}
  ↓ (CWE XML lookup — Related_Attack_Patterns)
{CAPEC[]}
  ↓ (CAPEC XML lookup — Taxonomy_Mappings)
{ATT&CK techniques[]}
  ↓ (Center for Threat-Informed Defense Mappings Explorer)
{NIST 800-53 controls[]}
  ↓ (enrich với KEV + EPSS)
Final report: attack techniques + recommended controls + priority score
```

---

## CHI TIẾT GAPS

### Gap #1: CWE → CAPEC Mapping

**Mô tả ngắn**: Missing step để link CWE (từ NVD) tới CAPEC attack patterns

**File/module sẽ chạm**:
- NEW: `tools/capec_loader.py` (chứa CAPECLoader class)
- NEW: `tools/capec_cache.py` (caching CWE XML dump)
- EXTEND: `tools/cwe_mapper.py` (add `cwe_to_capec_ids()` method)
- EXTEND: `enrichment/schema.py` (add `capec_ids: List[str]` field)

**Lý do chọn chỗ này (vs tạo mới)**:
- `cwe_mapper.py` đã có logic load CWE data; extend nó là tự nhiên
- CAPEC XML cần cache riêng (separate from Pydantic models)
- Schema mở rộng dễ hơn tạo file mapping riêng

**Thay đổi dự kiến**:

| Loại | File | Chi Tiết |
|------|------|---------|
| **NEW file** | `tools/capec_loader.py` | Class `CAPECLoader`: load CWE XML, extract CWE-ID → `<Related_Attack_Patterns>` → CAPEC-ID |
| **NEW file** | `tools/capec_cache.py` | Cache CAPEC XML dump (weekly refresh) |
| **EXTEND** | `tools/cwe_mapper.py` | Add method: `cwe_to_capec_ids(cwe_id: str) -> List[str]` |
| **EXTEND** | `enrichment/schema.py` | Add field: `capec_ids: Optional[List[str]] = None` |

**Example Output**:
```python
# INPUT
cwe_id = "22"  # Path Traversal

# PROCESS (CWE XML lookup)
# <CWE ID="22">
#   <Related_Attack_Patterns>
#     <Related_Attack_Pattern CAPEC_ID="126"/>
#     <Related_Attack_Pattern CAPEC_ID="3"/>
#   </Related_Attack_Patterns>
# </CWE>

# OUTPUT
capec_ids = ["126", "3"]
```

---

### Gap #2: CAPEC → ATT&CK Mapping

**Mô tả ngắn**: Missing step để link CAPEC tới ATT&CK techniques via Taxonomy_Mappings

**File/module sẽ chạm**:
- EXTEND: `tools/capec_loader.py` (add method để parse Taxonomy_Mappings)
- NEW: `tools/capec_to_attack_mapper.py` (logic for CAPEC → T-code resolution)
- EXTEND: `enrichment/schema.py` (fields already prepared in G1)

**Lý do chọn chỗ này**:
- CAPEC XML có field `<Taxonomy_Mappings>` → ATT&CK entry (T-number embedded)
- Cần parser riêng vì Taxonomy_Mappings structure phức tạp
- `capec_to_attack_mapper.py` keep concerns separated (CAPEC-specific logic)

**Thay đổi dự kiến**:

| Loại | File | Chi Tiết |
|------|------|---------|
| **EXTEND** | `tools/capec_loader.py` | Add method: `capec_to_attack_techniques(capec_id: str) -> List[str]` |
| **NEW file** | `tools/capec_to_attack_mapper.py` | Parser for `<Taxonomy_Mappings>` → extract T-numbers + confidence |
| **EXTEND** | `tools/cwe_mapper.py` | Add convenience method: `cwe_to_attack_techniques_via_capec(cwe_id) -> List[Dict]` |

**Example Output**:
```python
# INPUT
capec_id = "126"  # Forceful Browsing

# PROCESS (CAPEC XML lookup)
# <Attack_Pattern ID="126">
#   <Taxonomy_Mappings>
#     <Taxonomy_Mapping>
#       <Taxonomy_Name>ATT&amp;CK</Taxonomy_Name>
#       <Entry_ID>T1190</Entry_ID>  ← Exploit Public-Facing Application
#     </Taxonomy_Mapping>
#   </Taxonomy_Mappings>
# </Attack_Pattern>

# OUTPUT
attack_techniques = [
    {
        "t_number": "T1190",
        "name": "Exploit Public-Facing Application",
        "capec_confidence": 0.8  # from CAPEC Likelihood_Of_Attack
    }
]
```

---

### Gap #3: ATT&CK Technique Resolution (STIX)

**Mô tả ngắn**: Improve lookup of technique details từ STIX data (description, mitigations, tactics)

**File/module sẽ chạm**:
- EXTEND: `tools/cwe_mapper.py` (currently uses `mitre_attack.json`)
- NEW: `tools/stix_resolver.py` (better STIX parsing + caching)
- EXTEND: `enrichment/schema.py` (add technique description, tactics, mitigations)

**Lý do chọn chỗ này**:
- `cwe_mapper.py` đang load `mitre_attack.json` — extend nó
- STIX format complex → deserve riêng `stix_resolver.py`
- Current `mitre_attack.json` có sẵn techniques, chỉ cần enrich thêm fields

**Thay đổi dự kiến**:

| Loại | File | Chi Tiết |
|------|------|---------|
| **NEW file** | `tools/stix_resolver.py` | Class `STIXResolver`: load MITRE STIX JSON, resolve T-numbers → full technique data |
| **EXTEND** | `tools/cwe_mapper.py` | Use STIXResolver instead of direct JSON load |
| **EXTEND** | `enrichment/schema.py` | Add field to attack_technique: `tactics: List[str]`, `mitigations: List[str]` |

**Example Output**:
```python
# INPUT
t_number = "T1190"

# PROCESS (STIX lookup)
# From mitre-cti/enterprise-attack/enterprise-attack.json
# {
#   "type": "attack-pattern",
#   "id": "attack-pattern--..."
#   "name": "Exploit Public-Facing Application"
#   "x_mitre_platforms": ["Linux", "Windows", "macOS", "Web"]
#   "kill_chain_phases": [
#     {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
#   ]
#   "x_mitre_detection": "..."
# }

# OUTPUT
{
    "t_number": "T1190",
    "name": "Exploit Public-Facing Application",
    "tactics": ["Initial Access"],
    "description": "...",
    "detection": "...",
    "mitigations": ["M1050", "M1051"]
}
```

---

### Gap #4: ATT&CK → NIST 800-53 Bidirectional Mapping

**Mô tả ngắn**: Missing structured mapping từ ATT&CK techniques → NIST controls (center-for-threat-informed-defense)

**File/module sẽ chạm**:
- NEW: `tools/attack_nist_mapper.py` (load Mappings Explorer data)
- NEW: `tools/attack_nist_cache.py` (cache for mapping JSON)
- EXTEND: `enrichment/schema.py` (add `nist_controls` field with source tracking)

**Lý do chọn chỗ này**:
- Mappings Explorer là official mapping source (not cwe_mappings.json hack)
- ATT&CK → NIST is distinct from CWE → NIST fallback
- Deserves dedicated module để keep concerns clear

**Thay đổi dự kiến**:

| Loại | File | Chi Tiết |
|------|------|---------|
| **NEW file** | `tools/attack_nist_mapper.py` | Class `AttackNISTMapper`: load Rev.5 mappings, T-number → controls |
| **NEW file** | `tools/attack_nist_cache.py` | Cache mapping JSON (monthly refresh) |
| **EXTEND** | `enrichment/schema.py` | Add field: `nist_controls: List[Dict]` with {control_id, weight, techniques} |

**Example Output**:
```python
# INPUT
t_number = "T1190"

# PROCESS (Mappings Explorer lookup)
# Rev.5 JSON:
# {
#   "technique_id": "T1190",
#   "controls": [
#     {"control": "SI-10", "type": "Preventive"},
#     {"control": "DE-3", "type": "Detective"}
#   ]
# }

# OUTPUT
nist_controls_for_technique = [
    {"control": "SI-10", "name": "Information Input Validation", "type": "Preventive"},
    {"control": "DE-3", "name": "Analyze User-Generated Content", "type": "Detective"}
]
```

---

### Gap #5: CWE → NIST Fallback (Heimdall CSV)

**Mô tả ngắn**: Fallback path khi CWE → CAPEC → ATT&CK → NIST không có data

**File/module sẽ chạm**:
- NEW: `tools/heimdall_cwe_nist_mapper.py` (load deprecated Heimdall CSV)
- EXTEND: `cwe_mapper.py` (add fallback chain: try ATT&CK first, then Heimdall)

**Lý do chọn chỗ này**:
- CWE → NIST fallback, NOT primary
- Separate module signals "this is fallback, not authoritative"
- Integrate into `cwe_mapper.py` as secondary logic

**Thay đổi dự kiến**:

| Loại | File | Chi Tiết |
|------|------|---------|
| **NEW file** | `tools/heimdall_cwe_nist_mapper.py` | Parser for Heimdall CSV: CWE-ID → NIST control list |
| **EXTEND** | `cwe_mapper.py` | Add method: `cwe_to_nist_with_fallback(cwe_id) -> List[Dict]` (try ATT&CK first) |

**Example Output**:
```python
# INPUT
cwe_id = "22"  # Path Traversal

# PRIMARY PATH (CWE → CAPEC → T1083 → SI-10)
result = {
    "source": "attack_chain",
    "controls": [{"control": "SI-10", "confidence": 0.95}]
}

# FALLBACK (if no T-number found)
# Heimdall CSV: CWE-22,SI-10,SI-12,AC-3
result = {
    "source": "heimdall",
    "controls": [
        {"control": "SI-10", "confidence": 0.7},
        {"control": "SI-12", "confidence": 0.6}
    ]
}
```

---

### Gap #6: UnifiedCVE Schema Extension

**Mô tả ngắn**: Add fields for CAPEC, ATT&CK techniques, NIST controls to UnifiedCVE

**File/module sẽ chạm**:
- EXTEND: `enrichment/schema.py` (add fields to UnifiedCVE)

**Lý do chọn chỗ này**:
- UnifiedCVE là single source of truth
- Avoid creating separate data structures
- Already has extensible design

**Thay đổi dự kiến**:

| Field | Type | Purpose |
|-------|------|---------|
| `capec_ids` | `Optional[List[Dict]]` | CAPEC attack patterns: `[{id, name, likelihood}]` |
| `attack_techniques` | `Optional[List[Dict]]` | ATT&CK T-codes: `[{t_num, name, tactics, source}]` |
| `nist_controls` | `Optional[List[Dict]]` | NIST controls: `[{control, name, type, weight}]` |
| `attack_paths` | `Optional[List[Dict]]` | (for G10) Full paths: `[{cwe, capec, technique, control}]` |

---

### Gap #7: Caching for XML/JSON Dumps

**Mô tả ngắn**: Missing cache strategy for CWE/CAPEC/ATT&CK STIX/Heimdall data

**File/module sẽ chạm**:
- NEW: `tools/data_cache_manager.py` (unified cache manager)
- EXTEND: `enrichment/cache.py` (add refresh logic for XML/STIX)

**Lý do chọn chỗ này**:
- Caching strategy orthogonal to individual loaders
- Dedicated module signals "this is infrastructure"
- `enrichment/cache.py` already exists

**Thay đổi dự kiến**:

| Loại | File | Chi Tiết |
|------|------|---------|
| **NEW file** | `tools/data_cache_manager.py` | Manager class: tracks last refresh, triggers periodic downloads |
| **NEW** | `data/cache_metadata.json` | Tracks last refresh for CWE/CAPEC/STIX/Heimdall |
| **EXTEND** | Config | Add cache TTL settings (CWE: 7d, CAPEC: 7d, STIX: 30d, Heimdall: 30d) |

**Schedule**:
- CWE XML: Download weekly (Tue 00:00 UTC)
- CAPEC XML: Download weekly (Tue 01:00 UTC)
- MITRE STIX: Download monthly (1st of month)
- Heimdall CSV: Download monthly (5th of month)

---

### Gap #8: Ranking & Filtering Logic

**Mô tả ngắn**: Missing intelligent ranking of attack paths (CWE→CAPEC→ATT&CK→NIST)

**File/module sẽ chạm**:
- NEW: `tools/attack_path_ranker.py` (scoring logic)
- EXTEND: `enrichment/orchestrator.py` (call ranker in enrichment flow)

**Lý do chọn chỗ này**:
- Ranking is "post-processing" step in enrichment
- Dedicated module keeps scoring algorithm testable
- Orchestrator orchestrates → call ranker at end

**Thay đổi dự kiến**:

| Loại | File | Chi Tiết |
|------|------|---------|
| **NEW file** | `tools/attack_path_ranker.py` | Class `AttackPathRanker`: implement BƯỚC 4 scoring logic |
| **EXTEND** | `enrichment/orchestrator.py` | After enrichment, call `ranker.rank_paths(unified_cve)` |
| **EXTEND** | `enrichment/schema.py` | Add fields: `attack_paths: List[RankedAttackPath]`, `filtered_count: int` |

---

### Gap #9: Control Deduplication

**Mô tả ngắn**: Missing aggregation of NIST controls across multiple attack paths

**File/module sẽ chạm**:
- NEW: `tools/control_aggregator.py` (deduplication + weighting)
- EXTEND: `tools/attack_path_ranker.py` (call aggregator after ranking)

**Lý do chọn chỗ này**:
- Separate concern: ranking paths vs aggregating controls
- Keep ranker focused on path scoring
- Aggregator runs as post-process

**Thay đổi dự kiến**:

| Loại | File | Chi Tiết |
|------|------|---------|
| **NEW file** | `tools/control_aggregator.py` | Class `ControlAggregator`: compute `control_weight`, dedup, top-K |
| **EXTEND** | `tools/attack_path_ranker.py` | Call `ControlAggregator.aggregate(ranked_paths)` after path ranking |

---

### Gap #10: CVE Priority Scoring (CWE Level)

**Mô tả ngắn**: New layer of scoring BEFORE path ranking (CVE priority filters low-relevance CVEs early)

**File/module sẽ chạm**:
- EXTEND: `tools/risk_scorer.py` (add new `calculate_cve_priority_score()` method)
- EXTEND: `enrichment/orchestrator.py` (call scorer early in flow)

**Lý do chọn chỗ này**:
- Risk scorer already exists and scores CVEs
- Add new scoring layer naturally extends it
- Call in orchestrator before CAPEC/ATT&CK enrichment (cost optimization)

**Thay đổi dự kiến**:

| Loại | File | Chi Tiết |
|------|------|---------|
| **EXTEND** | `tools/risk_scorer.py` | Add method: `calculate_cve_priority_score(cve: UnifiedCVE) -> Tuple[float, str]` (0.35 CVSS + 0.30 KEV + 0.25 EPSS + 0.10 relevance) |
| **EXTEND** | `enrichment/orchestrator.py` | After basic enrichment, calculate priority → skip if < 0.4 (cost optimization) |

---

## SUMMARY TABLE

| Gap # | Component | Type | File Touched | Impact |
|-------|-----------|------|--------------|--------|
| G1 | CWE → CAPEC | NEW | capec_loader.py, capec_cache.py, cwe_mapper.py, schema.py | 4 |
| G2 | CAPEC → ATT&CK | NEW | capec_loader.py, capec_to_attack_mapper.py, cwe_mapper.py | 3 |
| G3 | ATT&CK STIX resolution | EXTEND | stix_resolver.py, cwe_mapper.py, schema.py | 3 |
| G4 | ATT&CK → NIST mapping | NEW | attack_nist_mapper.py, attack_nist_cache.py, schema.py | 3 |
| G5 | CWE → NIST fallback | NEW | heimdall_cwe_nist_mapper.py, cwe_mapper.py | 2 |
| G6 | Schema extension | EXTEND | schema.py | 1 |
| G7 | Caching strategy | NEW | data_cache_manager.py, cache.py, config | 3 |
| G8 | Path ranking | NEW | attack_path_ranker.py, orchestrator.py, schema.py | 3 |
| G9 | Control dedup | NEW | control_aggregator.py, attack_path_ranker.py | 2 |
| G10 | CVE priority score | EXTEND | risk_scorer.py, orchestrator.py | 2 |

**Total files to create/extend: 14**

---

## READY FOR BƯỚC 3: PLAN BỔ SUNG
