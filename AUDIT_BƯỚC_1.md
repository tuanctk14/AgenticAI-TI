# BƯỚC 1: AUDIT CODEBASE HIỆN TẠI

**Ngày**: 2026-06-15  
**Mục tiêu**: Hiểu rõ pipeline CVE → CWE → ATT&CK → NIST hiện tại, xác định gaps

---

## PHẦN I: TREE STRUCTURE - MODULE LIÊN QUAN

```
ATI-AgenticThreatIntelligence/
├── core/
│   ├── threat_schema.py        (Canonical threat entities: CVE, ATT&CK, etc)
│   ├── threat_enrichment_pipeline.py
│   └── threat_repository.py
│
├── tools/
│   ├── nvd_client.py           (PRIMARY: NVD API 2.0 - CVE/CWE/CPE fetching)
│   ├── cwe_mapper.py           (CWE → MITRE ATT&CK + NIST direct mapping)
│   ├── risk_scorer.py          (CVE priority scoring)
│   ├── cve_parser.py
│   ├── cve_relationship_tool.py
│   │
│   ├── enrichment/
│   │   ├── orchestrator.py     (Multi-provider async orchestration)
│   │   ├── schema.py           (UnifiedCVE schema - CVSS/CWE/CPE/KEV/EPSS)
│   │   └── cache.py            (SQLite cache for enrichment data)
│   │
│   └── providers/
│       ├── nvd_provider.py
│       ├── epss_provider.py    (EPSS probability scoring)
│       ├── kev_provider.py     (CISA Known Exploited Vulnerabilities)
│       └── vulners_provider.py (Exploit intelligence)
│
└── data/
    ├── cwe_mappings.json       (CWE → MITRE/NIST - STATIC MAPPINGS)
    ├── mitre_attack.json       (ATT&CK techniques 858 techniques - STATIC)
    └── nist_controls.json      (NIST 800-53 controls - STATIC)
```

---

## PHẦN II: AUDIT TỪNG MODULE

### 1. **nvd_client.py** — CVE/CWE/CPE Input Layer

**Entry Points**:
- `fetch_cve_by_id(cve_id)` → 1 CVE từ NVD API 2.0
- `fetch_nvd_cves(keyword, severity, days_back)` → bulk CVE từ NVD API 2.0

**Dữ liệu NVD API trả về**:
```python
{
    "id": "CVE-2021-44228",
    "description": "...",
    "cvss_score": 10.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "severity": "CRITICAL",
    "published": "2021-12-10",
    "references": [...],
    "configurations": [...],  # Contains CPE entries
    "cwe_ids": ["22", "444"],  # ← EXTRACTED từ NVD weaknesses[]
    "enrichment": {  # Added by orchestrator.enrich_cve()
        "epss_score": 0.968,
        "epss_percentile": 99.0,
        "kev_listed": true,
        "public_exploit": true,
        "exploit_count": 5,
        "metasploit": true,
        ...
    }
}
```

**Data Model**: Flat dict (NOT Pydantic UnifiedCVE)

**Caching**: 
- Orchestrator uses SQLiteCacheProvider (24h TTL)
- But nvd_client itself does NOT cache NVD API calls

**Refresh Strategy**:
- Realtime API calls (5 req/sec without key, 50 req/s with key)
- Enrich data (EPSS/KEV/Vulners) cached 24h

---

### 2. **cwe_mapper.py** — CWE → MITRE ATT&CK + NIST Mapping

**Entry Points**:
- `get_mitre_attack_info(cve_id, cwe_ids)` → MITRE techniques
- `get_nist_controls(cve_id, cwe_ids)` → NIST controls
- `CWEMapper.cwe_to_mitre_techniques(cwe_id)` → direct CWE lookup
- `CWEMapper.cwe_to_nist_controls(cwe_id)` → direct CWE lookup

**Data Model** (Input):
```python
cwe_ids = ["22", "444"]  # List[str] from NVD
```

**Data Model** (Output):
```python
{
    "cve_id": "CVE-2021-44228",
    "mitre_techniques": [
        {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "description": "...",
            "tactics": ["Initial Access"]
        }
    ],
    "technique_count": 1,
    "source": "CWE-based inference"
}
```

**Data Sources**:
- `cwe_mappings.json` → {"cwe_to_mitre": {...}, "cwe_to_nist": {...}}
- `mitre_attack.json` → {"techniques": {"T1190": {...}}}
- `nist_controls.json` → {...}

**Mapping Logic**:
```
CWE-22 (Path Traversal)
  ↓ (lookup in cwe_mappings.json)
  → T1083 (File and Directory Discovery)
    ↓ (lookup technique in mitre_attack.json)
    → name, description, tactics
```

**Caching**: 
- JSON files loaded into memory at module import (singleton pattern)
- CWEMapper instance cached globally

**Coverage**:
- 802 CWEs mapped
- 858 MITRE techniques
- NIST 800-53 controls (unknown count)

**ISSUE #1**: NO CWE → CAPEC mapping (missing step in pipeline!)

---

### 3. **enrichment/schema.py** — UnifiedCVE Data Schema

**Core Schema**:
```python
class UnifiedCVE(BaseModel):
    cve_id: str
    metadata: CVEMetadata  # id, description, dates, refs
    cvss: Optional[CVSSData]  # score (float), severity, vector
    cwe: Optional[CWEData]  # ids: List[str]
    cpe: Optional[CPEData]  # entries: List[str]
    epss: Optional[EPSSData]  # score (0-1), percentile
    kev: Optional[KEVData]  # listed (bool), date_added
    vulncheck: Optional[VulnersData]  # public_exploit, metasploit, count
    unified_risk_score: float
    enrichment_summary: str
    data_quality: Optional[DataQuality]  # track sources
```

**Supported Fallback Chains**:
- CVSS: NVD → Vulners
- CWE: NVD → Vulners
- CPE: NVD → Vulners
- KEV: CISA → Vulners (but not recommended)

**ISSUE #2**: Schema has CWE IDs but NO fields for CAPEC, ATT&CK techniques, NIST controls!

---

### 4. **enrichment/orchestrator.py** — Multi-Provider Enrichment

**Flow**:
```
enrich_cve(cve_id)
  → 1. Check cache
  → 2. Fetch NVD (required)
  → 3. Async fetch EPSS + KEV + Vulners
  → 4. Merge data → UnifiedCVE
  → 5. Calculate risk_score
  → 6. Cache result
  → 7. Return UnifiedCVE
```

**Providers**:
- NVDProvider: CVE/CWE/CPE/CVSS
- EPSSProvider: EPSS probability
- KEVProvider: CISA Known Exploited Vulnerabilities
- VulnersProvider: Exploit intelligence

**Caching**: SQLiteCacheProvider (data/enrichment_cache.db, 24h TTL)

**ISSUE #3**: Orchestrator does NOT enrich with CAPEC, ATT&CK, NIST!

---

### 5. **risk_scorer.py** — CVE Priority Scoring

**Current Algorithm**:
```
Risk Score (per CVE on device) =
  Max CVSS × 0.25
  + Avg CVSS × 0.10
  + EPSS × 0.15
  + KEV Bonus × 0.10
  + Exploit Bonus × 0.10
  + Asset Criticality × 0.15
  + Exposure × 0.10
```

**Output Tiers**:
- 0-19: Low
- 20-39: Medium
- 40-59: High
- 60-79: Critical
- 80-100: Emergency

**ISSUE #4**: Scoring is per-CVE on asset, NOT per attack path (CWE→CAPEC→ATT&CK)

---

### 6. **cve_parser.py** — CVE Description Parsing

**Purpose**: Extract IOCs (IP, domain, hash) from CVE descriptions

**ISSUE #5**: Does NOT extract CAPEC IDs from CWE descriptions

---

### 7. **core/threat_schema.py** — Canonical Threat Schema

**Entities Defined**:
```python
class EntityType:
    VULNERABILITY = "vulnerability"  # ← CVE
    ATTACK_PATTERN = "attack_pattern"  # ← ATT&CK technique
    # But NO CAPEC, NO NIST control entity types!
```

**ISSUE #6**: Schema supports ATT&CK but NOT CAPEC as entity type

---

## PHẦN III: DATA FILES INVENTORY

### cwe_mappings.json
```json
{
  "cwe_to_mitre": {
    "20": ["T1190"],
    "21": ["T1190", "T1083"],
    "22": ["T1083"]
  },
  "cwe_to_nist": {
    "20": ["SI-10"],
    "21": ["SI-10", "AC-3"]
  }
}
```

**Issues**:
- Direct CWE → MITRE (no CAPEC intermediate)
- Direct CWE → NIST (no ATT&CK intermediate)
- Missing CAPEC IDs entirely

### mitre_attack.json (858 techniques)
```json
{
  "techniques": {
    "T1190": {
      "name": "Exploit Public-Facing Application",
      "description": "...",
      "tactics": ["Initial Access"],
      "detection": "...",
      "mitigations": ["M1050"]
    }
  },
  "mitigations": {...},
  "cve_mapping": {...}  # ← CVE to technique mapping (if any)
}
```

**Note**: Has CVE mapping but NOT structured well for pipeline

### nist_controls.json
```json
{
  "AC-3": {
    "title": "Access Enforcement",
    "description": "...",
    "family": "AC"
  }
}
```

**Issues**:
- No bidirectional ATT&CK → NIST mapping
- No mapping strength/relevance scoring

---

## PHẦN IV: CURRENT PIPELINE (AS IS)

```
CVE ID (string)
  ↓
fetch_cve_by_id() or fetch_nvd_cves()
  ↓ (NVD API 2.0)
{
  id, description, cvss_score, severity,
  cwe_ids: ["20", "22"],  ← EXTRACTED
  cpe: [...],
  enrichment: {epss, kev, exploit}
}
  ↓
enrich_cve() (orchestrator)
  ↓
UnifiedCVE schema (cached)
  ↓
cwe_mapper.get_mitre_attack_info(cwe_ids) [DIRECT]
  ↓
MITRE techniques (if CWE in cwe_mappings.json)
  ↓
risk_scorer.calculate_device_risk_score()
  ↓
Final score (per device)
```

**Pipeline DOES NOT HAVE**:
1. CWE → CAPEC mapping (missing!)
2. CAPEC → ATT&CK mapping (missing!)
3. ATT&CK → NIST mapping (hardcoded, not structured)
4. Ranking/filtering of multiple techniques per CVE
5. Attack path relevance scoring

---

## PHẦN V: GAP SUMMARY TABLE

| Gap # | Component | Current State | Needed |
|-------|-----------|---------------|--------|
| **G1** | CWE → CAPEC | ❌ MISSING | CWE XML lookup + CAPEC IDs extraction |
| **G2** | CAPEC → ATT&CK | ❌ MISSING | CAPEC XML lookup + Taxonomy_Mappings parsing |
| **G3** | ATT&CK technique resolution | ⚠️ PARTIAL | Better STIX integration, tactic/description |
| **G4** | ATT&CK → NIST mapping | ⚠️ HARDCODED | Center for Threat-Informed Defense mappings |
| **G5** | CWE → NIST fallback | ⚠️ BASIC | Heimdall CSV for secondary mapping |
| **G6** | UnifiedCVE schema | ⚠️ INCOMPLETE | Add capec_ids, attack_techniques, nist_controls fields |
| **G7** | Caching for XML dumps | ❌ MISSING | Weekly refresh for CWE/CAPEC/ATT&CK STIX data |
| **G8** | Ranking/filtering logic | ❌ MISSING | Path relevance scoring + hard filters + Top-K cutoff |
| **G9** | Control deduplication | ❌ MISSING | Weight-based control aggregation |
| **G10** | Scoring algorithm (CWE priority) | ❌ MISSING | New layer: path_relevance_score (see BƯỚC 4) |

---

## PHẦN VI: ENTRY POINTS FOR AGENTS

**Current agent entry points**:
1. `agents/base.py` → `get_mitre_attack_info(cve_id, cwe_ids)`
2. `agents/base.py` → `get_nist_controls(cve_id, cwe_ids)`
3. `agents/base.py` → `fetch_cve_by_id(cve_id)`
4. `tools/risk_scorer.py` → `calculate_device_risk_score(cves)`

**Agent can call these directly**:
- NVD: ✅ `fetch_cve_by_id()` works
- Enrichment: ✅ `orchestrator.enrich_cve()` works
- MITRE: ✅ `get_mitre_attack_info()` works (but direct CWE→MITRE)
- NIST: ✅ `get_nist_controls()` works (but direct CWE→NIST)
- Risk: ✅ `calculate_device_risk_score()` works

---

## PHẦN VII: CACHING STRATEGY (CURRENT)

| Data Layer | Storage | TTL | Refresh |
|-----------|---------|-----|---------|
| NVD API calls | None (realtime) | - | Realtime |
| Enrichment (EPSS/KEV) | SQLite (data/enrichment_cache.db) | 24h | Auto on hit |
| JSON mappings | In-memory (singleton) | ∞ | Manual reload |

**MISSING**:
- CWE XML cache (should refresh weekly)
- CAPEC XML cache (should refresh weekly)
- ATT&CK STIX cache (should refresh monthly)
- Heimdall CSV cache (should refresh monthly)

---

## KẾT LUẬN BƯỚC 1

**Pipeline hiện tại**:
- ✅ CVE/CWE/CPE/CVSS fetching (NVD API)
- ✅ EPSS/KEV/exploit enrichment
- ✅ Direct CWE → MITRE mapping
- ✅ Direct CWE → NIST mapping
- ❌ CWE → CAPEC → ATT&CK chain (MISSING)
- ❌ Intelligent ranking of attack paths
- ❌ Proper caching of XML/STIX data

**Modules ready for extension**:
1. `enrichment/orchestrator.py` — Add CAPEC/ATT&CK enrichment provider
2. `enrichment/schema.py` — Add capec_ids, attack_techniques, nist_controls fields
3. `cwe_mapper.py` — Add CWE→CAPEC lookup + extend with CAPEC data
4. `risk_scorer.py` — Add path_relevance_score layer

**Modules need NEW code**:
1. CAPEC XML loader + cache
2. ATT&CK STIX parser + cache
3. CAPEC→ATT&CK mapper
4. ATT&CK→NIST bidirectional mapper
5. Attack path ranking + filtering
6. Control deduplication logic

---

**READY FOR BƯỚC 2: GAP ANALYSIS**
