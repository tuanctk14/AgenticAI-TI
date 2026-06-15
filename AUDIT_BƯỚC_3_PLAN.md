# BƯỚC 3: PLAN BỔ SUNG — CHI TIẾT THỰC HIỆN

**Mục tiêu**: Liệt kê cụ thể TỰ TỪNG GAP, code cần thay đổi, không tạo abstraction dư thừa

---

## NGUYÊN TẮC BẮT BUỘC

✅ **KHÔNG tạo abstraction layer mới** nếu module hiện có chỗ extend được  
✅ **KHÔNG duplicate data model** — reuse UnifiedCVE schema, chỉ add field  
✅ **KHÔNG tạo service riêng** cho mỗi nguồn — gom vào enrichment pipeline  
✅ **ƯU TIÊN refactor/extend** chỗ gần đúng, không tạo mới

---

## PLAN CHI TIẾT TỪNG GAP

### Gap #1: CWE → CAPEC Mapping

**Status**: ⚠️ HIGH PRIORITY — Foundation cho G2, G3, G4

**Files**:

#### 1.1 NEW: `tools/capec_loader.py`

```python
"""
tools/capec_loader.py — Load + parse CWE/CAPEC XML dumps

Tasks:
1. Download CWE XML from cwe.mitre.org weekly
2. Download CAPEC XML from capec.mitre.org weekly
3. Parse CWE XML to extract: CWE-ID → <Related_Attack_Patterns> → CAPEC-IDs
4. Parse CAPEC XML to extract: CAPEC-ID → name, likelihood, abstraction_level

Caching: via tools/data_cache_manager.py (see G7)
"""

class CWEXMLParser:
    def load_from_file(xml_path: str) -> Dict[str, List[str]]:
        # Parse CWE XML → {"20": ["126", "3"], "22": ["3"]}
        # Field: <Related_Attack_Patterns><Related_Attack_Pattern CAPEC_ID="..."/>
        pass

class CAPECXMLParser:
    def load_from_file(xml_path: str) -> Dict[str, Dict]:
        # Parse CAPEC XML → 
        # {"126": {"name": "Forceful Browsing", "likelihood": "High", "abstraction": "Standard"}}
        # Fields: <Name>, <Likelihood_Of_Attack>, <CAPEC_Meta_Class> (or <Attack_Patterns>)
        pass

def cwe_to_capec_ids(cwe_id: str) -> List[str]:
    """Convenience: CWE-20 → ["126", "3"]"""
    # Lookup in parsed CWE XML
    pass

def get_capec_details(capec_id: str) -> Dict:
    """CAPEC-126 → {name, likelihood, abstraction, ...}"""
    # Lookup in parsed CAPEC XML
    pass
```

**Design Decisions**:
- Separate CWEXMLParser + CAPECXMLParser: each parses its own format
- Cache XML files locally (weekly refresh via data_cache_manager)
- NOT a class-based wrapper; simple functions + module-level cache
- No async (XML parsing is cheap, done once per week)

---

#### 1.2 EXTEND: `tools/cwe_mapper.py`

**Add method**:
```python
def cwe_to_capec_ids(cwe_id: str) -> List[str]:
    """
    Map CWE to CAPEC attack patterns.
    
    Args:
        cwe_id: "CWE-22" or "22"
    
    Returns:
        ["126", "3"] or []
    
    Uses capec_loader under the hood.
    """
    from tools.capec_loader import cwe_to_capec_ids as _cwe_to_capec_ids
    cwe_num = cwe_id.replace("CWE-", "")
    return _cwe_to_capec_ids(cwe_num)
```

**Rationale**: Keep `cwe_mapper.py` as single entry point for CWE lookups (CWE→CAPEC, CWE→MITRE, CWE→NIST)

---

#### 1.3 EXTEND: `enrichment/schema.py`

**Add field to UnifiedCVE**:
```python
class UnifiedCVE(BaseModel):
    # ... existing fields ...
    
    # NEW (G1)
    capec_ids: Optional[List[Dict]] = None  # [{"id": "126", "name": "Forceful Browsing", "likelihood": "High"}]
```

---

#### 1.4 NEW: `tools/data_cache_manager.py` (partial — full impl in G7)

**For now, just detect if XML files exist**:
```python
def has_capec_xml() -> bool:
    """Check if CAPEC XML cached locally"""
    return os.path.exists("data/capec_latest.xml")

def should_refresh_capec() -> bool:
    """Check if refresh needed (weekly)"""
    # Load data/cache_metadata.json → check last_refresh timestamp
    # Return True if > 7 days old
    pass
```

---

### Gap #2: CAPEC → ATT&CK Mapping

**Status**: ⚠️ HIGH PRIORITY — Depends on G1

**Files**:

#### 2.1 EXTEND: `tools/capec_loader.py`

**Add method**:
```python
class CAPECXMLParser:
    # ... existing ...
    
    def capec_to_attack_techniques(capec_id: str) -> List[str]:
        """
        Parse CAPEC XML <Taxonomy_Mappings> to extract ATT&CK T-codes.
        
        CAPEC XML structure:
        <Attack_Pattern ID="126">
          <Taxonomy_Mappings>
            <Taxonomy_Mapping>
              <Taxonomy_Name>ATT&amp;CK</Taxonomy_Name>
              <Entry_ID>T1190</Entry_ID>
            </Taxonomy_Mapping>
            <Taxonomy_Mapping>
              <Taxonomy_Name>NIST</Taxonomy_Name>
              <Entry_ID>AC-3</Entry_ID>
            </Taxonomy_Mapping>
          </Taxonomy_Mappings>
        </Attack_Pattern>
        
        Returns: ["T1190"] (filter only ATT&CK)
        """
        # Parse CAPEC XML, lookup CAPEC-ID, extract Taxonomy_Mappings
        # Filter by Taxonomy_Name == "ATT&CK"
        # Return Entry_ID list
        pass
```

---

#### 2.2 EXTEND: `tools/cwe_mapper.py`

**Add method**:
```python
def cwe_to_attack_techniques_via_capec(cwe_id: str) -> List[Dict]:
    """
    Full chain: CWE → CAPEC → ATT&CK
    
    Returns: [
        {"t_number": "T1190", "name": "Exploit Public-Facing Application", 
         "capec_id": "126", "capec_name": "Forceful Browsing"}
    ]
    """
    from tools.capec_loader import cwe_to_capec_ids, capec_to_attack_techniques
    
    capec_ids = cwe_to_capec_ids(cwe_id)
    results = []
    
    for capec_id in capec_ids:
        t_numbers = capec_to_attack_techniques(capec_id)
        for t_num in t_numbers:
            # Lookup T-number in MITRE data
            tech_data = self.mitre_data.get("techniques", {}).get(t_num, {})
            results.append({
                "t_number": t_num,
                "name": tech_data.get("name", f"Technique {t_num}"),
                "capec_id": capec_id,
                # ... more fields
            })
    
    return results
```

---

#### 2.3 EXTEND: `enrichment/schema.py`

**Modify `attack_techniques` field** (will be fully defined in G3):
```python
class UnifiedCVE(BaseModel):
    # ... existing fields ...
    
    # NEW (G2 + G3)
    attack_techniques: Optional[List[Dict]] = None  
    # [{"t_number": "T1190", "name": "...", "source": "cwe_capec_chain", ...}]
```

---

### Gap #3: ATT&CK STIX Resolution

**Status**: ⚠️ MEDIUM PRIORITY — Improves existing data, not blocker

**Files**:

#### 3.1 NEW: `tools/stix_resolver.py`

```python
"""
tools/stix_resolver.py — Resolve ATT&CK T-codes to full STIX data

MITRE provides STIX 2.1 JSON export in mitre/cti repo.
Our tools/cwe_mapper.py already loads mitre_attack.json (converted STIX).

This module improves resolution with better STIX parsing.
"""

class STIXResolver:
    def __init__(self):
        # Load mitre_attack.json
        self.techniques = self._load_techniques()
    
    def resolve_technique(self, t_number: str) -> Dict:
        """
        Resolve T1190 → full technique data
        
        Returns: {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactics": ["Initial Access"],
            "platforms": ["Linux", "Windows", "macOS"],
            "detection": "...",
            "mitigations": ["M1050", "M1051"],
            "description": "..."
        }
        """
        return self.techniques.get(t_number, {})
    
    def _load_techniques(self) -> Dict:
        """Load from mitre_attack.json"""
        # ... same as CWEMapper._load_mitre_data()
        pass
```

**Integration**: Import STIXResolver in `cwe_mapper.py`, use instead of direct JSON access.

---

#### 3.2 EXTEND: `enrichment/schema.py`

**Enhance `attack_techniques` field with more detail**:
```python
class AttackTechnique(BaseModel):
    """Single ATT&CK technique"""
    t_number: str  # "T1190"
    name: str
    tactics: List[str]  # ["Initial Access"]
    platforms: Optional[List[str]] = None
    detection: Optional[str] = None
    mitigations: Optional[List[str]] = None
    description: Optional[str] = None
    source: str  # "cwe_capec_chain", "direct_cwe_mitre"

class UnifiedCVE(BaseModel):
    # ... existing fields ...
    attack_techniques: Optional[List[AttackTechnique]] = None  # ← improved type
```

---

### Gap #4: ATT&CK → NIST Bidirectional Mapping

**Status**: ⚠️ HIGH PRIORITY — Needed for control recommendations

**Files**:

#### 4.1 NEW: `tools/attack_nist_mapper.py`

```python
"""
tools/attack_nist_mapper.py — Map ATT&CK techniques to NIST 800-53 controls

Source: center-for-threat-informed-defense/mappings-explorer
- Rev.4 (SP 800-53 Rev.4): mappings_attack_v13_nist-800-53-rev4.xlsx
- Rev.5 (SP 800-53 Rev.5): mappings_attack_v13_nist-800-53-rev5.xlsx

We use Rev.5 (current).

Data format (from JSON export of XLSX):
{
  "technique_id": "T1190",
  "technique_name": "Exploit Public-Facing Application",
  "controls": [
    {"control_id": "SI-10", "control_name": "Information Input Validation"},
    {"control_id": "DE-3", "control_name": "Analyze User-Generated Content"}
  ]
}
"""

class AttackNISTMapper:
    def __init__(self):
        self.mappings = self._load_mappings()
    
    def technique_to_nist_controls(self, t_number: str) -> List[Dict]:
        """
        T1190 → [{"control": "SI-10", "name": "...", "type": "Preventive"}, ...]
        """
        controls = self.mappings.get(t_number, {}).get("controls", [])
        
        # Enhance with control details from nist_controls.json
        from tools.cwe_mapper import _get_mapper
        mapper = _get_mapper()
        
        results = []
        for ctrl in controls:
            ctrl_data = mapper.nist_data.get("controls", {}).get(ctrl["control"], {})
            results.append({
                "control": ctrl["control"],
                "name": ctrl_data.get("title", ctrl_data.get("name", "")),
                "type": ctrl.get("type", "Unknown"),
                "description": ctrl_data.get("description", "")
            })
        
        return results
    
    def _load_mappings(self) -> Dict:
        """
        Load from data/attack_nist_mappings_rev5.json
        Format: {"T1190": {"controls": [...]}, ...}
        """
        # Load JSON file, cache in memory
        pass
```

---

#### 4.2 NEW: `tools/attack_nist_cache.py` (placeholder, full impl in G7)

```python
def should_refresh_attack_nist() -> bool:
    """Check if mapping file needs refresh (monthly)"""
    pass

def has_attack_nist_mappings() -> bool:
    """Check if mappings JSON exists"""
    pass
```

---

#### 4.3 EXTEND: `enrichment/schema.py`

**Add NIST controls to UnifiedCVE**:
```python
class NISTControl(BaseModel):
    """Single NIST control with source tracking"""
    control_id: str  # "SI-10"
    name: str
    family: str  # "SI"
    type: Optional[str] = None  # "Preventive", "Detective"
    description: Optional[str] = None
    source: str  # "attack_nist", "cwe_nist_fallback"
    weight: float = 1.0  # Used in aggregation (G9)

class UnifiedCVE(BaseModel):
    # ... existing fields ...
    nist_controls: Optional[List[NISTControl]] = None  # ← NEW
```

---

### Gap #5: CWE → NIST Fallback

**Status**: 🟢 LOW PRIORITY — Fallback only, not critical path

**Files**:

#### 5.1 NEW: `tools/heimdall_cwe_nist_mapper.py`

```python
"""
tools/heimdall_cwe_nist_mapper.py — Load deprecated Heimdall CWE-NIST mapping

Source: https://github.com/mitre/heimdall_tools/blob/master/lib/data/cwe-nist-mapping.csv
Format: CWE,NIST (e.g., "CWE-20,SI-10")

CAVEAT: Mapping is GENERIC, not threat-informed. Use as FALLBACK only.
PRIMARY: CWE → CAPEC → ATT&CK → NIST (via attack_nist_mapper)
"""

class HeimdallCWENISTMapper:
    def __init__(self):
        self.mappings = self._load_csv()
    
    def cwe_to_nist_controls(self, cwe_id: str) -> List[str]:
        """
        CWE-20 → ["SI-10", "AC-3"]
        
        Returns control IDs only (use cwe_mapper to get details)
        """
        cwe_num = cwe_id.replace("CWE-", "")
        return self.mappings.get(cwe_num, [])
    
    def _load_csv(self) -> Dict[str, List[str]]:
        """Load CSV → {"20": ["SI-10", "AC-3"], ...}"""
        pass
```

**Integration**: Call this as fallback in new `cwe_mapper.cwe_to_nist_with_fallback()` method (see next).

---

#### 5.2 EXTEND: `tools/cwe_mapper.py`

**Add fallback method**:
```python
def cwe_to_nist_with_fallback(cwe_id: str, use_capec: bool = True) -> List[Dict]:
    """
    Get NIST controls for CWE with intelligent fallback.
    
    Priority:
    1. CWE → CAPEC → ATT&CK → NIST (if use_capec=True)
    2. Fallback: CWE → NIST (Heimdall CSV, confidence=0.6)
    
    Returns: [{"control": "SI-10", "confidence": 0.95, "source": "attack_chain"}]
    """
    results = []
    
    if use_capec:
        # Try primary path
        from tools.capec_loader import cwe_to_capec_ids
        from tools.attack_nist_mapper import AttackNISTMapper
        
        capec_ids = cwe_to_capec_ids(cwe_id)
        if capec_ids:
            mapper = AttackNISTMapper()
            for t_num in self.cwe_to_attack_techniques_via_capec(cwe_id):
                controls = mapper.technique_to_nist_controls(t_num["t_number"])
                for ctrl in controls:
                    results.append({
                        "control": ctrl["control"],
                        "confidence": 0.95,  # High confidence from ATT&CK chain
                        "source": "attack_chain"
                    })
    
    # If no results or use_capec=False, try fallback
    if not results:
        from tools.heimdall_cwe_nist_mapper import HeimdallCWENISTMapper
        heimdall = HeimdallCWENISTMapper()
        ctrl_ids = heimdall.cwe_to_nist_controls(cwe_id)
        for ctrl_id in ctrl_ids:
            results.append({
                "control": ctrl_id,
                "confidence": 0.6,  # Lower confidence for fallback
                "source": "heimdall"
            })
    
    # Deduplicate by control ID
    seen = {}
    for r in results:
        ctrl = r["control"]
        if ctrl not in seen or r["confidence"] > seen[ctrl]["confidence"]:
            seen[ctrl] = r
    
    return list(seen.values())
```

---

### Gap #6: UnifiedCVE Schema Extension

**Status**: 🟢 DONE (via G1-G5)

Fields added in previous gaps:
- G1: `capec_ids`
- G2-G3: `attack_techniques`
- G4: `nist_controls`

---

### Gap #7: Caching Strategy for XML/JSON Dumps

**Status**: ⚠️ MEDIUM PRIORITY — Infrastructure, not blocker

**Files**:

#### 7.1 NEW: `tools/data_cache_manager.py`

```python
"""
tools/data_cache_manager.py — Unified cache management for external data

Manages:
- CWE XML (cwe.mitre.org, ~3MB, weekly)
- CAPEC XML (capec.mitre.org, ~2MB, weekly)
- MITRE STIX JSON (mitre/cti repo, ~50MB, monthly)
- Heimdall CSV (GitHub, small, monthly)

Strategy:
- Check cache_metadata.json for last refresh timestamp
- If age > TTL, trigger download
- Downloads happen async on first request (on-demand)
"""

import os
import json
from datetime import datetime, timedelta
from typing import Optional

class DataCacheManager:
    CACHE_DIR = "data/cache"
    METADATA_FILE = "data/cache_metadata.json"
    
    SOURCES = {
        "cwe_xml": {
            "url": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
            "local_path": "data/cache/cwec_latest.xml",
            "ttl_days": 7,
            "last_refresh": None
        },
        "capec_xml": {
            "url": "https://capec.mitre.org/data/xml/capec_latest.xml",
            "local_path": "data/cache/capec_latest.xml",
            "ttl_days": 7,
            "last_refresh": None
        },
        "attack_nist_mappings": {
            "url": "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/src/data/mappings_attack_v13_nist-800-53-rev5.json",
            "local_path": "data/cache/attack_nist_mappings_rev5.json",
            "ttl_days": 30,
            "last_refresh": None
        },
        "heimdall_csv": {
            "url": "https://raw.githubusercontent.com/mitre/heimdall_tools/master/lib/data/cwe-nist-mapping.csv",
            "local_path": "data/cache/cwe_nist_mapping.csv",
            "ttl_days": 30,
            "last_refresh": None
        }
    }
    
    def __init__(self):
        self._load_metadata()
        os.makedirs(self.CACHE_DIR, exist_ok=True)
    
    def _load_metadata(self):
        """Load cache_metadata.json"""
        if os.path.exists(self.METADATA_FILE):
            with open(self.METADATA_FILE) as f:
                meta = json.load(f)
                for source, data in self.SOURCES.items():
                    if source in meta:
                        data["last_refresh"] = datetime.fromisoformat(meta[source].get("last_refresh", "1900-01-01"))
        
    def _save_metadata(self):
        """Save cache_metadata.json"""
        meta = {}
        for source, data in self.SOURCES.items():
            meta[source] = {
                "last_refresh": data.get("last_refresh", datetime.fromisoformat("1900-01-01")).isoformat(),
                "ttl_days": data["ttl_days"]
            }
        with open(self.METADATA_FILE, "w") as f:
            json.dump(meta, f, indent=2)
    
    def should_refresh(self, source: str) -> bool:
        """Check if source needs refresh"""
        if source not in self.SOURCES:
            return False
        
        data = self.SOURCES[source]
        ttl = timedelta(days=data["ttl_days"])
        last_refresh = data.get("last_refresh")
        
        if last_refresh is None:
            return True  # Never downloaded
        
        return datetime.utcnow() - last_refresh > ttl
    
    def has_cache(self, source: str) -> bool:
        """Check if source is cached locally"""
        if source not in self.SOURCES:
            return False
        return os.path.exists(self.SOURCES[source]["local_path"])
    
    async def ensure_fresh(self, source: str):
        """
        Async: download if not fresh.
        Call this at module load time (lazy).
        """
        if not self.should_refresh(source):
            return
        
        print(f"[CacheManager] Refreshing {source}...")
        # Download logic (requests.get, save to local_path)
        # self._download(source)
        # self.SOURCES[source]["last_refresh"] = datetime.utcnow()
        # self._save_metadata()
        pass
```

**Usage in loaders**:
```python
# In capec_loader.py
async def load_capec_xml() -> Dict:
    cache_mgr = DataCacheManager()
    await cache_mgr.ensure_fresh("capec_xml")  # Download if needed
    
    xml_path = cache_mgr.SOURCES["capec_xml"]["local_path"]
    return _parse_capec_xml_file(xml_path)
```

---

### Gap #8: Ranking & Filtering Logic

**Status**: ⚠️ HIGH PRIORITY — Core of ranking requirement

**Files**:

#### 8.1 NEW: `tools/attack_path_ranker.py`

```python
"""
tools/attack_path_ranker.py — Rank attack paths (CWE→CAPEC→ATT&CK) by relevance

Implements BƯỚC 4 scoring:
- CẤP 1: CVE priority score (0.35 CVSS + 0.30 KEV + 0.25 EPSS + 0.10 relevance)
- CẤP 2: Attack path relevance score (0.40 CAPEC strength + 0.30 directness + 0.20 tactic + 0.10 abstraction)
- Hard filtering: Remove deprecated CAPEC, Meta-only (unless necessary), domain mismatches

Returns: Top-K (default K=5) ranked paths per CVE
"""

from typing import List, Dict, Optional
from tools.enrichment.schema import UnifiedCVE

class AttackPathRanker:
    
    @staticmethod
    def calculate_cve_priority_score(cve: UnifiedCVE) -> Tuple[float, str]:
        """
        CẤP 1: CVE priority score (0-1)
        
        Score = 0.35 × norm_cvss + 0.30 × kev_flag + 0.25 × epss + 0.10 × relevance
        Tier:
          >= 0.7: critical
          0.4-0.69: standard
          < 0.4: low (skip deep enrichment)
        """
        
        # Extract signals
        cvss = cve.cvss.score.value if cve.cvss else 0.0
        norm_cvss = min(cvss / 10.0, 1.0)  # Normalize to 0-1
        
        kev_flag = 1.0 if (cve.kev and cve.kev.listed) else 0.0
        
        epss = cve.epss.score if cve.epss else 0.0  # Already 0-1
        
        # Relevance: assume always 0.8 (can be enhanced with asset context)
        relevance = 0.8
        
        score = (
            0.35 * norm_cvss +
            0.30 * kev_flag +
            0.25 * epss +
            0.10 * relevance
        )
        
        if score >= 0.7:
            tier = "critical"
        elif score >= 0.4:
            tier = "standard"
        else:
            tier = "low"
        
        return (score, tier)
    
    @staticmethod
    def rank_attack_paths(cve: UnifiedCVE, max_paths: int = 5) -> List[Dict]:
        """
        CẤP 2: Rank attack paths (CWE→CAPEC→ATT&CK) by relevance
        
        Inputs:
        - cve.cwe_ids: ["20", "22"]
        - cve.capec_ids: [{"id": "126", "likelihood": "High"}, ...]
        - cve.attack_techniques: [{"t_number": "T1190", ...}, ...]
        
        Algorithm:
        1. Hard filter: Remove deprecated CAPEC, Meta-only, domain mismatches
        2. Score each path: 0.40 capec_strength + 0.30 directness + 0.20 tactic + 0.10 abstraction
        3. Sort by score descending
        4. Return top-K paths
        
        Returns: [
            {
                "rank": 1,
                "relevance_score": 0.78,
                "cwe": "CWE-20",
                "capec": {"id": "126", "name": "Forceful Browsing"},
                "attack_technique": {"t_number": "T1190", "name": "...", "tactic": "Initial Access"},
                "reasoning": "High-likelihood CAPEC directly mapped to web exploitation technique"
            },
            ...
        ]
        """
        
        # Step 1: Hard filter
        valid_paths = []
        
        if not cve.attack_techniques:
            return []
        
        for tech in cve.attack_techniques:
            # Filter 1: Domain check (skip if not applicable)
            # TODO: Implement based on CVE context (web-facing, network, etc.)
            
            # Filter 2: Tactic relevance
            # RCE CVE should prefer Initial Access, Execution tactics
            # Not Persistence or Defense Evasion
            
            valid_paths.append({
                "technique": tech,
                "capec": tech.get("capec_id"),  # Link back to CAPEC
                "cwe": tech.get("cwe"),  # Link back to CWE
            })
        
        # Step 2: Score each path
        scored_paths = []
        for path in valid_paths:
            tech = path["technique"]
            capec_id = path["capec"]
            
            # Get CAPEC strength (likelihood: High=1.0, Medium=0.6, Low=0.3)
            capec_strength = 0.8  # TODO: fetch from cve.capec_ids
            
            # Directness: direct CAPEC→technique mapping = 1.0, via sub = 0.6
            directness = 1.0  # TODO: check CAPEC taxonomy structure
            
            # Tactic relevance (heuristic based on CVE type)
            tactic = tech.get("tactic", "Unknown")
            if tactic in ["Initial Access", "Execution"]:  # High priority for RCE-like
                tactic_relevance = 1.0
            elif tactic in ["Persistence", "Privilege Escalation"]:
                tactic_relevance = 0.7
            else:
                tactic_relevance = 0.5
            
            # Abstraction penalty: Meta=0.2, Category=0.4, Standard=0.8, Detailed=1.0
            abstraction_level = "Standard"  # TODO: fetch from CAPEC data
            abstraction_map = {"Meta": 0.2, "Category": 0.4, "Standard": 0.8, "Detailed": 1.0}
            abstraction_penalty = abstraction_map.get(abstraction_level, 0.5)
            
            score = (
                0.40 * capec_strength +
                0.30 * directness +
                0.20 * tactic_relevance +
                0.10 * abstraction_penalty
            )
            
            scored_paths.append({
                "score": score,
                "path": path,
                "reasoning": f"{tactic} technique with {abstraction_level} CAPEC pattern"
            })
        
        # Step 3: Sort + return top-K
        scored_paths.sort(key=lambda x: x["score"], reverse=True)
        
        results = []
        for rank, item in enumerate(scored_paths[:max_paths], 1):
            results.append({
                "rank": rank,
                "relevance_score": item["score"],
                "cwe": item["path"].get("cwe"),
                "capec": item["path"].get("capec"),
                "attack_technique": item["path"]["technique"],
                "reasoning": item["reasoning"]
            })
        
        return results
    
    @staticmethod
    def filter_noise(ranked_paths: List[Dict], top_k: int = 5) -> List[Dict]:
        """
        Apply hard cutoff: keep only top-K paths.
        Removes noise from "fan-out" explosion (1 CWE → 10-20 techniques).
        """
        return ranked_paths[:top_k]
```

---

#### 8.2 EXTEND: `enrichment/schema.py`

**Add ranked paths to UnifiedCVE**:
```python
class RankedAttackPath(BaseModel):
    """Single ranked attack path"""
    rank: int
    relevance_score: float  # 0-1
    cwe: str
    capec: Optional[Dict] = None  # {"id": "126", "name": "..."}
    attack_technique: Optional[Dict] = None  # From G2-G3
    nist_controls: Optional[List[Dict]] = None  # Added by aggregator (G9)
    reasoning: str

class UnifiedCVE(BaseModel):
    # ... existing fields ...
    attack_paths: Optional[List[RankedAttackPath]] = None  # ← NEW
    filtered_count: int = 0  # How many paths were filtered out
```

---

#### 8.3 EXTEND: `enrichment/orchestrator.py`

**Call ranker in enrichment flow**:
```python
async def enrich_cve(self, cve_id: str) -> UnifiedCVE:
    # ... existing: NVD fetch, EPSS/KEV/Vulners ...
    
    # NEW: Calculate CVE priority (early filter)
    from tools.attack_path_ranker import AttackPathRanker
    priority_score, priority_tier = AttackPathRanker.calculate_cve_priority_score(unified)
    
    if priority_score < 0.4:  # Skip low-priority CVEs
        print(f"[Enrichment] Skipping {cve_id}: low priority ({priority_score:.2f})")
        return unified  # Return with basic data only
    
    # NEW: Enrich with CWE→CAPEC→ATT&CK→NIST chain
    # (Will be added in next commits, after G1-G5 are ready)
    
    # NEW: Rank attack paths
    ranked_paths = AttackPathRanker.rank_attack_paths(unified)
    unified.attack_paths = ranked_paths[:5]  # Top-5 only
    unified.filtered_count = len(ranked_paths) - 5
    
    return unified
```

---

### Gap #9: Control Deduplication

**Status**: 🟡 MEDIUM PRIORITY — Post-process of G8

**Files**:

#### 9.1 NEW: `tools/control_aggregator.py`

```python
"""
tools/control_aggregator.py — Aggregate NIST controls from multiple attack paths

Problem: Multiple attack paths map to same controls (SI-10, SC-7, AC-3 appear often)

Solution:
- For each control, count how many techniques map to it
- Weight = count × avg(relevance_score of those techniques)
- Sort controls by weight descending
- Return top 10-15 controls
"""

from typing import List, Dict

class ControlAggregator:
    
    @staticmethod
    def aggregate_controls(ranked_paths: List[Dict], top_k: int = 12) -> List[Dict]:
        """
        Deduplicate + weight NIST controls across attack paths.
        
        Input:
        [
            {
                "rank": 1,
                "relevance_score": 0.78,
                "nist_controls": [
                    {"control": "SI-10", "name": "...", "type": "Preventive"},
                    {"control": "SC-7", "name": "...", "type": "Detective"}
                ]
            },
            ...
        ]
        
        Process:
        1. For each path, collect controls
        2. Track: control → [path_relevance_scores]
        3. Weight = count × avg(relevance_scores)
        4. Sort by weight descending
        5. Return top-K
        
        Output:
        [
            {
                "control": "SI-10",
                "name": "Information Input Validation",
                "weight": 4.2,  # count=3, avg_relevance=1.4
                "type": "Preventive",
                "reason": "covers 3 of top 5 paths",
                "technique_count": 3
            },
            ...
        ]
        """
        
        if not ranked_paths:
            return []
        
        # Collect controls from all paths
        control_stats = {}  # control_id → {"weights": [...], "name": "...", "type": "..."}
        
        for path in ranked_paths:
            relevance = path.get("relevance_score", 0.5)
            controls = path.get("nist_controls", [])
            
            for ctrl in controls:
                ctrl_id = ctrl["control"]
                
                if ctrl_id not in control_stats:
                    control_stats[ctrl_id] = {
                        "weights": [],
                        "name": ctrl.get("name", ""),
                        "type": ctrl.get("type", ""),
                        "technique_count": 0
                    }
                
                control_stats[ctrl_id]["weights"].append(relevance)
                control_stats[ctrl_id]["technique_count"] += 1
        
        # Calculate weights
        results = []
        for ctrl_id, stats in control_stats.items():
            count = len(stats["weights"])
            avg_relevance = sum(stats["weights"]) / count
            weight = count * avg_relevance
            
            results.append({
                "control": ctrl_id,
                "name": stats["name"],
                "weight": weight,
                "type": stats["type"],
                "reason": f"covers {count} attack path(s)",
                "technique_count": stats["technique_count"]
            })
        
        # Sort by weight descending
        results.sort(key=lambda x: x["weight"], reverse=True)
        
        return results[:top_k]
```

---

#### 9.2 EXTEND: `tools/attack_path_ranker.py`

**Call aggregator after path ranking**:
```python
# In AttackPathRanker, add method:

@staticmethod
def finalize_with_aggregated_controls(ranked_paths: List[Dict], top_k_controls: int = 12) -> Dict:
    """
    Post-process: Rank paths, then aggregate controls.
    
    Returns: {
        "attack_paths": [...],
        "recommended_controls": [...],
        "filtered_count": int
    }
    """
    from tools.control_aggregator import ControlAggregator
    
    # Rank paths
    ranked_paths = AttackPathRanker.rank_attack_paths(..., max_paths=10)  # Get more for aggregation
    
    # Aggregate controls
    agg_controls = ControlAggregator.aggregate_controls(ranked_paths, top_k=12)
    
    return {
        "attack_paths": ranked_paths[:5],  # Top-5 for output
        "recommended_controls": agg_controls,
        "filtered_paths": len(ranked_paths) - 5
    }
```

---

### Gap #10: CVE Priority Scoring

**Status**: ✅ ALREADY DONE (in G8)

See `AttackPathRanker.calculate_cve_priority_score()` in Gap #8.1

---

## INTEGRATION SEQUENCE (ORDER OF IMPLEMENTATION)

**Phase 1: Foundation (G1-G2)**
1. Implement `capec_loader.py` (CWE XML + CAPEC XML parsing)
2. Extend `cwe_mapper.py` with `cwe_to_capec_ids()` + `cwe_to_attack_techniques_via_capec()`
3. Extend `schema.py` with CAPEC fields

**Phase 2: NIST Mapping (G3-G5)**
4. Implement `stix_resolver.py` (improve ATT&CK lookup)
5. Implement `attack_nist_mapper.py` (ATT&CK → NIST)
6. Implement `heimdall_cwe_nist_mapper.py` (CWE → NIST fallback)
7. Extend `cwe_mapper.py` with `cwe_to_nist_with_fallback()`

**Phase 3: Ranking (G8-G10)**
8. Implement `attack_path_ranker.py` (all scoring + ranking)
9. Implement `control_aggregator.py` (control dedup)
10. Extend `enrichment/orchestrator.py` to call ranking in flow

**Phase 4: Infrastructure (G7)**
11. Implement `data_cache_manager.py` (cache refresh strategy)
12. Update `config.py` with cache TTL settings

---

## READY FOR BƯỚC 4: RANKING/FILTERING LOGIC DESIGN

**NEXT: Receive confirmation before implementation**
