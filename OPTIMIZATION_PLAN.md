# System Optimization Plan - Execution Checklist

**Overall Goal:** Reduce LOC by 300, improve performance by 20-40%, enhance maintainability  
**Timeline:** 2-3 weeks (4 phases)  
**Status:** Ready to Execute

---

## PHASE 1: Quick Wins (2-3 hours) 🚀

### Task 1.1: Remove Remediation Duplication
**Priority:** 🔴 HIGH | **Effort:** ⏱️ 30 min | **Impact:** -50 LOC, single source of truth

**Current State:**
- `main.py` lines 99-147: `_get_remediation_steps()` 
- `tools/remediation_framework.py`: `get_remediation_actions()`
- Both do same thing with different names

**Action:**
```python
# In main.py, replace _get_remediation_steps() calls with:
from tools.remediation_framework import get_remediation_actions

# Then remove entire _get_remediation_steps() function from main.py
```

**Verification:**
- [ ] Run Menu 2 report generation - remediation section renders correctly
- [ ] Run Menu 4 chat - remediation recommendations appear

---

### Task 1.2: Consolidate Print Functions
**Priority:** 🔴 HIGH | **Effort:** ⏱️ 1 hour | **Impact:** -250 LOC, single parse logic

**Current State:**
```
main.py:
- _print_chat_response() (lines 150-296) - 150 LOC
- _print_summary() (lines 244-450) - 200 LOC
- Both extract CVE/IOC/device/remediation details
- 95% code duplication
```

**Action:**
1. Create new function in `utils/output_formatter.py`:
```python
def format_response_output(result: dict, full_details: bool = True) -> tuple[str, str, str, str]:
    """
    Build formatted output sections for CVEs, IOCs, Devices, Remediation.
    Returns: (cve_section, ioc_section, device_section, remediation_section)
    """
    cve_text = _format_cves(result.get("cves", []))
    ioc_text = _format_indicators(result.get("indicators", []))
    device_text = _format_devices(result.get("devices", []))
    remediation_text = _format_remediation(result.get("remediation", []))
    
    return cve_text, ioc_text, device_text, remediation_text
```

2. Update main.py:
```python
# Replace _print_chat_response() and _print_summary()
from utils.output_formatter import format_response_output

cve_sec, ioc_sec, dev_sec, rem_sec = format_response_output(result)
print(cve_sec)
print(ioc_sec)
# ...
```

**Verification:**
- [ ] Menu 1 output identical to before
- [ ] Menu 2 report has correct formatting
- [ ] Menu 4 chat shows results properly
- [ ] No regressions in styling/colors

---

### Task 1.3: Fix CVE ID Regex Bug
**Priority:** 🟡 MEDIUM | **Effort:** ⏱️ 15 min | **Impact:** Better input validation

**Current State:**
```python
# agents/base.py line 1139
if re.search(r'CVE-\d{4}-\d{4,}', text):
# Accepts CVE-2099-99999 (future year)
```

**Action:**
```python
# Replace with:
if re.search(r'CVE-[12]\d{3}-\d{4,}', text):
# Only accepts 1000-2999, covers 1000 years
```

**Files to Update:**
- [ ] `agents/base.py` line 1139
- [ ] `tools/cve_parser.py` (if similar regex exists)

**Verification:**
- [ ] CVE-2026-8500 matches ✓
- [ ] CVE-2021-44228 matches ✓
- [ ] CVE-9999-99999 doesn't match ✓

---

### Task 1.4: Move Late Imports to Top-Level
**Priority:** 🟡 MEDIUM | **Effort:** ⏱️ 20 min | **Impact:** Better dependency tracking

**Current State:**
```python
# main.py lines 608-609
def run_query(...):
    from tools.remediation_framework import get_remediation_actions  # LATE
```

**Action:**
Move all function-level imports to module level (top of file)

**Files:**
- [ ] `main.py` - scan for `from ... import` inside functions
- [ ] `agents/base.py` - scan for `from ... import` inside handler functions

**Verification:**
- [ ] `python -m py_compile main.py` succeeds
- [ ] All imports resolved at startup

---

## PHASE 2: Performance & Stability (1-2 days)

### Task 2.1: Add CMDB Software Indexing
**Priority:** 🔴 HIGH | **Effort:** ⏱️ 2 hours | **Impact:** +40% matching speed

**Current State:**
```python
# tools/cmdb.py (O(n*m*k) complexity)
for device in devices:
    for cve in cves:
        for software in device_software:
            if match(software, cve_product): ...
```

**Action:**
1. Create index at startup in `cmdb.py`:
```python
def build_software_index(devices: list) -> dict:
    """
    Build (vendor, product) → [device_ids] lookup table.
    
    Example:
    {
        ("apache", "http_server"): ["dev-001", "dev-003"],
        ("mysql", "mysql"): ["dev-004"],
    }
    """
    index = defaultdict(list)
    for device in devices:
        for software in device.get("software", []):
            vendor, product = _normalize_software(software)
            key = (vendor, product)
            index[key].append(device["device_id"])
    return dict(index)

# Usage:
software_index = build_software_index(devices)

# In matching:
cve_vendor, cve_product = _extract_cve_software(cve)
matching_devices = software_index.get((cve_vendor, cve_product), [])
```

**Verification:**
- [ ] Benchmark matching speed (before/after)
- [ ] Run Menu 1 - device matching completes faster
- [ ] Results still accurate (same devices matched)

---

### Task 2.2: Implement NVD API Caching
**Priority:** 🟡 MEDIUM | **Effort:** ⏱️ 1.5 hours | **Impact:** +50% API throughput

**Current State:**
```python
# tools/nvd_client.py
def fetch_nvd_cves(...):
    # Fresh API call every time
    resp = requests.get(base_url, params=params, timeout=30)
```

**Action:**
1. Add caching layer:
```python
from functools import lru_cache
from datetime import datetime, timedelta

class NVDCache:
    def __init__(self, ttl_seconds=3600):
        self.cache = {}
        self.ttl = ttl_seconds
    
    def get(self, key: str):
        if key in self.cache:
            data, timestamp = self.cache[key]
            if datetime.now() - timestamp < timedelta(seconds=self.ttl):
                return data
        return None
    
    def set(self, key: str, data):
        self.cache[key] = (data, datetime.now())

# Global cache
nvd_cache = NVDCache(ttl_seconds=3600)  # 1 hour TTL

def fetch_nvd_cves(cve_id: str, ...):
    cache_key = f"nvd_{cve_id}"
    
    # Check cache first
    cached = nvd_cache.get(cache_key)
    if cached:
        print(f"  [NVD-CACHE] Hit: {cve_id}")
        return cached
    
    # Fetch from API
    result = requests.get(...)
    
    # Store in cache
    nvd_cache.set(cache_key, result)
    return result
```

**Verification:**
- [ ] First Menu 1 query: uses NVD API (slower)
- [ ] Second Menu 1 query with same CVEs: uses cache (fast)
- [ ] Log shows "[NVD-CACHE] Hit" messages

---

### Task 2.3: Create date_range_utils Module
**Priority:** 🟡 MEDIUM | **Effort:** ⏱️ 1 hour | **Impact:** Single date logic

**Current State:**
```
Date parsing scattered in:
- main.py lines 516-586 (user input)
- nvd_client.py lines 78-97 (NVD formatting)
- report_generator.py lines 94-100 (report filtering)
```

**Action:**
1. Create `utils/date_range_utils.py`:
```python
from datetime import datetime, timedelta, timezone

def parse_user_date_range(start_str: str, end_str: str) -> tuple[str, str]:
    """Parse user input (flexible) to ISO 8601 strings."""
    # Support: "2026-05-01", "May 1", "1 week ago", etc.
    start_dt = dateparser.parse(start_str)
    end_dt = dateparser.parse(end_str)
    return start_dt.isoformat(), end_dt.isoformat()

def get_default_date_range(days_back: int = 30) -> tuple[str, str]:
    """Return (start_date, end_date) for last N days."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days_back)
    return start.strftime("%Y-%m-%dT%H:%M:%S.000"), end.strftime("%Y-%m-%dT%H:%M:%S.000")

def ensure_full_day_coverage(date_str: str) -> str:
    """Ensure end_date has 23:59:59 for full day coverage."""
    if "T00:00:00" in date_str:
        return date_str.replace("T00:00:00.000", "T23:59:59.000")
    return date_str

def filter_by_date_range(items: list, start_date: str, end_date: str, date_field: str = "published") -> list:
    """Filter items by date range."""
    items_in_range = []
    for item in items:
        item_date = dateparser.parse(item.get(date_field))
        if start_date <= item_date.isoformat() <= end_date:
            items_in_range.append(item)
    return items_in_range
```

2. Update imports in main.py, nvd_client.py, report_generator.py

**Verification:**
- [ ] Menu 2 date range parsing works
- [ ] NVD API receives correct date format
- [ ] Report filtering shows correct CVEs

---

### Task 2.4: Add OpenCTI Pagination
**Priority:** 🟡 MEDIUM | **Effort:** ⏱️ 1.5 hours | **Impact:** Handle large datasets

**Current State:**
```python
# tools/opencti_client.py (no pagination)
query = {...}
result = client.execute(query)
# Returns max_results, truncates large datasets
```

**Action:**
Implement cursor-based pagination (if not already done)

**Verification:**
- [ ] Search for IOCs returns all results (test with large dataset)
- [ ] No timeout on large OpenCTI queries

---

## PHASE 3: Architecture & Refactoring (1 week)

### Task 3.1: Create IterationManager Class
**Priority:** 🔴 HIGH | **Effort:** ⏱️ 2 hours | **Impact:** Cleaner state, better debugging

**Create:** `utils/iteration_manager.py`

```python
class IterationManager:
    """Centralized agent iteration tracking."""
    
    def __init__(self, max_iterations: int = 5):
        self.max_iterations = max_iterations
        self.agent_iterations = {}  # agent_name → count
    
    def increment(self, agent_name: str) -> int:
        """Increment and return current iteration count."""
        self.agent_iterations[agent_name] = self.agent_iterations.get(agent_name, 0) + 1
        return self.agent_iterations[agent_name]
    
    def get_count(self, agent_name: str) -> int:
        return self.agent_iterations.get(agent_name, 0)
    
    def is_complete(self, agent_name: str) -> bool:
        return self.get_count(agent_name) >= self.max_iterations
    
    def reset(self):
        self.agent_iterations.clear()
    
    def get_state_dict(self) -> dict:
        """Export to state for persistence."""
        return self.agent_iterations.copy()
    
    def from_state_dict(self, data: dict):
        """Restore from state."""
        self.agent_iterations = data.copy()
```

**Update agents/base.py:**
```python
# Old (lines 811-821):
iter_key = f"{agent_name.split('_')[1]}_iterations"
state[iter_key] = current_iter + 1
if current_iter >= MAX_ITERATIONS: state[f"{...}_completed"] = True

# New:
from utils.iteration_manager import IterationManager

iteration_mgr = IterationManager(max_iterations=5)
current = iteration_mgr.increment(agent_name)
if iteration_mgr.is_complete(agent_name):
    # Agent limit exceeded
```

**Verification:**
- [ ] Menu 1 query: iteration count increases correctly
- [ ] Exceeding max iterations shows error
- [ ] Reset clears iteration history

---

### Task 3.2: Create LLM Message Builder Utility
**Priority:** 🔴 HIGH | **Effort:** ⏱️ 2 hours | **Impact:** -200 LOC, single message logic

**Create:** `utils/message_builder.py`

```python
def build_agent_messages(
    state: dict,
    agent_name: str,
    observations: dict = None
) -> list[dict]:
    """
    Build LLM messages for agent call.
    
    Returns list of {"role": "user/assistant", "content": "..."}
    """
    messages = []
    
    # 1. Include conversation history (last 5 turns)
    history = state.get("conversation_history", [])[-5:]
    for msg in history:
        messages.append({
            "role": msg.get("role", "user"),
            "content": msg.get("content", "")
        })
    
    # 2. Build observation text from state
    observation_text = _build_observation_text(state, agent_name, observations)
    messages.append({"role": "user", "content": observation_text})
    
    # 3. Add iteration context
    iteration_num = state.get(f"{agent_name}_iterations", 0)
    if iteration_num > 1:
        messages.append({
            "role": "assistant",
            "content": f"Note: This is iteration {iteration_num}. Previous attempts may have failed."
        })
    
    return messages

def _build_observation_text(state: dict, agent_name: str, observations: dict) -> str:
    """Build observation context from state."""
    parts = []
    
    # Add CVE context if relevant
    if "collected_cves" in state:
        parts.append(f"CVEs found: {len(state['collected_cves'])}")
    
    # Add device context
    if "matched_devices" in state:
        parts.append(f"Devices affected: {len(state['matched_devices'])}")
    
    # Add custom observations
    if observations:
        parts.extend([f"{k}: {v}" for k, v in observations.items()])
    
    return "\n".join(parts)
```

**Update agents/base.py:**
```python
# Replace 8 agent call points with:
from utils.message_builder import build_agent_messages

messages = build_agent_messages(state, "agent_ti", observations={"query": query})
result = llm.invoke(messages)
```

**Verification:**
- [ ] All agent calls work (Menu 1, 2, 4)
- [ ] Message format identical to before
- [ ] Conversation history preserved

---

### Task 3.3: Split cve_parser.py
**Priority:** 🟡 MEDIUM | **Effort:** ⏱️ 3 hours | **Impact:** Better modularity

**Current:** 684 LOC in single file  
**Target:** Split into 3 focused modules

**New Structure:**
```
tools/
  ├─ cpe_parser.py (150 LOC)
  │  ├─ CPEParser class
  │  ├─ extract_cpe_from_configurations()
  │  └─ parse_version_range()
  │
  ├─ software_normalizer.py (150 LOC)
  │  ├─ SOFTWARE_NORMALIZATION dict
  │  ├─ normalize_software_name()
  │  └─ handle_version_aliases()
  │
  ├─ confidence_scorer.py (100 LOC)
  │  ├─ match_confidence_score()
  │  └─ calculate_overall_confidence()
  │
  └─ cve_parser.py (150 LOC) - Coordinator
     ├─ parse_cve() - Main entry point
     └─ Imports from above 3 modules
```

**Verification:**
- [ ] Run Menu 1 query - CVE parsing works
- [ ] Imports resolve correctly
- [ ] No functionality lost

---

## PHASE 4: Enhancement & Polish (2+ weeks)

### Task 4.1: KB Schema Validation
**Priority:** 🟡 MEDIUM | **Effort:** ⏱️ 2 hours

**Create:** `utils/kb_schema.py`

```python
from pydantic import BaseModel
from datetime import datetime

class CVERecord(BaseModel):
    id: str
    description: str
    cvss_score: float
    severity: str
    published: str
    affected_software: str

class IOCRecord(BaseModel):
    id: str
    type: str
    value: str
    threat_actor: str

class MalwareRecord(BaseModel):
    id: str
    malware_family: str
    type: str
    threat_actor: str
```

**Integration:**
Update `doc_store.py` to validate on upload

---

### Task 4.2: Jinja2 Report Templating
**Priority:** 🟡 MEDIUM | **Effort:** ⏱️ 2 hours

**Create:** `templates/report.html.j2`

Benefits:
- More maintainable report generation
- Easier to customize styling
- Reusable blocks

---

### Task 4.3: Full Multi-Source Intelligence Integration
**Priority:** 🟡 MEDIUM | **Effort:** ⏱️ 3 hours

**Current:** Only 30% of multi_source_intel.py signals used  
**Goal:** Full voting system in agent pipeline

---

## Execution Checklist

### Pre-Execution
- [ ] Create backup branch: `git checkout -b optimization/phase-1`
- [ ] Verify all tests pass
- [ ] Document current behavior (screenshots/logs)

### Phase 1 Execution (Day 1)
- [ ] Task 1.1: Remove remediation duplication
- [ ] Task 1.2: Consolidate print functions
- [ ] Task 1.3: Fix CVE ID regex
- [ ] Task 1.4: Move late imports
- [ ] **Testing:** Run Menu 1, 2, 4 thoroughly
- [ ] **Commit:** "refactor: phase 1 cleanup - consolidate duplication, fix regex"

### Phase 2 Execution (Day 2-3)
- [ ] Task 2.1: Add CMDB indexing
- [ ] Task 2.2: NVD API caching
- [ ] Task 2.3: Create date_range_utils
- [ ] Task 2.4: Add OpenCTI pagination
- [ ] **Testing:** Performance benchmarks
- [ ] **Commit:** "perf: phase 2 optimization - add caching, indexing, pagination"

### Phase 3 Execution (Week 2)
- [ ] Task 3.1: Create IterationManager
- [ ] Task 3.2: Create message builder
- [ ] Task 3.3: Split cve_parser.py
- [ ] **Testing:** All features functional
- [ ] **Commit:** "refactor: phase 3 architecture - iteration mgr, message builder, parser split"

### Phase 4 Execution (Week 3)
- [ ] Task 4.1-4.3: Enhanced features
- [ ] **Testing:** Full regression testing
- [ ] **Commit:** "feat: phase 4 enhancements - validation, templating, multi-source intel"

### Post-Execution
- [ ] Merge to main
- [ ] Update documentation
- [ ] Performance benchmarking report

---

## Success Metrics

| Metric | Before | After | Target |
|--------|--------|-------|--------|
| **Code Lines** | ~9500 | ~9200 | -300 LOC |
| **CMDB Match Speed** | Baseline | +40% | 40% faster |
| **API Throughput** | Baseline | +50% | 50% more requests |
| **Startup Time** | Baseline | -20% | 20% faster |
| **Code Duplication** | ~400 LOC | ~100 LOC | Minimal |

---

**Status:** ✅ Ready to Execute  
**Recommendation:** Start Phase 1 immediately for quick wins
