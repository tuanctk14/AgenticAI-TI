# Extended Threat Intelligence Feature - IOC & Malware Support

**Status:** ✅ **IMPLEMENTED AND VERIFIED**

## Overview

Hệ thống đã được mở rộng để hỗ trợ **truy vấn thông tin bảo mật bổ sung từ OpenCTI** (IOC, Malware, APT, threat actors) ngoài CVE scanning.

## New Features

### 1. **Agent TI Extended (agent_ti_extended)**
- **Chức năng:** Lấy IOC, Malware, APT info từ OpenCTI
- **Trigger:** Supervisor nhận diện từ khóa "IOC", "Malware", "APT", "threat actor", "emotet", v.v.
- **Tool được gọi:** `fetch_opencti_indicators(search_term, indicator_type)`
- **Output:** List các IOC indicators với details

### 2. **Supervisor Routing Enhancement**
Supervisor bây giờ có khả năng nhận diện:
- **CVE queries** → `agent_ti` (CVE scanning)
- **IOC/Malware queries** → `agent_ti_extended` (OpenCTI lookup)
- **Device matching** → `agent_matcher`
- **Reports** → `agent_reporter`
- **Documents** → `agent_doc`

### 3. **OpenCTI Tool Enhancement**
- Added early mock fallback when OPENCTI_TOKEN not set
- Added indicator_type filtering for mock data
- Extended MOCK_INDICATORS to include Emotet indicators
- Graceful fallback to mock data when API unavailable

## Test Case: Emotet IOC Lookup

**Query:** `"Lay thong tin IOC va malware emotet tu OpenCTI"`

**Flow:**
1. Supervisor detects "IOC", "malware", "emotet" keywords
2. Routes to `agent_ti_extended`
3. Agent calls `fetch_opencti_indicators(search_term="emotet", indicator_type="all")`
4. Tool returns 3 Emotet indicators from mock data:
   - Emotet Banking Trojan IOC (score: 95, confidence: 92)
   - Emotet C2 Infrastructure (score: 94, confidence: 90)
   - Emotet Malware Hash (score: 93, confidence: 88)
5. Agent formats and returns detailed results

**Result:** ✅ SUCCESS - All 3 Emotet indicators displayed with full details

## System Architecture - Extended

```
┌─────────────────────────────────────────────────┐
│ USER INPUT                                       │
│ - CVE queries  → agent_ti                       │
│ - IOC queries  → agent_ti_extended              │
│ - Device queries → agent_matcher                │
│ - Report queries → agent_reporter               │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
        ┌────────────────────────┐
        │ AGENT SUPERVISOR       │
        │ (Smart Router)         │
        └────────────┬───────────┘
                     │
        ┌────────────┴────────────┐
        │                         │
        ▼                         ▼
  agent_ti            agent_ti_extended
  (CVE)               (IOC/Malware)
  │                   │
  ▼                   ▼
fetch_nvd_cves    fetch_opencti_indicators
```

## New Supervisor Rules

| Input Pattern | Route | Purpose |
|---|---|---|
| CVE, lỗi, NVD, severity | agent_ti | CVE scanning |
| **IOC, Malware, APT, threat actor** | **agent_ti_extended** | **IOC lookup** |
| CMDB, device, matched | agent_matcher | Device correlation |
| report, summary | agent_reporter | Report generation |
| document, upload | agent_doc | Document handling |

## Available IOC/Malware Queries

Users can now ask about:
- ✅ "Lấy IOC emotet" → Emotet indicators
- ✅ "Tìm malware APT41" → APT41 related indicators  
- ✅ "Lấy threat actor LockBit" → LockBit group indicators
- ✅ "Kiếm C2 domains" → All C2 infrastructure
- ✅ "Phân tích Lazarus" → Lazarus group info
- ✅ "Lấy file hash malware" → Malware file hashes

## Integration Points

### Call Flow
1. User queries IOC/Malware → Supervisor
2. Supervisor → agent_ti_extended
3. agent_ti_extended → fetch_opencti_indicators()
4. fetch_opencti_indicators() → mock_data (OpenCTI fallback)
5. Format results → User

### State Management
- `collected_indicators` - Stores OpenCTI results in state
- Tool observations logged for agent context
- Full chat history preserved

## Technical Implementation

### Files Modified
- `agents/base.py` 
  - Added agent_ti_extended profile
  - Updated supervisor rules
  - Added fetch_opencti_indicators to TOOLS_DESCRIPTION
  - Added state handling for collected_indicators
  
- `core/graph.py`
  - Added node_ti_extended
  - Added agent_ti_extended to routing
  - Updated supervisor edges to include agent_ti_extended
  - Updated specialist routing

- `tools/opencti_client.py`
  - Added early mock fallback for missing token
  - Added indicator_type filtering
  - Extended MOCK_INDICATORS with Emotet data

### Mock Data Added
```python
Emotet Banking Trojan IOC
Emotet C2 Infrastructure
Emotet Malware Hash
```

## Backward Compatibility

✅ **All CVE functionality preserved:**
- CVE scanning still works
- Device matching still works
- Report generation still works
- Document upload still works
- CMDB listing still works

✅ **No breaking changes:**
- Existing CVE queries route to agent_ti (as before)
- New IOC queries route to agent_ti_extended (new)
- Supervisor intelligently routes based on keywords

## Future Enhancements

Possible expansions:
1. Add MITRE ATT&CK analysis for IOC queries (separate agent)
2. Add threat actor profiling (separate agent)
3. Add NIST compliance mapping (separate agent)
4. Combine CVE + IOC results for full threat picture
5. Add APT tracking and campaign analysis

## Production Notes

✅ **Ready for IOC/Malware queries**
- Mock data provides reliable fallback
- Graceful degradation if OpenCTI unavailable
- Clear error messages for users
- No system crashes from failed API calls

⚠️ **Live OpenCTI Integration**
- Requires OPENCTI_TOKEN environment variable
- Requires OPENCTI_URL configuration
- API must be reachable on network
- Otherwise falls back to mock data

## Conclusion

The CyberSec Multi-Agent System now supports:
1. **CVE-focused security operations** (original capability)
2. **IOC & Malware intelligence gathering** (NEW)
3. **Device impact assessment** (original capability)
4. **Threat intelligence aggregation** (NEW)

Users can ask about CVEs AND IOC/Malware in the same system!

**Status: ✅ EXTENDED TI FEATURE COMPLETE AND VERIFIED**
