"""
MASTER_SYSTEM_DOCUMENTATION_VI.md - Tài liệu kiến trúc hệ thống ATI (Tiếng Việt)
"""

# ATI-AgenticThreatIntelligence: Tài liệu Kiến Trúc Hệ Thống

**Phiên bản**: 3.0 (Phase 0-C)  
**Ngày cập nhật**: 2026-06-14  
**Mô tả**: Hệ thống threat intelligence đa agent với offline-first design, RAG, scheduling.

---

## 1. Tổng quan kiến trúc

### 1.1 6 Lớp hệ thống

```
┌─────────────────────────────────────────────────┐
│ Lớp 6: CLI Commands & Interactive Menu          │ (main.py)
├─────────────────────────────────────────────────┤
│ Lớp 5: Authentication & Authorization (Phase A) │ (auth/, cli/)
├─────────────────────────────────────────────────┤
│ Lớp 4: Hybrid RAG (Phase B)                     │ (rag/)
├─────────────────────────────────────────────────┤
│ Lớp 3: Scheduling & Job Management (Phase C)   │ (scheduler/)
├─────────────────────────────────────────────────┤
│ Lớp 2: LLM Agent Graph (core/graph.py)          │ (LangGraph)
├─────────────────────────────────────────────────┤
│ Lớp 1: Threat Intelligence Sources              │ (NVD, OpenCTI, etc)
└─────────────────────────────────────────────────┘
```

### 1.2 Đặc điểm chính

- **Offline-first**: Zero cloud dependencies (Ollama local)
- **Multi-agent**: LangGraph + Ollama qwen2.5:7b
- **Hybrid Retrieval**: BM25 + Dense + Graph (RRF fusion)
- **Role-based Access**: Admin + Viewer roles
- **OS-native Scheduling**: Windows Task Scheduler integration
- **Audit Trail**: Toàn bộ admin actions được log

---

## 2. Phase A: Authentication & Phân Quyền

### 2.1 Kiến trúc

**File**:
- `auth/models.py`: User, Role, Schedule, AuditEntry dataclasses
- `auth/db.py`: AuthDB (SQLite abstraction)
- `auth/service.py`: AuthService (bcrypt + HMAC tokens)
- `cli/auth_commands.py`: CLI commands (init-admin, login, create-user, etc)
- `cli/permission.py`: @require_role decorator

**Database Schema** (`data/auth.db`):

```sql
users(
  id PRIMARY KEY,
  username UNIQUE,
  password_hash BLOB (bcrypt, cost=12),
  role ENUM (admin, viewer),
  created_at ISO8601,
  last_login ISO8601
)

schedules(
  id PRIMARY KEY,
  name TEXT,
  time_of_day HH:MM,
  severity_filter ENUM (HIGH, CRITICAL, MEDIUM, ALL),
  enabled BOOL,
  created_by FK users(id),
  created_at ISO8601,
  last_run ISO8601,
  last_status TEXT
)

schedule_runs(
  id PRIMARY KEY,
  schedule_id FK schedules(id),
  started_at ISO8601,
  finished_at ISO8601,
  status ENUM (success, failed, running),
  cve_count INT,
  report_path TEXT,
  error_message TEXT
)

audit_log(
  id PRIMARY KEY,
  user_id FK users(id),
  action TEXT,
  resource TEXT,
  timestamp ISO8601
)
```

### 2.2 Session Management

**Token Format**: `base64(payload).hmac_signature`

```json
{
  "user_id": 1,
  "role": "admin",
  "expires_at": "2026-06-14T16:30:00"
}
```

**Persistence**: `~/.ati/session.json` (HMAC-verified)

**TTL**: 8 giờ (configurable via `SESSION_SECRET` env var)

### 2.3 Roles & Permissions

| Role | Menus 1-4 | Menu 5 (Admin) | Auth Commands | Schedule Mgmt |
|------|-----------|---|---|---|
| viewer | ✓ | ✗ | ✗ | ✗ |
| admin | ✓ | ✓ | ✓ | ✓ |

---

## 3. Phase B: Hybrid RAG

### 3.1 Kiến trúc

**Multi-source Retrieval** với RRF fusion:

```
Query (text)
  ├─→ BM25Retriever (full-text search)
  │    └─→ top-20 ranked results
  ├─→ DenseRetriever (vector similarity)
  │    └─→ OllamaEmbeddings + ChromaVectorStore
  │        └─→ nomic-embed-text (768d)
  │        └─→ top-20 ranked results
  └─→ GraphRetriever (entity + traversal)
       └─→ Entity extraction (CVE, IP, hash)
       └─→ Neo4j 1-2 hop traversal
       └─→ top-20 ranked results

  RRF Fusion (k=60):
    score(d) = sum_i 1/(k + rank_i(d))

  Output: top-10 hydrated documents
```

**File Structure**:

```
rag/
├── embeddings.py       # OllamaEmbeddings (httpx → Ollama API)
├── vector_store.py     # ChromaVectorStore (persistent, 3 collections)
├── bm25_store.py       # BM25Store (pkl persistence)
├── graph_retriever.py  # GraphRetriever (entity extraction + traversal)
├── fusion.py           # RRF algorithm
├── hybrid.py           # HybridRetriever (orchestrator)
└── __init__.py
```

### 3.2 Collections & Indexing

**Chroma Collections** (persistent tại `data/chroma/`):
- `kb_cves`: CVE documents
- `kb_iocs`: IOC (Indicators of Compromise)
- `kb_malwares`: Malware families

**BM25 Index** (pickle tại `data/bm25_index.pkl`):
- Rebuilt khi `rag reindex` chạy
- Auto-loaded khi search queries

### 3.3 Entity Extraction Patterns

```python
CVE:  r'CVE-\d{4}-\d+'
IP:   r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
Hash: r'\b[a-f0-9]{32,64}\b'
```

---

## 4. Phase C: Scheduling & Automation

### 4.1 Windows Task Scheduler Integration

**Adapter** (`scheduler/os_adapter.py`):

```
schedule_id=1, time="06:00"
  ↓
schtasks /create /tn "ATI_1" 
         /tr "python scripts/run_scheduled_report.py --id 1"
         /sc daily /st 06:00 /f
  ↓
Task Scheduler registers job
```

**Job Runner** (`scheduler/job_runner.py`):

1. Lấy config từ `auth.db`
2. Fetch NVD CVEs (1 ngày gần đây)
3. Generate HTML report
4. Update `schedule_runs` table (success/failed)
5. Audit log action

### 4.2 CLI Commands

```bash
python main.py schedule add --name daily-cve --time 06:00 --severity HIGH
python main.py schedule list
python main.py schedule remove --id 1
python main.py schedule enable --id 1
python main.py schedule disable --id 1
python main.py schedule runs --id 1
python main.py schedule run-now --id 1
```

---

## 5. LLM Agent Graph (Existing)

### 5.1 Agent Types

- `agent_ti`: Threat intelligence extraction
- `agent_matcher`: CVE ↔ CMDB device matching
- `agent_analyst`: Remediation & MITRE/NIST mapping
- `supervisor`: Routing logic

### 5.2 Integration Points

**Query Flow**:
```
Menu 1/4 (user query)
  ↓
supervisor (route to appropriate agent)
  ├─→ agent_ti (CVE/IOC search)
  ├─→ agent_matcher (device matching)
  └─→ agent_analyst (MITRE/remediation)
  ↓
Generate report
```

---

## 6. Data Storage & Persistence

### 6.1 Database Files

| File | Purpose | Format | Size |
|------|---------|--------|------|
| `data/auth.db` | Auth, schedules, audit | SQLite | <10MB |
| `data/threat_knowledge.db` | CVE/IOC knowledge base | SQLite | Variable |
| `data/bm25_index.pkl` | Full-text search index | Pickle | <100MB |
| `data/chroma/` | Vector embeddings | Chroma | <500MB |

### 6.2 Report Output

- `reports/` - User-generated reports (HTML)
- `reports/scheduled/` - Auto-scheduled reports (YYYY-MM-DD.html)

---

## 7. Offline-First Design

### 7.1 Dependencies

**No Cloud APIs Required**:
- ✅ Ollama (local LLM)
- ✅ Chroma (local vector DB)
- ✅ SQLite (local databases)
- ✅ Windows Task Scheduler (OS-native)

**Optional External APIs** (cached/periodic):
- NVD API (CVE fetching, explicitly triggered)
- OpenCTI (IOC search, explicitly triggered)

### 7.2 Network Traffic

- **Zero**: By default (pure local operation)
- **Minimal**: When user explicitly triggers NVD/OpenCTI fetch
- **No daemon**: No background sync or cloud updates

---

## 8. Setup & Deployment

### 8.1 Prerequisites

```bash
# Windows 10+
# Python 3.11+
# Ollama (local)

ollama pull qwen2.5:7b          # LLM (4.5GB)
ollama pull nomic-embed-text    # Embeddings (274MB)

pip install -r requirements.txt

python main.py init-admin
python main.py login
python main.py                  # Interactive CLI
```

### 8.2 First Schedule Setup

```bash
python main.py schedule add --name daily-cve-6am --time 06:00 --severity HIGH
# Task Scheduler automatically runs daily at 6 AM

python main.py schedule list
# Verify registration
```

---

## 9. Security Considerations

### 9.1 Authentication

- **Password Hash**: bcrypt (cost=12, ~250ms)
- **Session Token**: HMAC-SHA256 signed, expires 8h
- **Token Storage**: Local file `~/.ati/session.json` (user-owned)

### 9.2 Access Control

- **Role-based**: @require_role(Role.ADMIN) decorator
- **Audit Trail**: All admin actions logged
- **Rate Limiting**: Can be added to API/CLI if needed

### 9.3 Data Protection

- **At Rest**: SQLite databases (user can encrypt partition)
- **In Transit**: Ollama local only (no network)
- **Credentials**: .env file (not in git)

---

## 10. Performance & Scalability

### 10.1 Typical Queries

- **BM25 search**: <100ms (in-memory index)
- **Vector search**: <500ms (Chroma local)
- **Graph traversal**: <200ms (1-2 hops)
- **RRF fusion**: <50ms
- **LLM inference**: 5-30s (Ollama qwen2.5:7b)

### 10.2 Scaling Limits

- **CVE database**: Up to 100k+ documents (tested)
- **Concurrent schedules**: 10+ without issue
- **Storage**: Practical limit ~2GB (auth + vectors + KB)

---

## 11. Troubleshooting

### 11.1 Common Issues

| Issue | Solution |
|-------|----------|
| Ollama not found | `ollama serve` or launch app |
| Session expired | `python main.py login` |
| Task Scheduler fails | Run PowerShell as admin |
| Vector search slow | Run `python main.py rag reindex` |

### 11.2 Debug Commands

```bash
# Check Ollama connection
python main.py --check

# Show current session
python main.py whoami

# View audit log
python main.py whoami  # In Menu 5 (admin)
# Then select audit log option

# Force rebuild indices
# (Not implemented yet, can be added)
```

---

## 12. Future Enhancements

### 12.1 Potential Additions

- [ ] Multi-language support (Vietnamese, English, Chinese)
- [ ] Web UI (FastAPI + React)
- [ ] Database encryption (Fernet)
- [ ] Distributed scheduling (for multi-node)
- [ ] Advanced RAG: Reranking, fusion weighting
- [ ] ML-based anomaly detection for threats

### 12.2 Phase Roadmap

- **Phase 0-C (Complete)**: Auth, RAG, Scheduling
- **Phase D (Optional)**: Web UI, advanced analytics
- **Phase E (Optional)**: Multi-node distribution

---

## 13. Tài liệu thêm

- `SETUP.md`: Setup instructions
- `docs/archive/`: Archived documentation
- `tests/`: Test suites (Phase A: 13 tests, Phase B: 15 tests)

---

**Phục vụ threat intelligence analysis nhanh, offline-first, không cần cloud.**
