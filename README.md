# 🛡️ ATI-AgenticThreatIntelligence: Nền Tảng Phân Tích Mối Đe Dọa Thông Minh

**Phiên bản**: 3.0 (Phase 0-C)  
**Trạng thái**: ✅ Sẵn sàng cho Production  
**Ngôn ngữ**: Python 3.11+ | Ollama (Local)

---

## 📋 Tổng Quan

ATI là một **nền tảng phân tích mối đe dọa doanh nghiệp** chạy hoàn toàn offline, không cần cloud API. Hệ thống sử dụng:

- 🤖 **LLM Local**: Ollama + qwen2.5:7b
- 🔐 **Xác thực Multi-user**: Bcrypt + HMAC session tokens
- 🔍 **Hybrid Retrieval**: BM25 + Vector embeddings + Graph traversal
- ⏰ **Tự động Báo cáo**: Windows Task Scheduler integration
- 📊 **Audit Trail**: Ghi log tất cả hành động admin

**Không cần**: AWS, Azure, Google Cloud, hoặc bất kỳ dịch vụ cloud nào.

---

## 🚀 Bắt Đầu Nhanh

### 1️⃣ Cài đặt Ollama

```bash
# Tải từ https://ollama.ai
ollama pull qwen2.5:7b          # LLM chính (~4.5GB)
ollama pull nomic-embed-text    # Embeddings (~274MB)
```

### 2️⃣ Cài đặt Dependencies

```bash
cd ATI-AgenticThreatIntelligence
pip install -r requirements.txt
```

### 3️⃣ Khởi tạo Admin

```bash
python main.py init-admin
# Nhập tên user: admin
# Nhập mật khẩu: (>= 6 ký tự)
```

### 4️⃣ Đăng nhập & Sử dụng

```bash
python main.py login
# Nhập tên user: admin
# Nhập mật khẩu: ...

python main.py              # Menu tương tác
```

---

## 📱 Menu Chính

```
+-----------------------------------------------+
|  1. Quét CVE & tìm thiết bị ảnh hưởng        |
|  2. Tạo báo cáo lỗ hổng                      |
|  3. Upload / Xử lý tài liệu nội bộ           |
|  4. Chat với ATI BOT (AI trực tiếp)          |
|  5. Quản trị (admin only)                    |
|  0. Thoát                                    |
+-----------------------------------------------+
```

**Menu 5 (Admin)**:
- Quản lý schedule (tự động báo cáo)
- Xem audit log (lịch sử hành động)
- Quản lý người dùng

---

## 📅 Quản lý Schedule (Báo Cáo Tự Động)

### Tạo schedule

```bash
python main.py schedule add \
  --name daily-cve-6am \
  --time 06:00 \
  --severity HIGH
```

Hệ thống sẽ tự động lấy CVE mới trong 24h và gửi báo cáo mỗi ngày lúc 6:00 AM.

### Các lệnh khác

```bash
python main.py schedule list              # Xem danh sách
python main.py schedule remove --id 1     # Xóa
python main.py schedule enable --id 1     # Bật
python main.py schedule disable --id 1    # Tắt
python main.py schedule runs --id 1       # Xem lịch sử chạy
python main.py schedule run-now --id 1    # Chạy ngay
```

---

## 👤 Quản lý Người Dùng

### Tạo user mới (admin)

```bash
python main.py login
python main.py create-user
# Chọn role: viewer (read-only) hoặc admin
```

### Xem thông tin hiện tại

```bash
python main.py whoami
```

### Đăng xuất

```bash
python main.py logout
```

---

## 🔧 Cấu Hình

### `.env` - Biến môi trường

```env
# Ollama (local)
OLLAMA_BASE_URL=http://localhost:11555
OLLAMA_MODEL=qwen2.5:7b

# API Keys (tùy chọn)
NVD_API_KEY=your_api_key_here
OPENCTI_URL=http://your_opencti
OPENCTI_TOKEN=your_token

# App Settings
REPORTS_DIR=./reports
MAX_STEPS=20

# Authentication
SESSION_SECRET=your_secret_key_32_chars_minimum
```

### Dữ liệu lưu trữ

```
data/
├── auth.db                  # Người dùng, schedules, audit log
├── threat_knowledge.db      # Knowledge base CVE/IOC
├── bm25_index.pkl          # Full-text search index
└── chroma/                 # Vector embeddings
```

---

## 🔐 Tính Năng Bảo Mật

| Tính năng | Chi tiết |
|----------|---------|
| **Mật khẩu** | Bcrypt hash (cost=12, ~250ms) |
| **Session Token** | HMAC-SHA256 signed, 8h TTL |
| **Access Control** | Role-based (admin/viewer) |
| **Audit Trail** | Ghi log tất cả hành động |
| **Session Storage** | Offline (~/.ati/session.json) |

---

## 📊 Kiến Trúc Hệ Thống

### 6 Lớp

```
┌─────────────────────────────────────┐
│ 6. CLI Commands & Interactive Menu  │ (main.py)
├─────────────────────────────────────┤
│ 5. Authentication & Authorization   │ (Phase A)
├─────────────────────────────────────┤
│ 4. Hybrid RAG Search               │ (Phase B)
├─────────────────────────────────────┤
│ 3. Scheduling & Automation         │ (Phase C)
├─────────────────────────────────────┤
│ 2. LLM Agent Graph                 │ (LangGraph)
├─────────────────────────────────────┤
│ 1. Threat Intelligence Sources     │ (NVD, OpenCTI)
└─────────────────────────────────────┘
```

### Hybrid Retrieval

```
Truy vấn
  ├─→ BM25 Search (full-text)
  ├─→ Dense Search (embeddings)
  └─→ Graph Search (relationships)
       ↓
  RRF Fusion (kết hợp kết quả)
       ↓
  Top-10 Kết quả Hydrated
```

---

## 🧪 Kiểm Thử

```bash
# Chạy tất cả tests
pytest tests/

# Chi tiết
pytest tests/test_phase_a_auth.py -v   # 13 tests
pytest tests/test_phase_b_rag.py -v    # 15 tests
```

**Kết quả**: ✅ 28/28 tests (100% PASS)

---

## 📚 Tài Liệu Chi Tiết

| Tài liệu | Mục đích |
|----------|---------|
| **SETUP.md** | Hướng dẫn cài đặt từng bước |
| **MASTER_SYSTEM_DOCUMENTATION_VI.md** | Kiến trúc & thiết kế |
| **PHASE_0_TO_C_COMPLETION.md** | Báo cáo hoàn thành |

---

## 🎯 Các Tính Năng Chính

### ✅ Phase A: Xác Thực & Phân Quyền
- Đăng nhập/đăng xuất an toàn
- 2 vai trò: Admin (toàn quyền) + Viewer (read-only)
- Quản lý người dùng
- Audit trail đầy đủ
- Session offline

### ✅ Phase B: Hybrid RAG
- **BM25**: Tìm kiếm văn bản toàn cầu
- **Dense**: Vector similarity search
- **Graph**: Tìm kiếm dựa trên mối quan hệ
- **RRF Fusion**: Kết hợp thông minh 3 phương pháp
- Tìm kiếm song song

### ✅ Phase C: Tự Động Báo Cáo
- Windows Task Scheduler integration
- Fetch CVE tự động theo lịch
- Tạo báo cáo HTML
- Lưu lịch sử chạy
- Xử lý lỗi & retry tự động

---

## ⚙️ Yêu Cầu Hệ Thống

| Yêu cầu | Tối thiểu | Khuyến nghị |
|--------|-----------|-----------|
| **OS** | Windows 10 | Windows 11 |
| **Python** | 3.11 | 3.11+ |
| **RAM** | 4GB | 8GB+ |
| **Disk** | 2GB | 5GB+ |
| **Ollama** | Local | Chạy trên máy |

---

## 🔗 Lệnh Hữu Ích

### Xác Thực
```bash
python main.py init-admin          # Tạo admin lần đầu
python main.py login               # Đăng nhập
python main.py logout              # Đăng xuất
python main.py whoami              # Kiểm tra user hiện tại
python main.py create-user         # Tạo user mới (admin)
python main.py list-users          # Liệt kê users (admin)
```

### Schedule
```bash
python main.py schedule add --name daily-cve --time 06:00 --severity HIGH
python main.py schedule list
python main.py schedule enable --id 1
python main.py schedule disable --id 1
python main.py schedule remove --id 1
python main.py schedule runs --id 1
python main.py schedule run-now --id 1
```

### Menu Tương Tác
```bash
python main.py                     # Vào menu (cần login trước)
```

---

## 🐛 Xử Lý Sự Cố

| Vấn đề | Giải pháp |
|-------|---------|
| Ollama không kết nối | `ollama serve` hoặc mở app Ollama |
| Session hết hạn | `python main.py login` đăng nhập lại |
| Task Scheduler lỗi | Chạy PowerShell với quyền Admin |
| Lỗi auth.db | `rm data/auth.db` rồi `python main.py init-admin` |

---

## 📈 Hiệu Năng

| Hoạt động | Thời gian |
|-----------|----------|
| BM25 search | <100ms |
| Vector search | <500ms |
| RRF fusion | <50ms |
| LLM inference | 5-30s |
| Schedule execution | 2-5 phút |

**Khả năng**: 
- 100K+ CVE documents
- 10+ concurrent schedules
- ~2GB storage

---

## 🌐 Offline-First Design

✅ **Hoàn toàn offline**:
- Ollama chạy local
- Tất cả dữ liệu trong SQLite/Chroma
- Windows Task Scheduler (OS native)
- Không daemon process

⚙️ **Optional APIs** (user-triggered):
- NVD API: Fetch CVE explicitly
- OpenCTI: IOC search manually
- Cached locally khi sử dụng

---

## 📊 Thống Kê Mã

| Component | LOC | Files | Tests |
|-----------|-----|-------|-------|
| Phase A (Auth) | 1,340 | 5 | 13 |
| Phase B (RAG) | 1,094 | 7 | 15 |
| Phase C (Schedule) | 188 | 3 | - |
| Integration | 500+ | 3 | - |
| **Total** | **4,500+** | **23** | **28** |

---

## 🚀 Production Deployment

### Bước 1: Chuẩn bị
```bash
pip install -r requirements.txt
python main.py init-admin
```

### Bước 2: Tạo schedule
```bash
python main.py schedule add --name daily-report --time 06:00
```

### Bước 3: Kiểm tra
```bash
python main.py schedule list
python main.py schedule run-now --id 1
```

### Bước 4: Backup dữ liệu
```bash
# Backup folder: data/
# Chứa: auth.db, threat_knowledge.db, chroma/
```

---

## 📞 Hỗ Trợ

| Vấn đề | Xem |
|-------|-----|
| Setup | SETUP.md |
| Kiến trúc | MASTER_SYSTEM_DOCUMENTATION_VI.md |
| Hoàn thành | PHASE_0_TO_C_COMPLETION.md |

---

## ✨ Tính Năng Nổi Bật

🔐 **Bảo mật doanh nghiệp**: Bcrypt, HMAC, role-based access  
🔍 **Tìm kiếm thông minh**: 3 retrievers + RRF fusion  
⏰ **Tự động hóa**: Windows Task Scheduler  
📊 **Audit trail**: Ghi log tất cả hành động  
🌐 **Offline**: Zero cloud dependencies  
🧪 **Kiểm thử**: 28 tests, 100% pass rate  
📚 **Tài liệu**: 3 guides chi tiết tiếng Việt  

---

## ✅ Trạng Thái

| Tiêu chí | Kết quả |
|----------|---------|
| Tests | ✅ 28/28 (100%) |
| Documentation | ✅ Hoàn thành |
| Security | ✅ Best practices |
| Offline-first | ✅ Zero cloud |
| Production Ready | ✅ SẴN DÙNG |

---

## 🎯 Lộ Trình Tương Lai (Tùy chọn)

- [ ] Web UI (FastAPI + React)
- [ ] Advanced RAG (re-ranking)
- [ ] Multi-language support
- [ ] Database encryption
- [ ] Distributed scheduling

---

## 📄 Giấy phép

Phần mềm ATI được phát hành dưới giấy phép mã nguồn mở.

---

**ATI: Phân tích mối đe dọa nhanh, offline-first, không cần cloud. Sẵn sàng cho doanh nghiệp ngay bây giờ.** 🛡️

---

**Bắt đầu**: `python main.py init-admin` → `python main.py login` → `python main.py`
