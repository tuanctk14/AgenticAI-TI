"""
SETUP.md - Hướng dẫn cài đặt ATI-AgenticThreatIntelligence (Offline Edition)
"""

# ATI-AgenticThreatIntelligence: Setup Guide

## Yêu cầu hệ thống

- **OS**: Windows 10+ (Task Scheduler support)
- **Python**: 3.11+
- **Ollama**: Chạy local trên port 11555 (mặc định)
- **Disk**: 2GB+ (vectors, databases)
- **RAM**: 8GB+ (Ollama models)

## Bước 1: Cài đặt Ollama

1. Download Ollama từ https://ollama.ai
2. Cài đặt và khởi động Ollama
3. Pull models:
   ```bash
   ollama pull qwen2.5:7b          # LLM chính (7B, ~4.5GB)
   ollama pull nomic-embed-text    # Embeddings (768d, ~274MB)
   ```
4. Kiểm tra kết nối:
   ```bash
   python main.py --check
   ```

## Bước 2: Cài đặt Dependencies

```bash
cd ATI-AgenticThreatIntelligence
pip install -r requirements.txt
```

Dependencies chính:
- `pydantic>=2.0.0` - Validation
- `chromadb>=0.4.0` - Vector storage
- `rank_bm25>=0.2.2` - Full-text search
- `bcrypt>=4.0.0` - Password hashing
- `httpx>=0.24.0` - HTTP client

## Bước 3: Khởi tạo Admin

Lần đầu tiên, tạo tài khoản admin:

```bash
python main.py init-admin
# Nhập tên user: admin
# Nhập mật khẩu: (yêu cầu >= 6 ký tự)
```

**Lưu ý**: Chỉ được tạo admin 1 lần. Để tạo user khác, dùng:
```bash
python main.py login
python main.py create-user
```

## Bước 4: Đăng nhập

```bash
python main.py login
# Nhập tên user: admin
# Nhập mật khẩu: ...
```

Session token được lưu tại `~/.ati/session.json` (8 giờ TTL).

Kiểm tra trạng thái:
```bash
python main.py whoami
```

## Bước 5: Chạy CLI Interactive

```bash
python main.py
```

**Menu**:
1. Quét CVE và tìm thiết bị ảnh hưởng
2. Tạo báo cáo
3. Upload / xử lý tài liệu nội bộ
4. Chat với ATI BOT
5. Quản trị (admin only)
   - Quản lý schedule
   - Xem audit log
   - Quản lý users

## Bước 6: Quản lý Schedule (Tự động báo cáo)

### Tạo schedule

```bash
python main.py schedule add --name daily-cve-06h --time 06:00 --severity HIGH
```

Thời gian: `HH:MM` (24h). Severity: `HIGH`, `CRITICAL`, `MEDIUM`, hoặc `ALL`.

### Liệt kê schedules

```bash
python main.py schedule list
```

Output:
```
ID  Tên                Thời gian  Severity  Trạng thái  Lần chạy cuối
--  ---                -----      --------  --------    ----
1   daily-cve-06h      06:00      HIGH      ✓ Enabled   2026-06-15 06:01:23
    Task Scheduler: ✓ Registered
```

### Chạy ngay lập tức

```bash
python main.py schedule run-now --id 1
```

### Xem lịch sử chạy

```bash
python main.py schedule runs --id 1
```

### Bật/tắt schedule

```bash
python main.py schedule enable --id 1
python main.py schedule disable --id 1
```

### Xóa schedule

```bash
python main.py schedule remove --id 1
```

## Cấu hình

### `.env` - Environment Variables

```env
# Ollama
OLLAMA_BASE_URL=http://localhost:11555
OLLAMA_MODEL=qwen2.5:7b

# API Keys (tuỳ chọn)
NVD_API_KEY=your_key_here
OPENCTI_URL=http://your_opencti_url
OPENCTI_TOKEN=your_token
VULNERS_API_KEY=your_key

# App Settings
LOG_LEVEL=INFO
REPORTS_DIR=./reports
MAX_STEPS=20

# Auth
SESSION_SECRET=your_secret_key_32_chars_minimum
```

### Dữ liệu

Các file dữ liệu được lưu tại:
- `data/auth.db` - Users, schedules, audit log (Phase A)
- `data/chroma/` - Vector embeddings (Phase B)
- `data/bm25_index.pkl` - Full-text index (Phase B)
- `data/threat_knowledge.db` - Knowledge base (existing)
- `reports/` - Generated reports
- `reports/scheduled/` - Scheduled reports

## Offline Mode

ATI hoạt động hoàn toàn offline sau khi setup:
- Ollama chạy local (no cloud)
- Tất cả data trong `data/`
- NVD API chỉ được gọi khi explicit fetch CVE (không tự động)
- Task Scheduler là OS-native (no external services)

## Troubleshooting

### "Ollama không kết nối"
```bash
ollama serve
# Hoặc khởi động Ollama app
```

### "Session hết hạn"
```bash
python main.py login
# Đăng nhập lại
```

### "Task Scheduler command không chạy"
- Chạy PowerShell với **admin privileges**
- Kiểm tra path tới Python: `python -c "import sys; print(sys.executable)"`

### "Không thể tạo admin"
```bash
rm data/auth.db
python main.py init-admin
```

## Production Deployment

Để deploy trên server:

1. **Cài Ollama** trên server
2. **Cập nhật `OLLAMA_BASE_URL`** trong `.env` thành IP server
3. **Cài deps** và init admin
4. **Tạo schedule** cho báo cáo hằng ngày
5. **Backup dữ liệu**: `data/` folder regularly

Không cần database server, cloud APIs, hoặc special infrastructure.

## Tính năng

- ✅ **Auth**: HMAC-signed sessions, role-based access (admin/viewer)
- ✅ **Hybrid RAG**: BM25 + dense embeddings + graph retrieval
- ✅ **Scheduler**: Windows Task Scheduler + SQLite tracking
- ✅ **Offline-first**: Zero cloud dependencies
- ✅ **Auditing**: Audit trail cho tất cả admin actions

## Tiếp theo

- Xem `MASTER_SYSTEM_DOCUMENTATION_VI.md` để hiểu kiến trúc
- Chạy `pytest tests/` để validate setup
- Kiểm tra `docs/archive/` cho legacy documentation
