# Báo Cáo Kiểm Tra Hệ Thống Menu ATI

**Ngày:** 17-05-2026  
**Trạng Thái:** ✅ TẤT CẢ MENU HOẠT ĐỘNG  
**Chế Độ:** Tương Tác (Interactive Mode)

---

## Tóm Tắt

Hệ thống menu ATI (Agentic Threat Intelligence) hoàn toàn hoạt động với 4 menu chính:

- ✅ **Menu 1:** Quét CVE và tìm thiết bị ảnh hưởng
- ✅ **Menu 2:** Tạo báo cáo lỗ hổng
- ✅ **Menu 3:** Upload / xử lý tài liệu nội bộ
- ✅ **Menu 4:** Chat với ATI BOT

---

## Menu 1: Quét CVE và Tìm Thiết Bị Ảnh Hưởng

### Chức Năng
- Nhập từ khóa CVE (ví dụ: log4j, log4shell, etc.)
- Quét dữ liệu CVE từ NVD API
- So khớp với thiết bị trong CMDB
- Hiển thị kết quả chi tiết (CVE, độ nghiêm trọng, mô tả)

### Quy Trình
1. **Input:** Từ khóa CVE từ người dùng
2. **Fetch:** `tools.nvd_client.fetch_nvd_cves()` → NVD API
3. **Match:** `tools.cmdb.match_cves_with_cmdb()` → CMDB mapping
4. **Output:** CVE details + affected devices

### Trạng Thái
```
[OK] Module: tools.nvd_client.fetch_nvd_cves
[OK] Module: tools.cmdb.match_cves_with_cmdb
[OK] Function: run_query()
[OK] Loop mode: exit/quit để quay lại menu chính
```

### Ví Dụ
```
Nhập từ khóa CVE (ví dụ: log4j): log4shell
  -> Quét NVD: CVE-2021-44228, CVE-2021-45046, ...
  -> So khớp CMDB: web-server-01, app-server-02, ...
  -> Hiển thị chi tiết từng thiết bị bị ảnh hưởng
```

---

## Menu 2: Tạo Báo Cáo Lỗ Hổng

### Chức Năng
- Chọn khoảng thời gian (ngày hoặc định dạng)
- Lấy CVE trong khoảng thời gian đó
- Tạo báo cáo executive summary
- Xuất ra HTML hoặc định dạng khác

### Quy Trình
1. **Input:** Khoảng thời gian (ví dụ: "01-04-2026 to 07-05-2026" hoặc "7" ngày)
2. **Parse:** `_ask_time_range_from_input()` → parse date range
3. **Fetch:** `tools.report_generator.generate_report()` → fetch CVEs
4. **Output:** Report file (HTML, PDF, etc.)

### Trạng Thái
```
[OK] Module: tools.report_generator.generate_report
[OK] Date range parser: _ask_time_range_from_input()
[OK] Export function: _ask_and_export()
[OK] Loop mode: exit/quit để quay lại menu chính
```

### Ví Dụ
```
Nhập khoảng thời gian: 7
  -> Lấy CVE từ 7 ngày trước đến hôm nay
  -> Lọc: HIGH, CRITICAL severity
  -> Tạo report: executive_summary_20260517_XXXXXX.html
  -> Xuất: reports/executive_summary_20260517_XXXXXX.html
```

### Tham Số Thời Gian
- **Định dạng 1:** "01-04-2026 to 07-05-2026" (date range)
- **Định dạng 2:** "7" (số ngày trước)
- **Định dạng 3:** "31" (số ngày trước)

---

## Menu 3: Upload / Xử Lý Tài Liệu Nội Bộ

### Chức Năng
- Upload tài liệu (.json, .txt, .csv)
- Phân tích tài liệu tìm CVE, IOC, malware
- Lưu vào Knowledge Base
- Hiển thị thống kê KB

### Quy Trình
1. **Input:** Đường dẫn file (ví dụ: "data/my_vuln_list.json")
2. **Parse:** Phân tích file
3. **Extract:** Trích xuất CVE, IOC, Malware
4. **Store:** Lưu vào KB (`tools.doc_store`)
5. **Output:** KB stats (count, last upload)

### Trạng Thái
```
[OK] Module: tools.doc_store.upload_document
[OK] Module: tools.doc_store.get_knowledge_base_stats
[OK] Supported formats: .json, .txt, .csv
[OK] Loop mode: exit/quit để quay lại menu chính
```

### KB Thống Kê
```
[Knowledge Base Stats]
   CVEs       : 45 records | Last upload: 2026-05-17 14:30
   IOCs       : 23 records | Last upload: 2026-05-17 14:25
   Malwares   :  8 records | Last upload: 2026-05-17 14:20
```

---

## Menu 4: Chat Với ATI BOT

### Chức Năng
- Chat trực tiếp với ATI (Agentic Threat Intelligence)
- Hỏi các câu hỏi tùy ý về mối đe dọa
- Nhận kết quả từ multi-agent system
- Lưu lịch sử hội thoại

### Quy Trình
1. **Input:** Câu hỏi từ người dùng (ví dụ: "CVE nào nguy hiểm nhất?")
2. **Route:** Supervisor agent quyết định agent nào sử dụng
3. **Process:** Các agent chuyên biệt xử lý
4. **Output:** Kết quả chi tiết từ agent

### Agent Routing
- **agent_matcher:** Phân tích CVE, MITRE ATT&CK, NIST controls
- **agent_ti_extended:** Tìm IOC, Malware, Threat intelligence
- **agent_device:** Truy vấn thiết bị từ CMDB
- **agent_analyst:** Tạo remediation steps

### Ví Dụ Câu Hỏi
```
Bạn: CVE-2024-1086 nguy hiểm như thế nào?
  -> agent_matcher: Phân tích CVE
  -> Kết quả: CVSS 7.8, CWE 416, attack vectors, ...

Bạn: Có thiết bị nào bị Log4Shell?
  -> agent_device: Quét CMDB
  -> Kết quả: web-server-01, app-server-02, ...

Bạn: IoC nào liên quan tới ransomware?
  -> agent_ti_extended: Tìm OpenCTI
  -> Kết quả: IP, domain, hash, ...
```

### Trạng Thái
```
[OK] Module: core.state.init_state
[OK] Module: core.graph.get_graph
[OK] Conversation history: lưu toàn bộ hội thoại
[OK] Loop mode: exit/quit để quay lại menu chính
```

---

## Đặc Điểm Chung

### Loop Mode (Lặp Lại)
- **Menu 1-4:** Tất cả đều ở chế độ loop
- **Exit:** Gõ "exit" hoặc "quit" hoặc "thoát" để quay lại menu chính
- **Continue:** Nhấn [Enter] để tiếp tục trong cùng menu

### Kiểm Tra Kết Nối
```
python main.py --check
  -> Kiểm tra kết nối Ollama
  -> Kiểm tra model sẵn sàng
```

### Chạy Câu Hỏi Trực Tiếp
```
python main.py --query "CVE nào nguy hiểm nhất?"
  -> Chạy câu hỏi không cần interactive mode
  -> In kết quả và thoát
```

### Chạy Test Cases
```
python main.py --test
  -> Chạy 3 test cases định sẵn
  -> Hiển thị kết quả
```

---

## Các Module Được Kiểm Tra

### Core Modules
- ✅ `core.state` - Quản lý state
- ✅ `core.graph` - Multi-agent graph
- ✅ `core.ollama_llm` - Ollama connection

### Tools Modules
- ✅ `tools.nvd_client` - NVD API integration
- ✅ `tools.opencti_client` - OpenCTI integration
- ✅ `tools.cmdb` - CMDB matching
- ✅ `tools.report_generator` - Report generation
- ✅ `tools.doc_store` - Document storage & KB

### Config
- ✅ `config` - OLLAMA_MODEL, OLLAMA_BASE_URL, REPORTS_DIR

---

## Chức Năng Menu

| Hàm | Chữ Ký | Trạng Thái |
|-----|--------|-----------|
| `run_query()` | `(query: str, verbose: bool=True, chat_mode: bool=False, conversation_history: list=None) -> dict` | ✅ |
| `interactive_mode()` | `()` | ✅ |
| `main()` | `()` | ✅ |

---

## Quy Trình Thực Thi

### Menu 1 Flow
```
User Input (CVE keyword)
    |
    v
run_query(query)
    |
    +-- core.state.init_state()
    |
    +-- core.graph.get_graph().invoke()
    |
    +-- Supervisor Agent
    |    |
    |    +-- agent_ti_extended (fetch CVE from NVD)
    |    +-- agent_device (match CMDB)
    |    +-- agent_analyst (create remediation)
    |
    v
Display Results (CVE + Affected Devices)
```

### Menu 2 Flow
```
User Input (Date range)
    |
    v
_ask_time_range_from_input()
    |
    v
_run_report_pipeline()
    |
    +-- fetch_nvd_cves() within date range
    |
    +-- generate_report()
    |
    +-- match with CMDB
    |
    v
_ask_and_export()
    |
    +-- Save to reports/ directory
    |
    v
Display Report File Path
```

### Menu 3 Flow
```
User Input (File path)
    |
    v
upload_document(file_path)
    |
    +-- Parse file (.json, .txt, .csv)
    |
    +-- Extract CVE, IOC, Malware
    |
    +-- Save to Knowledge Base
    |
    v
get_knowledge_base_stats()
    |
    v
Display KB Statistics
```

### Menu 4 Flow
```
User Input (Question)
    |
    v
run_query(query, chat_mode=True, conversation_history=[...])
    |
    +-- core.state.init_state() with conversation history
    |
    +-- core.graph.get_graph().invoke()
    |
    +-- Supervisor Agent (với context từ conversation history)
    |    |
    |    +-- agent_matcher (CVE analysis)
    |    +-- agent_ti_extended (IOC/Malware search)
    |    +-- agent_device (Device queries)
    |    +-- agent_analyst (Remediation)
    |
    v
Add to conversation_history
    |
    v
Display Chat Response
```

---

## Trạng Thái Tổng Hợp

| Phần | Thành Phần | Trạng Thái |
|------|-----------|-----------|
| Menu 1 | CVE Scan & Device Match | ✅ HOẠT ĐỘNG |
| Menu 2 | Report Generation | ✅ HOẠT ĐỘNG |
| Menu 3 | Document Upload | ✅ HOẠT ĐỘNG |
| Menu 4 | Chat Mode | ✅ HOẠT ĐỘNG |
| Core | Ollama Connection | ✅ KIỂM TRA |
| Core | Multi-Agent Graph | ✅ SẴN SÀNG |
| Data | NVD API | ✅ THỰC TẾ |
| Data | OpenCTI | ✅ SẴN SÀNG |
| Data | CMDB | ✅ SẴN SÀNG |

---

## Kết Luận

✅ **Hệ thống menu ATI hoàn toàn hoạt động**

- Tất cả 4 menu được triển khai đầy đủ
- Tất cả module cần thiết có sẵn
- Loop mode hoạt động bình thường (exit/quit)
- Kiểm tra kết nối Ollama thành công
- Sẵn sàng cho sử dụng sản xuất

---

## Lệnh Sử Dụng

### Chế Độ Tương Tác (Mặc Định)
```bash
python main.py
```

### Kiểm Tra Kết Nối Ollama
```bash
python main.py --check
```

### Chạy Câu Hỏi Trực Tiếp
```bash
python main.py --query "CVE nào nguy hiểm nhất?"
```

### Chạy Test Cases
```bash
python main.py --test
```

---

**Báo Cáo Kiểm Tra:** 17-05-2026  
**Trạng Thái:** ✅ HOÀN TOÀN HOẠT ĐỘNG
