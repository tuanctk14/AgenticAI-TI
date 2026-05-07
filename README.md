# 🛡️ CyberSec Multi-Agent System — Ollama Local Edition

Hệ thống Multi-Agent bảo mật chạy **hoàn toàn offline** với Ollama trên máy tính cá nhân.

## Kiến trúc hệ thống

```
User Input
    │
    ▼
Supervisor Agent (điều phối)
    ├── TI Agent        → NVD API / Mock data
    ├── Matcher Agent   → CMDB matching
    ├── Analyst Agent   → MITRE ATT&CK / NIST
    ├── Doc Agent       → ChromaDB / RAG
    └── Reporter Agent  → Tạo báo cáo MD/TXT
```

## Yêu cầu hệ thống

| Thành phần | Yêu cầu tối thiểu |
|---|---|
| RAM | 8 GB (khuyến nghị 16 GB) |
| GPU | Tuỳ chọn (CPU cũng chạy được) |
| Disk | 5-10 GB cho model |
| Python | 3.10+ |
| Ollama | v0.1.x trở lên |

## Cài đặt nhanh

```bash
# 1. Cài Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull model (chọn 1 trong các model sau)
ollama pull llama3.2        # 3B - nhẹ nhất, ~2GB RAM
ollama pull llama3.1        # 8B - cân bằng, ~5GB RAM  
ollama pull qwen2.5         # 7B - tốt tiếng Việt, ~4GB RAM
ollama pull mistral         # 7B - nhanh, ~4GB RAM

# 3. Cài dependencies Python
pip install -r requirements.txt

# 4. Cấu hình
cp .env.example .env
# Chỉnh sửa .env theo nhu cầu

# 5. Chạy
python main.py
```

## Cấu trúc thư mục

```
cybersec-ollama/
├── main.py              # Entry point - CLI interface
├── config.py            # Cấu hình toàn cục
├── requirements.txt     # Dependencies
├── .env.example         # Mẫu cấu hình
├── agents/
│   ├── supervisor.py    # Agent điều phối
│   ├── ti_agent.py      # Threat Intelligence Agent
│   ├── matcher.py       # CMDB Matcher Agent
│   ├── analyst.py       # Risk Analysis Agent
│   ├── doc_agent.py     # Document/RAG Agent
│   └── reporter.py      # Report Generator Agent
├── tools/
│   ├── nvd_client.py    # NVD API client
│   ├── opencti_client.py # OpenCTI client
│   ├── cmdb.py          # CMDB matching
│   ├── mitre.py         # MITRE ATT&CK lookup
│   └── nist.py          # NIST controls mapping
├── core/
│   ├── state.py         # LangGraph state schema
│   ├── graph.py         # Workflow graph builder
│   └── ollama_llm.py    # Ollama LLM wrapper
├── data/
│   └── cmdb_devices.json # Mock CMDB data
└── reports/             # Báo cáo được lưu tại đây
```

## Sử dụng

```bash
# Chế độ interactive (menu)
python main.py

# Câu lệnh trực tiếp
python main.py --query "Quét CVE Log4Shell và tìm thiết bị bị ảnh hưởng"

# Chạy test cases
python main.py --test
```

## Models được hỗ trợ

| Model | RAM | Chất lượng tiếng Việt | Tốc độ |
|---|---|---|---|
| llama3.2:3b | ~2GB | Tốt | Rất nhanh |
| llama3.1:8b | ~5GB | Tốt | Nhanh |
| qwen2.5:7b | ~4GB | Xuất sắc | Nhanh |
| mistral:7b | ~4GB | Khá | Rất nhanh |
| llama3.1:70b | ~40GB | Xuất sắc | Chậm |
