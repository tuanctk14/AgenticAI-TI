"""
config.py - Cấu hình toàn cục cho CyberSec Multi-Agent System
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ── Ollama ─────────────────────────────────────────────────────────────────
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL",    "qwen2.5:7b")

# ── External APIs (tuỳ chọn) ────────────────────────────────────────────────
NVD_API_KEY    = os.getenv("NVD_API_KEY",    "")
OPENCTI_URL    = os.getenv("OPENCTI_URL",    "http://localhost:8080")
OPENCTI_TOKEN  = os.getenv("OPENCTI_TOKEN",  "")

# ── App ─────────────────────────────────────────────────────────────────────
REPORTS_DIR    = os.getenv("REPORTS_DIR", "./reports")
MAX_STEPS      = int(os.getenv("MAX_STEPS", "20"))
LOG_LEVEL      = os.getenv("LOG_LEVEL", "INFO")

# Tạo thư mục reports nếu chưa có
os.makedirs(REPORTS_DIR, exist_ok=True)
