"""
config.py - Cấu hình toàn cục cho ATI-AgenticThreatIntelligence System
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
VULNERS_API_KEY = os.getenv("VULNERS_API_KEY", "")

# ── Neo4j Graph Database (tuỳ chọn) ─────────────────────────────────────────
NEO4J_URI      = os.getenv("NEO4J_URI",      "bolt://localhost:7687")
NEO4J_USER     = os.getenv("NEO4J_USER",     "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")

# ── App ─────────────────────────────────────────────────────────────────────
REPORTS_DIR    = os.getenv("REPORTS_DIR", "./reports")
MAX_STEPS      = int(os.getenv("MAX_STEPS", "20"))
LOG_LEVEL      = os.getenv("LOG_LEVEL", "INFO")

# Tạo thư mục reports nếu chưa có
os.makedirs(REPORTS_DIR, exist_ok=True)
