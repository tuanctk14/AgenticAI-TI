"""
core/ollama_llm.py - Wrapper để kết nối với Ollama local
"""
import requests
import json
from config import OLLAMA_BASE_URL, OLLAMA_MODEL


def check_ollama_connection() -> tuple[bool, str]:
    """Kiểm tra Ollama đang chạy và model đã được pull."""
    try:
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        if resp.status_code != 200:
            return False, f"Ollama không phản hồi (HTTP {resp.status_code})"
        
        models = [m["name"] for m in resp.json().get("models", [])]
        # Kiểm tra model (so sánh linh hoạt)
        model_base = OLLAMA_MODEL.split(":")[0]
        found = any(model_base in m for m in models)
        
        if not found:
            available = ", ".join(models) if models else "(chưa có model nào)"
            return False, (
                f"Model '{OLLAMA_MODEL}' chưa được pull.\n"
                f"Models hiện có: {available}\n"
                f"Chạy: ollama pull {OLLAMA_MODEL}"
            )
        return True, "OK"
    except requests.exceptions.ConnectionError:
        return False, (
            "Không kết nối được Ollama.\n"
            "Hãy chắc chắn Ollama đang chạy: ollama serve"
        )


def ollama_chat(messages: list[dict], temperature: float = 0.1) -> str:
    """
    Gọi Ollama API với danh sách messages (OpenAI-compatible format).
    messages = [{"role": "system"|"user"|"assistant", "content": "..."}]
    """
    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": 2048,
        }
    }
    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json=payload,
            timeout=120
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]
    except requests.exceptions.Timeout:
        return "[LỖI] Ollama timeout - model đang xử lý quá lâu. Thử model nhỏ hơn."
    except Exception as e:
        return f"[LỖI Ollama] {e}"


def build_messages(system_prompt: str, user_content: str) -> list[dict]:
    """Helper tạo messages list chuẩn."""
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_content},
    ]
