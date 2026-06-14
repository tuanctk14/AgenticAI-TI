"""
rag/embeddings.py - OllamaEmbeddings để sinh vector embeddings từ Ollama.

Sử dụng model nomic-embed-text (768 dims) qua Ollama /api/embeddings endpoint.
"""

import httpx
from typing import List


class OllamaEmbeddings:
    """Client embeddings qua Ollama local."""

    def __init__(self, base_url: str = "http://localhost:11555", model: str = "nomic-embed-text"):
        """Khởi tạo OllamaEmbeddings.

        Args:
            base_url: URL của Ollama server
            model: Model name (mặc định: nomic-embed-text)
        """
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.client = httpx.Client(timeout=30.0)

    def embed(self, texts: List[str]) -> List[List[float]]:
        """Sinh embedding vector cho danh sách texts.

        Args:
            texts: Danh sách text strings

        Returns:
            List[List[float]]: Danh sách embedding vectors (mỗi ~768 dims cho nomic-embed-text)
        """
        if not texts:
            return []

        embeddings = []

        # Sequential batch: Ollama không support native batch endpoint
        for text in texts:
            try:
                response = self.client.post(
                    f"{self.base_url}/api/embeddings",
                    json={"model": self.model, "prompt": text},
                    timeout=30.0
                )

                if response.status_code == 200:
                    data = response.json()
                    embedding = data.get("embedding", [])
                    embeddings.append(embedding)
                else:
                    # Fallback: zero vector nếu fail
                    embeddings.append([0.0] * 768)

            except Exception as e:
                # Silent fail, append zero vector
                embeddings.append([0.0] * 768)

        return embeddings

    def close(self):
        """Đóng HTTP client."""
        self.client.close()

    def __enter__(self):
        """Context manager support."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup."""
        self.close()
