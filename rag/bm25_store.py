"""
rag/bm25_store.py - BM25Store cho full-text search trên Knowledge Base.

Persist index qua pickle để tránh rebuild mỗi lần chạy.
"""

import re
import pickle
from pathlib import Path
from typing import List, Tuple, Optional
from rank_bm25 import BM25Okapi


class BM25Store:
    """BM25 full-text search index."""

    def __init__(self):
        """Khởi tạo BM25Store."""
        self.indices = {}  # {category: BM25Okapi}
        self.doc_id_maps = {}  # {category: [doc_ids]}
        self.doc_texts = {}  # {category: [texts]}
        self.index_file = Path("data/bm25_index.pkl")

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text: lowercase + split by word boundary."""
        text = text.lower()
        # Split by non-word characters
        tokens = re.findall(r'\w+', text)
        return tokens

    def build_from_kb(self, kb_data: dict) -> bool:
        """Build BM25 indices từ Knowledge Base.

        Args:
            kb_data: Dict với structure {cves: [...], iocs: [...], malwares: [...]}

        Returns:
            True nếu thành công
        """
        try:
            categories = {"cves": kb_data.get("cves", []),
                         "iocs": kb_data.get("iocs", []),
                         "malwares": kb_data.get("malwares", [])}

            for cat, docs in categories.items():
                if not docs:
                    continue

                doc_ids = []
                doc_texts = []
                tokenized_docs = []

                for doc in docs:
                    doc_id = doc.get("id", "")
                    if not doc_id:
                        continue

                    # Extract searchable text
                    text_parts = [
                        doc.get("name", ""),
                        doc.get("description", ""),
                        doc.get("pattern", ""),
                    ]
                    text = " ".join(filter(None, text_parts))

                    if text:
                        doc_ids.append(doc_id)
                        doc_texts.append(text)
                        tokenized_docs.append(self._tokenize(text))

                if doc_ids:
                    self.indices[cat] = BM25Okapi(tokenized_docs)
                    self.doc_id_maps[cat] = doc_ids
                    self.doc_texts[cat] = doc_texts

            # Persist index
            self._save_index()
            return True

        except Exception as e:
            print(f"[LỖI] BM25 build failed: {e}")
            return False

    def query(
        self,
        category: str,
        query: str,
        top_k: int = 20
    ) -> List[Tuple[str, float]]:
        """Query BM25 index.

        Args:
            category: Category (cves/iocs/malwares)
            query: Query string
            top_k: Số kết quả

        Returns:
            List[(doc_id, score)] sắp xếp giảm theo score
        """
        if category not in self.indices:
            return []

        try:
            tokens = self._tokenize(query)
            bm25 = self.indices[category]

            scores = bm25.get_scores(tokens)
            doc_ids = self.doc_id_maps[category]

            # Zip with IDs, sort by score, return top-k
            scored = list(zip(doc_ids, scores))
            scored.sort(key=lambda x: x[1], reverse=True)

            return scored[:top_k]

        except Exception as e:
            print(f"[LỖI] BM25 query failed: {e}")
            return []

    def _save_index(self):
        """Persist indices to file."""
        try:
            Path("data").mkdir(exist_ok=True)
            with open(self.index_file, "wb") as f:
                pickle.dump({
                    "indices": self.indices,
                    "doc_id_maps": self.doc_id_maps,
                    "doc_texts": self.doc_texts
                }, f)
        except Exception as e:
            print(f"[CẢNH BÁO] Không thể save BM25 index: {e}")

    def load_index(self) -> bool:
        """Load indices từ file nếu tồn tại."""
        if not self.index_file.exists():
            return False

        try:
            with open(self.index_file, "rb") as f:
                data = pickle.load(f)
                self.indices = data["indices"]
                self.doc_id_maps = data["doc_id_maps"]
                self.doc_texts = data["doc_texts"]
            return True
        except Exception as e:
            print(f"[CẢNH BÁO] Không thể load BM25 index: {e}")
            return False
