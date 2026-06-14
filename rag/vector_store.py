"""
rag/vector_store.py - ChromaVectorStore wrapper cho persistent vector storage.

Lưu trữ embeddings trong data/chroma/ với 3 collections: kb_cves, kb_iocs, kb_malwares
"""

from typing import Optional, List, Dict
import chromadb
from pathlib import Path


class ChromaVectorStore:
    """Wrapper cho Chroma vector database."""

    def __init__(self, persist_dir: str = "data/chroma"):
        """Khởi tạo Chroma persistent client.

        Args:
            persist_dir: Đường dẫn folder lưu vector data
        """
        Path(persist_dir).mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(path=persist_dir)
        self.collections = {}

    def _get_collection(self, collection_name: str):
        """Lấy hoặc tạo collection."""
        if collection_name not in self.collections:
            self.collections[collection_name] = self.client.get_or_create_collection(
                name=collection_name,
                metadata={"hnsw:space": "cosine"}
            )
        return self.collections[collection_name]

    def upsert(
        self,
        collection: str,
        ids: List[str],
        documents: List[str],
        embeddings: List[List[float]],
        metadatas: Optional[List[Dict]] = None
    ) -> bool:
        """Upsert documents + embeddings vào collection.

        Args:
            collection: Collection name
            ids: Document IDs (unique)
            documents: Document texts
            embeddings: Pre-computed embeddings
            metadatas: Optional metadata dicts

        Returns:
            True nếu thành công
        """
        try:
            col = self._get_collection(collection)
            # Chroma requires metadata to be non-empty dict
            if metadatas is None:
                metadatas = [{"source": collection, "index": i} for i in range(len(ids))]
            col.upsert(
                ids=ids,
                documents=documents,
                embeddings=embeddings,
                metadatas=metadatas
            )
            return True
        except Exception as e:
            print(f"[LỖI] Chroma upsert failed: {e}")
            return False

    def query(
        self,
        collection: str,
        query_embedding: List[float],
        top_k: int = 10
    ) -> List[Dict]:
        """Query collection dựa vào embedding.

        Args:
            collection: Collection name
            query_embedding: Query vector
            top_k: Số kết quả trả về

        Returns:
            List[Dict] với structure: {id, document, distance, metadata}
        """
        try:
            col = self._get_collection(collection)
            results = col.query(
                query_embeddings=[query_embedding],
                n_results=top_k
            )

            # Convert Chroma format to dict list
            output = []
            if results["ids"] and len(results["ids"]) > 0:
                for i, doc_id in enumerate(results["ids"][0]):
                    output.append({
                        "id": doc_id,
                        "document": results["documents"][0][i],
                        "distance": results["distances"][0][i] if results.get("distances") else 0.0,
                        "metadata": results["metadatas"][0][i] if results.get("metadatas") else {}
                    })

            return output

        except Exception as e:
            print(f"[LỖI] Chroma query failed: {e}")
            return []

    def count(self, collection: str) -> int:
        """Đếm số documents trong collection."""
        try:
            col = self._get_collection(collection)
            return col.count()
        except Exception:
            return 0

    def reset(self) -> bool:
        """Xóa tất cả vector store."""
        try:
            for col_name in ["kb_cves", "kb_iocs", "kb_malwares"]:
                if col_name in self.collections:
                    self.client.delete_collection(name=col_name)
                    del self.collections[col_name]
            return True
        except Exception as e:
            print(f"[LỖI] Reset failed: {e}")
            return False

    def close(self):
        """Đóng kết nối."""
        pass
