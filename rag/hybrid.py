"""
rag/hybrid.py - Hybrid search orchestrator: BM25 + Dense + Graph → RRF fuse.

Entry point cho hybrid retrieval trong agent flow.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple
from .embeddings import OllamaEmbeddings
from .vector_store import ChromaVectorStore
from .bm25_store import BM25Store
from .graph_retriever import GraphRetriever
from .fusion import rrf_fuse


class HybridRetriever:
    """Orchestrate hybrid retrieval: BM25 + dense + graph."""

    def __init__(
        self,
        ollama_base_url: str = "http://localhost:11555",
        ollama_model: str = "nomic-embed-text",
        chroma_dir: str = "data/chroma",
        kb_data: Optional[Dict] = None
    ):
        """Khởi tạo HybridRetriever.

        Args:
            ollama_base_url: URL của Ollama server
            ollama_model: Model embeddings
            chroma_dir: Đường dẫn Chroma persistent dir
            kb_data: KB data để build BM25 index
        """
        self.embeddings = OllamaEmbeddings(ollama_base_url, ollama_model)
        self.vector_store = ChromaVectorStore(chroma_dir)
        self.bm25_store = BM25Store()
        self.graph_retriever = GraphRetriever()
        self.kb_data = kb_data or {}

        # Load hay build BM25 index
        if not self.bm25_store.load_index():
            self.bm25_store.build_from_kb(kb_data)

    def hybrid_search(
        self,
        query: str,
        top_k: int = 10,
        sources: Tuple[str, ...] = ("bm25", "dense", "graph"),
        kb_data: Optional[Dict] = None
    ) -> List[Dict]:
        """Hybrid search qua nhiều retriever.

        Args:
            query: Query string
            top_k: Số kết quả cuối cùng
            sources: Tuple các retriever để dùng (bm25/dense/graph)
            kb_data: KB data (để hydrate document content)

        Returns:
            List[Dict] with {id, source, content, score, retrievers}
        """
        if not query or not query.strip():
            return []

        kb_data = kb_data or self.kb_data
        results = {}

        # 1. BM25 search (parallel)
        bm25_results = {}
        if "bm25" in sources:
            bm25_results = self._bm25_search(query, kb_data)

        # 2. Dense search (parallel)
        dense_results = {}
        if "dense" in sources:
            dense_results = self._dense_search(query, kb_data)

        # 3. Graph search (parallel)
        graph_results = {}
        if "graph" in sources:
            graph_results = self._graph_search(query)

        # 4. RRF Fusion
        rankings = []
        if bm25_results:
            rankings.append([doc_id for doc_id, _ in sorted(
                bm25_results.items(), key=lambda x: x[1], reverse=True
            )[:20]])
        if dense_results:
            rankings.append([doc_id for doc_id, _ in sorted(
                dense_results.items(), key=lambda x: x[1], reverse=True
            )[:20]])
        if graph_results:
            rankings.append([r["id"] for r in graph_results[:20]])

        if rankings:
            fused = rrf_fuse(rankings, k=60)
            fused_ids = [doc_id for doc_id, _ in fused[:top_k]]
        else:
            fused_ids = []

        # 5. Hydrate document content
        for doc_id in fused_ids:
            # Find document in KB
            doc_content = self._hydrate_document(doc_id, kb_data)
            if doc_content:
                results[doc_id] = {
                    "id": doc_id,
                    "content": doc_content.get("text", ""),
                    "score": 0.0,  # RRF score không return
                    "retrievers": self._get_source_retrievers(
                        doc_id, bm25_results, dense_results, graph_results
                    )
                }

        return list(results.values())

    def _bm25_search(self, query: str, kb_data: Dict) -> Dict[str, float]:
        """BM25 full-text search."""
        results = {}

        for category in ["cves", "iocs", "malwares"]:
            ranked = self.bm25_store.query(category, query, top_k=20)
            for doc_id, score in ranked:
                results[doc_id] = score

        return results

    def _dense_search(self, query: str, kb_data: Dict) -> Dict[str, float]:
        """Dense vector search via Chroma."""
        results = {}

        try:
            # Embed query
            embedding = self.embeddings.embed([query])[0]

            # Search each collection
            for collection in ["kb_cves", "kb_iocs", "kb_malwares"]:
                hits = self.vector_store.query(collection, embedding, top_k=20)
                for hit in hits:
                    # Convert distance to similarity
                    similarity = 1.0 - hit["distance"]
                    results[hit["id"]] = similarity

        except Exception as e:
            pass  # Silent fail

        return results

    def _graph_search(self, query: str) -> List[Dict]:
        """Graph-based retrieval."""
        try:
            return self.graph_retriever.hybrid_retrieve(query, top_k=20)
        except Exception:
            return []

    def _hydrate_document(self, doc_id: str, kb_data: Dict) -> Optional[Dict]:
        """Lấy document content từ KB."""
        for category in ["cves", "iocs", "malwares"]:
            for doc in kb_data.get(category, []):
                if doc.get("id") == doc_id:
                    # Tạo text representation
                    text_parts = [
                        doc.get("name", ""),
                        doc.get("description", ""),
                        doc.get("content", "")
                    ]
                    return {
                        "text": " ".join(filter(None, text_parts)),
                        "metadata": doc
                    }
        return None

    @staticmethod
    def _get_source_retrievers(
        doc_id: str,
        bm25_results: Dict,
        dense_results: Dict,
        graph_results: List[Dict]
    ) -> List[str]:
        """Determine which retrievers found this document."""
        sources = []
        if doc_id in bm25_results:
            sources.append("bm25")
        if doc_id in dense_results:
            sources.append("dense")
        if any(r["id"] == doc_id for r in graph_results):
            sources.append("graph")
        return sources

    def close(self):
        """Close resources."""
        self.embeddings.close()
        self.vector_store.close()


# Global instance
_hybrid_retriever: Optional[HybridRetriever] = None


def init_hybrid_retriever(
    ollama_base_url: str = "http://localhost:11555",
    ollama_model: str = "nomic-embed-text",
    chroma_dir: str = "data/chroma",
    kb_data: Optional[Dict] = None
) -> HybridRetriever:
    """Initialize global hybrid retriever."""
    global _hybrid_retriever
    _hybrid_retriever = HybridRetriever(ollama_base_url, ollama_model, chroma_dir, kb_data)
    return _hybrid_retriever


def get_hybrid_retriever() -> Optional[HybridRetriever]:
    """Get global hybrid retriever."""
    return _hybrid_retriever


def hybrid_search(
    query: str,
    top_k: int = 10,
    sources: Tuple[str, ...] = ("bm25", "dense", "graph")
) -> List[Dict]:
    """Convenience function for hybrid search."""
    retriever = get_hybrid_retriever()
    if not retriever:
        return []
    return retriever.hybrid_search(query, top_k, sources)
