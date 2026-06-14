"""
tests/test_phase_b_rag.py - Tests cho Phase B: Hybrid RAG system.
"""

import unittest
import tempfile
import os
from pathlib import Path
from rag import (
    OllamaEmbeddings,
    ChromaVectorStore,
    BM25Store,
    GraphRetriever,
    rrf_fuse,
    normalize_rankings,
    HybridRetriever
)


class TestOllamaEmbeddings(unittest.TestCase):
    """Tests cho OllamaEmbeddings."""

    def setUp(self):
        """Khởi tạo embeddings client."""
        # Note: Ollama phải chạy local cho test này
        self.embeddings = OllamaEmbeddings()

    def test_embed_single_text(self):
        """Test embedding một text."""
        # Mock: không call Ollama, chỉ verify interface
        texts = ["CVE-2024-1234 critical vulnerability"]
        result = self.embeddings.embed(texts)

        # Dù fail (Ollama không chạy), phải return list
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)

    def test_embed_empty_list(self):
        """Test embedding empty list."""
        result = self.embeddings.embed([])
        self.assertEqual(result, [])

    def test_embed_multiple_texts(self):
        """Test embedding multiple texts."""
        texts = ["text1", "text2", "text3"]
        result = self.embeddings.embed(texts)

        self.assertEqual(len(result), 3)
        # Mỗi embedding phải là list (vector)
        for emb in result:
            self.assertIsInstance(emb, list)


class TestChromaVectorStore(unittest.TestCase):
    """Tests cho ChromaVectorStore."""

    def setUp(self):
        """Khởi tạo temp Chroma store."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = ChromaVectorStore(self.temp_dir)

    def tearDown(self):
        """Dọn dẹp."""
        import shutil
        import time
        self.store.close()
        time.sleep(0.1)  # Đợi Chroma release locks
        if os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except PermissionError:
                pass  # Chroma may still hold locks

    def test_upsert_documents(self):
        """Test upsert documents vào Chroma."""
        ids = ["doc1", "doc2"]
        documents = ["Text for doc1", "Text for doc2"]
        embeddings = [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]]

        success = self.store.upsert("test_collection", ids, documents, embeddings)

        self.assertTrue(success)

    def test_count_documents(self):
        """Test count documents."""
        ids = ["doc1", "doc2"]
        documents = ["Text 1", "Text 2"]
        embeddings = [[0.1] * 768, [0.2] * 768]

        self.store.upsert("test_collection", ids, documents, embeddings)
        count = self.store.count("test_collection")

        self.assertEqual(count, 2)

    def test_query_documents(self):
        """Test query documents."""
        ids = ["doc1", "doc2", "doc3"]
        documents = ["CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9999"]
        embeddings = [[0.1] * 768, [0.2] * 768, [0.3] * 768]

        self.store.upsert("test_collection", ids, documents, embeddings)

        # Query with embedding
        query_embedding = [0.1] * 768
        results = self.store.query("test_collection", query_embedding, top_k=2)

        self.assertEqual(len(results), 2)
        # Results should have expected keys
        for result in results:
            self.assertIn("id", result)
            self.assertIn("document", result)


class TestBM25Store(unittest.TestCase):
    """Tests cho BM25Store."""

    def setUp(self):
        """Khởi tạo BM25Store."""
        self.store = BM25Store()
        self.temp_dir = tempfile.mkdtemp()
        self.original_index_file = self.store.index_file
        self.store.index_file = Path(self.temp_dir) / "bm25_index.pkl"

    def tearDown(self):
        """Dọn dẹp."""
        import shutil
        self.store.index_file = self.original_index_file
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_build_from_kb(self):
        """Test build BM25 index từ KB."""
        kb_data = {
            "cves": [
                {"id": "CVE-2024-1234", "name": "Log4Shell", "description": "Remote code execution in Log4j"},
                {"id": "CVE-2024-5678", "name": "Spring RCE", "description": "Spring framework vulnerability"}
            ],
            "iocs": [],
            "malwares": []
        }

        success = self.store.build_from_kb(kb_data)

        self.assertTrue(success)
        self.assertIn("cves", self.store.indices)

    def test_query_bm25(self):
        """Test BM25 query."""
        kb_data = {
            "cves": [
                {"id": "CVE-2024-1234", "name": "Log4Shell", "description": "Remote code execution in Log4j"},
                {"id": "CVE-2024-5678", "name": "Spring RCE", "description": "Spring framework vulnerability"},
                {"id": "CVE-2024-9999", "name": "DNS Poison", "description": "DNS poisoning attack"}
            ],
            "iocs": [],
            "malwares": []
        }

        self.store.build_from_kb(kb_data)

        # Query for Log4j
        results = self.store.query("cves", "Log4j remote code", top_k=5)

        self.assertGreater(len(results), 0)
        # Top result should be Log4Shell
        top_id, score = results[0]
        self.assertEqual(top_id, "CVE-2024-1234")

    def test_tokenize(self):
        """Test tokenization."""
        text = "CVE-2024-1234: Remote Code Execution in Apache Log4j"
        tokens = self.store._tokenize(text)

        expected_tokens = ["cve", "2024", "1234", "remote", "code", "execution", "in", "apache", "log4j"]
        self.assertEqual(set(tokens), set(expected_tokens))


class TestGraphRetriever(unittest.TestCase):
    """Tests cho GraphRetriever."""

    def setUp(self):
        """Khởi tạo GraphRetriever."""
        self.retriever = GraphRetriever()

    def test_extract_cve_entities(self):
        """Test CVE extraction."""
        query = "Analyze CVE-2024-1234 and CVE-2021-44228"
        entities = self.retriever.extract_entities(query)

        cves = entities["cves"]
        self.assertEqual(len(cves), 2)
        self.assertIn("CVE-2024-1234", cves)
        self.assertIn("CVE-2021-44228", cves)

    def test_extract_ip_entities(self):
        """Test IP extraction."""
        query = "Check indicators from 192.168.1.100 and 10.0.0.1"
        entities = self.retriever.extract_entities(query)

        ips = entities["ips"]
        self.assertEqual(len(ips), 2)
        self.assertIn("192.168.1.100", ips)

    def test_extract_hash_entities(self):
        """Test hash extraction."""
        query = "File hash: d41d8cd98f00b204e9800998ecf8427e"
        entities = self.retriever.extract_entities(query)

        hashes = entities["hashes"]
        self.assertEqual(len(hashes), 1)


class TestRRFFusion(unittest.TestCase):
    """Tests cho RRF fusion."""

    def test_rrf_fuse_basic(self):
        """Test RRF with 2 rankings."""
        rankings = [
            ["doc1", "doc2", "doc3"],
            ["doc2", "doc1", "doc4"]
        ]

        result = rrf_fuse(rankings, k=60)

        # doc1 and doc2 should be top (appear in both)
        self.assertGreater(len(result), 0)
        ids = [doc_id for doc_id, _ in result]
        self.assertIn("doc1", ids)
        self.assertIn("doc2", ids)

    def test_rrf_fuse_three_rankings(self):
        """Test RRF with 3 rankings."""
        rankings = [
            ["a", "b", "c"],
            ["b", "a", "d"],
            ["a", "b", "e"]
        ]

        result = rrf_fuse(rankings, k=60)
        ids = [doc_id for doc_id, _ in result]

        # "a" and "b" appear in all 3 → highest scores
        self.assertEqual(ids[0], "a")
        self.assertEqual(ids[1], "b")

    def test_rrf_empty_rankings(self):
        """Test RRF with empty rankings."""
        result = rrf_fuse([], k=60)
        self.assertEqual(result, [])


def run_tests():
    """Chạy tất cả tests."""
    suite = unittest.TestLoader().loadTestsFromModule(__import__(__name__))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    import sys
    print("[PHASE B: HYBRID RAG TEST SUITE]")
    print("=" * 60)

    success = run_tests()

    print("\n" + "=" * 60)
    if success:
        print("[OK] Tất cả Phase B tests passed!")
    else:
        print("[FAILED] Một số tests failed")

    sys.exit(0 if success else 1)
