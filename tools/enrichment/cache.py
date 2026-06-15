"""
tools/enrichment/cache.py - Provider-level caching abstraction

Supports:
- SQLite (local, offline-friendly)
- Future: Redis, PostgreSQL
"""

import json
import sqlite3
import asyncio
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Optional
from pathlib import Path
from .schema import UnifiedCVE


class CacheProvider(ABC):
    """Abstract caching interface"""

    @abstractmethod
    async def get(self, cve_id: str) -> Optional[UnifiedCVE]:
        """Retrieve cached CVE or None if not found/expired"""
        raise NotImplementedError

    @abstractmethod
    async def set(self, cve_id: str, data: UnifiedCVE, ttl: int = 86400) -> bool:
        """Cache CVE data with TTL (default 24h)"""
        raise NotImplementedError

    @abstractmethod
    async def exists(self, cve_id: str) -> bool:
        """Check if cache entry exists and is not expired"""
        raise NotImplementedError

    @abstractmethod
    async def clear(self, cve_id: str) -> bool:
        """Delete cache entry"""
        raise NotImplementedError


class SQLiteCacheProvider(CacheProvider):
    """SQLite-based cache (simple, offline, file-based)"""

    def __init__(self, db_path: str = "./data/enrichment_cache.db"):
        """Initialize SQLite cache"""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Create cache table if not exists"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                cached_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    async def get(self, cve_id: str) -> Optional[UnifiedCVE]:
        """Retrieve cached CVE if exists and not expired"""
        return await asyncio.to_thread(self._get_sync, cve_id)

    def _get_sync(self, cve_id: str) -> Optional[UnifiedCVE]:
        """Synchronous get for thread execution"""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()

            cursor.execute(
                "SELECT data, expires_at FROM cve_cache WHERE cve_id = ?",
                (cve_id,)
            )
            row = cursor.fetchone()
            conn.close()

            if not row:
                return None

            # Check expiration
            expires_at = datetime.fromisoformat(row["expires_at"])
            if datetime.now() > expires_at:
                # Cache expired, delete it
                asyncio.create_task(self.clear(cve_id))
                return None

            # Deserialize and return
            data_dict = json.loads(row["data"])
            return UnifiedCVE(**data_dict)
        except Exception as e:
            print(f"[CACHE] Error retrieving {cve_id}: {e}")
            return None

    async def set(self, cve_id: str, data: UnifiedCVE, ttl: int = 86400) -> bool:
        """Cache CVE data with TTL"""
        return await asyncio.to_thread(self._set_sync, cve_id, data, ttl)

    def _set_sync(self, cve_id: str, data: UnifiedCVE, ttl: int) -> bool:
        """Synchronous set for thread execution"""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()

            # Serialize CVE with custom datetime encoder
            data_dict = data.model_dump()
            # Pydantic v2 already serializes datetime to ISO format in dict representation
            data_json = json.dumps(data_dict, default=str)

            # Calculate expiration
            expires_at = datetime.now() + timedelta(seconds=ttl)

            cursor.execute(
                """INSERT OR REPLACE INTO cve_cache (cve_id, data, expires_at)
                   VALUES (?, ?, ?)""",
                (cve_id, data_json, expires_at.isoformat())
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[CACHE] Error caching {cve_id}: {e}")
            return False

    async def exists(self, cve_id: str) -> bool:
        """Check if cache entry exists and is not expired"""
        return await asyncio.to_thread(self._exists_sync, cve_id)

    def _exists_sync(self, cve_id: str) -> bool:
        """Synchronous exists check"""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()

            cursor.execute(
                "SELECT expires_at FROM cve_cache WHERE cve_id = ?",
                (cve_id,)
            )
            row = cursor.fetchone()
            conn.close()

            if not row:
                return False

            expires_at = datetime.fromisoformat(row["expires_at"])
            return datetime.now() < expires_at
        except Exception:
            return False

    async def clear(self, cve_id: str) -> bool:
        """Delete cache entry"""
        return await asyncio.to_thread(self._clear_sync, cve_id)

    def _clear_sync(self, cve_id: str) -> bool:
        """Synchronous clear"""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cve_cache WHERE cve_id = ?", (cve_id,))
            conn.commit()
            conn.close()
            return True
        except Exception:
            return False

    async def cleanup_expired(self) -> int:
        """Clean up expired entries. Returns number of deleted rows."""
        return await asyncio.to_thread(self._cleanup_expired_sync)

    def _cleanup_expired_sync(self) -> int:
        """Synchronous cleanup"""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM cve_cache WHERE expires_at < ?",
                (datetime.now().isoformat(),)
            )
            conn.commit()
            deleted = cursor.rowcount
            conn.close()
            return deleted
        except Exception as e:
            print(f"[CACHE] Error during cleanup: {e}")
            return 0

    async def get_stats(self) -> dict:
        """Get cache statistics"""
        return await asyncio.to_thread(self._get_stats_sync)

    def _get_stats_sync(self) -> dict:
        """Synchronous stats"""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) as total FROM cve_cache")
            total = cursor.fetchone()["total"]

            cursor.execute(
                "SELECT COUNT(*) as expired FROM cve_cache WHERE expires_at < ?",
                (datetime.now().isoformat(),)
            )
            expired = cursor.fetchone()["expired"]

            conn.close()
            return {
                "total_entries": total,
                "expired_entries": expired,
                "active_entries": total - expired,
            }
        except Exception:
            return {"total_entries": 0, "expired_entries": 0, "active_entries": 0}
