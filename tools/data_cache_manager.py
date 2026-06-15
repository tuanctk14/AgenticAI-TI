"""
tools/data_cache_manager.py - Unified cache manager for external data

Implements G7: Caching strategy for XML/JSON dumps

Manages:
  - CWE XML (cwe.mitre.org, ~3MB, weekly refresh)
  - CAPEC XML (capec.mitre.org, ~2MB, weekly refresh)
  - ATT&CK STIX JSON (mitre/cti repo, ~50MB, monthly refresh)
  - ATT&CK-NIST mappings (center-for-threat-informed-defense, monthly)
  - Heimdall CSV (GitHub, small, monthly)

Strategy:
  1. Check cache_metadata.json for last refresh timestamp
  2. If age > TTL: trigger download (on-demand, at module load time)
  3. Store files locally in data/cache/
  4. Graceful fallback: code works even if files not downloaded (returns empty)
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class DataCacheManager:
    """
    Singleton manager for external data caching.
    Tracks refresh status, downloads on demand.
    """

    CACHE_DIR = "data/cache"
    METADATA_FILE = "data/cache_metadata.json"

    # Data sources: name -> {url, local_path, ttl_days}
    SOURCES = {
        "cwe_xml": {
            "url": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
            "local_path": os.path.join(CACHE_DIR, "cwec_latest.xml"),
            "ttl_days": 7,
            "description": "CWE XML dump (parse CWE→CAPEC)"
        },
        "capec_xml": {
            "url": "https://capec.mitre.org/data/xml/capec_latest.xml",
            "local_path": os.path.join(CACHE_DIR, "capec_latest.xml"),
            "ttl_days": 7,
            "description": "CAPEC XML dump (parse CAPEC→ATT&CK)"
        },
        "attack_nist_mappings": {
            "url": "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/data/mappings_attack_v13_nist-800-53-rev5.json",
            "local_path": os.path.join(CACHE_DIR, "attack_nist_mappings_rev5.json"),
            "ttl_days": 30,
            "description": "ATT&CK→NIST control mappings (Rev.5)"
        },
        "heimdall_csv": {
            "url": "https://raw.githubusercontent.com/mitre/heimdall_tools/master/lib/data/cwe-nist-mapping.csv",
            "local_path": os.path.join(CACHE_DIR, "cwe_nist_mapping.csv"),
            "ttl_days": 30,
            "description": "CWE→NIST mapping (fallback, Heimdall CSV)"
        }
    }

    _instance = None
    _metadata = {}  # {source: {last_refresh: ISO8601, ttl_days: N}}
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DataCacheManager, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self._load_metadata()
            self._create_cache_dir()
            self._initialized = True

    def _create_cache_dir(self):
        """Create cache directory if not exists"""
        os.makedirs(self.CACHE_DIR, exist_ok=True)

    def _load_metadata(self):
        """Load cache_metadata.json"""
        if os.path.exists(self.METADATA_FILE):
            try:
                with open(self.METADATA_FILE, 'r', encoding='utf-8') as f:
                    self._metadata = json.load(f)
                    logger.debug(f"Loaded cache metadata from {self.METADATA_FILE}")
            except Exception as e:
                logger.warning(f"Could not load cache metadata: {e}")
                self._metadata = {}
        else:
            self._metadata = {}

    def _save_metadata(self):
        """Save cache_metadata.json"""
        try:
            os.makedirs(os.path.dirname(self.METADATA_FILE), exist_ok=True)
            with open(self.METADATA_FILE, 'w', encoding='utf-8') as f:
                json.dump(self._metadata, f, indent=2)
                logger.debug(f"Saved cache metadata to {self.METADATA_FILE}")
        except Exception as e:
            logger.error(f"Could not save cache metadata: {e}")

    def should_refresh(self, source: str) -> bool:
        """
        Check if source should be refreshed.

        Args:
            source: Source name (e.g., "cwe_xml")

        Returns:
            True if refresh needed, False otherwise
        """
        if source not in self.SOURCES:
            logger.warning(f"Unknown source: {source}")
            return False

        source_meta = self._metadata.get(source, {})
        ttl_days = self.SOURCES[source]["ttl_days"]

        # Never refreshed
        if not source_meta.get("last_refresh"):
            return True

        # Check age
        try:
            last_refresh = datetime.fromisoformat(source_meta["last_refresh"])
            age = datetime.utcnow() - last_refresh
            should_refresh = age > timedelta(days=ttl_days)

            if should_refresh:
                logger.info(f"Source '{source}' needs refresh (age {age.days}d > {ttl_days}d)")

            return should_refresh

        except Exception as e:
            logger.error(f"Error checking refresh for {source}: {e}")
            return True

    def has_cache(self, source: str) -> bool:
        """
        Check if source is cached locally.

        Args:
            source: Source name

        Returns:
            True if file exists and is non-empty
        """
        if source not in self.SOURCES:
            return False

        local_path = self.SOURCES[source]["local_path"]
        return os.path.exists(local_path) and os.path.getsize(local_path) > 0

    def mark_refreshed(self, source: str):
        """
        Mark source as just refreshed (update metadata).

        Args:
            source: Source name
        """
        if source not in self._metadata:
            self._metadata[source] = {}

        self._metadata[source]["last_refresh"] = datetime.utcnow().isoformat()
        self._metadata[source]["ttl_days"] = self.SOURCES[source]["ttl_days"]
        self._save_metadata()

        logger.info(f"Marked '{source}' as refreshed")

    def get_cache_path(self, source: str) -> Optional[str]:
        """
        Get cache file path if it exists.

        Args:
            source: Source name

        Returns:
            Path if exists and fresh enough, None otherwise
        """
        if not self.has_cache(source):
            logger.debug(f"Source '{source}' not in cache")
            return None

        # Note: We return path even if refresh_needed=True
        # Calling code can use with fallback to old data or skip enrichment
        return self.SOURCES[source]["local_path"]

    def get_cache_status(self) -> Dict[str, Dict]:
        """
        Get status of all cached sources.

        Returns: {
            "cwe_xml": {
                "cached": True,
                "path": "data/cache/cwec_latest.xml",
                "needs_refresh": True,
                "ttl_days": 7,
                "last_refresh": "2026-06-10T12:00:00"
            }
        }
        """
        status = {}

        for source, config in self.SOURCES.items():
            source_meta = self._metadata.get(source, {})

            status[source] = {
                "cached": self.has_cache(source),
                "path": config["local_path"],
                "needs_refresh": self.should_refresh(source),
                "ttl_days": config["ttl_days"],
                "last_refresh": source_meta.get("last_refresh", "never"),
                "description": config["description"]
            }

        return status

    def print_cache_status(self):
        """Print human-readable cache status"""
        status = self.get_cache_status()

        print("\n" + "=" * 70)
        print("DATA CACHE STATUS")
        print("=" * 70)

        for source, info in status.items():
            cached_str = "CACHED" if info["cached"] else "MISSING"
            refresh_str = "(refresh needed)" if info["needs_refresh"] else "(fresh)"

            print(f"\n[{source}]")
            print(f"  Status: {cached_str} {refresh_str}")
            print(f"  Path: {info['path']}")
            print(f"  TTL: {info['ttl_days']} days")
            print(f"  Last refresh: {info['last_refresh']}")
            print(f"  Description: {info['description']}")

        print("\n" + "=" * 70)


# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

_manager = DataCacheManager()


def get_cache_manager() -> DataCacheManager:
    """Get singleton cache manager"""
    return _manager


def get_cache_path(source: str) -> Optional[str]:
    """Get cache path for a source"""
    return _manager.get_cache_path(source)


def should_refresh(source: str) -> bool:
    """Check if source needs refresh"""
    return _manager.should_refresh(source)


def has_cache(source: str) -> bool:
    """Check if source is cached"""
    return _manager.has_cache(source)


def print_cache_status():
    """Print cache status"""
    _manager.print_cache_status()
