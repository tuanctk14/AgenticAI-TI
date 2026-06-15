"""
tools/nvd_knowledge_base_loader.py - Load NVD CVE data from local JSON files

Reads from D:\nvdcve (nvdcve-2.0-YYYY.json files) and imports into knowledge base.
Preserves year-based organization and metadata (source, import date).

Structure:
  KB/
    cves/
      2021/
        CVE-2021-39904.json
        CVE-2021-12345.json
      2020/
        CVE-2020-xxxxx.json
      ...
    metadata.json (tracks imports, users, changes)
"""

import json
import os
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import gzip

logger = logging.getLogger(__name__)

# Paths
NVD_DATA_DIR = Path("D:/nvdcve")  # Local NVD JSON dumps
KB_DIR = Path("data/knowledge_base")
KB_CVE_DIR = KB_DIR / "cves"
KB_METADATA_FILE = KB_DIR / "kb_metadata.json"


class NVDKnowledgeBaseLoader:
    """Load NVD CVE data into knowledge base by year."""

    def __init__(self):
        """Initialize KB directories."""
        self._ensure_directories()
        self._load_metadata()

    def _ensure_directories(self):
        """Create KB directories if not exists."""
        KB_DIR.mkdir(parents=True, exist_ok=True)
        KB_CVE_DIR.mkdir(parents=True, exist_ok=True)

    def _load_metadata(self):
        """Load KB metadata tracking."""
        if KB_METADATA_FILE.exists():
            try:
                with open(KB_METADATA_FILE, 'r', encoding='utf-8') as f:
                    self.metadata = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load metadata: {e}")
                self.metadata = self._init_metadata()
        else:
            self.metadata = self._init_metadata()

    def _init_metadata(self) -> dict:
        """Initialize empty metadata."""
        return {
            "imports": {},  # {year: {date, file, count, source}}
            "user_uploads": {},  # {cve_id: {date, user, file, changes}}
            "last_updated": None,
            "total_cves": 0
        }

    def _save_metadata(self):
        """Save metadata to file."""
        try:
            KB_DIR.mkdir(parents=True, exist_ok=True)
            with open(KB_METADATA_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save metadata: {e}")

    def import_nvd_data(self, year: Optional[int] = None, user: str = "system") -> Dict:
        """
        Import NVD CVE data from local files.

        Args:
            year: Specific year to import (None = all years)
            user: Username performing import

        Returns:
            {
                "status": "success" | "error",
                "imported": 1500,
                "years": ["2021", "2020", ...],
                "details": {...}
            }
        """
        results = {
            "status": "success",
            "imported": 0,
            "years": [],
            "errors": [],
            "details": {}
        }

        if not NVD_DATA_DIR.exists():
            results["status"] = "error"
            results["errors"].append(f"NVD data directory not found: {NVD_DATA_DIR}")
            return results

        # Find NVD files
        nvd_files = sorted(NVD_DATA_DIR.glob("nvdcve-2.0-*.json"))

        if not nvd_files:
            results["status"] = "error"
            results["errors"].append(f"No NVD files found in {NVD_DATA_DIR}")
            return results

        # Filter by year if specified
        if year:
            nvd_files = [f for f in nvd_files if str(year) in f.name]

        # Import each file
        for nvd_file in nvd_files:
            year_str = nvd_file.stem.split('-')[-1]  # Extract year from filename
            result = self._import_nvd_file(nvd_file, year_str, user)

            results["imported"] += result.get("imported", 0)
            results["years"].append(year_str)
            results["details"][year_str] = result

            if result.get("error"):
                results["errors"].append(result["error"])

        # Update metadata
        self.metadata["last_updated"] = datetime.utcnow().isoformat()
        self._save_metadata()

        return results

    def _import_nvd_file(self, nvd_file: Path, year: str, user: str) -> Dict:
        """
        Import single NVD JSON file.

        Returns:
            {"imported": N, "skipped": M, "error": "..."}
        """
        result = {
            "imported": 0,
            "skipped": 0,
            "error": None
        }

        try:
            logger.info(f"Importing {nvd_file.name}...")

            with open(nvd_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            vulnerabilities = data.get("vulnerabilities", [])
            year_dir = KB_CVE_DIR / year
            year_dir.mkdir(parents=True, exist_ok=True)

            # Import each CVE
            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id")

                if not cve_id:
                    result["skipped"] += 1
                    continue

                # Save CVE as individual JSON
                cve_file = year_dir / f"{cve_id}.json"

                try:
                    with open(cve_file, 'w', encoding='utf-8') as f:
                        # Store with metadata
                        cve_obj = {
                            "cve": cve_data,
                            "_import": {
                                "date": datetime.utcnow().isoformat(),
                                "source": "nvd",
                                "file": nvd_file.name,
                                "year": year
                            }
                        }
                        json.dump(cve_obj, f, indent=2)

                    result["imported"] += 1

                except Exception as e:
                    logger.error(f"Could not save {cve_id}: {e}")
                    result["skipped"] += 1

            # Update import metadata
            self.metadata["imports"][year] = {
                "date": datetime.utcnow().isoformat(),
                "file": nvd_file.name,
                "count": result["imported"],
                "source": "nvd",
                "user": user
            }

            logger.info(f"Imported {result['imported']} CVEs from {year}")

        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Error importing {nvd_file.name}: {e}")

        return result

    def get_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Get CVE from KB by ID.

        Args:
            cve_id: "CVE-2021-39904"

        Returns:
            CVE object or None
        """
        # Extract year from CVE ID (CVE-YYYY-XXXXX)
        parts = cve_id.split('-')
        if len(parts) < 2:
            return None

        year = parts[1]
        cve_file = KB_CVE_DIR / year / f"{cve_id}.json"

        if not cve_file.exists():
            return None

        try:
            with open(cve_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Could not read {cve_id}: {e}")
            return None

    def search_cves(self, keyword: str, year: Optional[str] = None) -> List[Dict]:
        """
        Search CVEs by keyword.

        Args:
            keyword: Search term
            year: Filter by year (None = all)

        Returns:
            [{cve_id, title, description, year}, ...]
        """
        results = []
        keyword_lower = keyword.lower()

        # Search directories
        if year:
            search_dirs = [KB_CVE_DIR / year]
        else:
            search_dirs = [d for d in KB_CVE_DIR.iterdir() if d.is_dir()]

        for year_dir in search_dirs:
            if not year_dir.is_dir():
                continue

            year_name = year_dir.name

            for cve_file in year_dir.glob("*.json"):
                try:
                    with open(cve_file, 'r', encoding='utf-8') as f:
                        cve_obj = json.load(f)

                    cve_data = cve_obj.get("cve", {})
                    cve_id = cve_data.get("id", "")

                    # Search in description + title + references
                    descriptions = cve_data.get("descriptions", [])
                    desc_text = " ".join([d.get("value", "") for d in descriptions]).lower()

                    if keyword_lower in desc_text or keyword_lower in cve_id.lower():
                        results.append({
                            "cve_id": cve_id,
                            "description": descriptions[0].get("value", "")[:200] if descriptions else "N/A",
                            "year": year_name,
                            "published": cve_data.get("published", "N/A")
                        })

                except Exception as e:
                    logger.debug(f"Error searching {cve_file}: {e}")

        return results

    def get_kb_stats(self) -> Dict:
        """Get KB statistics."""
        stats = {
            "total_cves": 0,
            "years": {},
            "imports": self.metadata.get("imports", {}),
            "user_uploads_count": len(self.metadata.get("user_uploads", {})),
            "last_updated": self.metadata.get("last_updated")
        }

        for year_dir in KB_CVE_DIR.iterdir():
            if not year_dir.is_dir():
                continue

            year = year_dir.name
            cve_count = len(list(year_dir.glob("*.json")))
            stats["years"][year] = cve_count
            stats["total_cves"] += cve_count

        return stats

    def record_user_upload(self, cve_id: str, user: str, changes: str = ""):
        """
        Record user upload/modification.

        Args:
            cve_id: CVE ID
            user: Username
            changes: What changed
        """
        if cve_id not in self.metadata["user_uploads"]:
            self.metadata["user_uploads"][cve_id] = []

        self.metadata["user_uploads"][cve_id].append({
            "date": datetime.utcnow().isoformat(),
            "user": user,
            "changes": changes
        })

        self._save_metadata()

    def export_kb_summary(self) -> Dict:
        """Export KB summary for UI."""
        stats = self.get_kb_stats()

        return {
            "status": "ready",
            "total_cves": stats["total_cves"],
            "years": stats["years"],
            "last_updated": stats["last_updated"],
            "imports": stats["imports"],
            "user_uploads": len(stats["user_uploads_count"])
        }


# Singleton
_loader = None


def get_kb_loader() -> NVDKnowledgeBaseLoader:
    """Get KB loader singleton."""
    global _loader
    if _loader is None:
        _loader = NVDKnowledgeBaseLoader()
    return _loader


def import_nvd_initial(user: str = "system") -> Dict:
    """Initial import of all NVD data."""
    loader = get_kb_loader()
    return loader.import_nvd_data(user=user)
