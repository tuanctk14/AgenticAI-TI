"""
tools/knowledge_base_manager.py - Unified Knowledge Base Manager

Tích hợp tất cả CVE data vào data/knowledge_base:
- NVD imports (từ D:\nvdcve) - sẵn có
- User uploads (từ Menu 3) - migrate từ data/docs
- Auto-cached from NVD API (từ Menu 1 searches)
- Metadata tracking: người up, ngày, chỉnh sửa

Structure:
  data/knowledge_base/
    cves/
      YYYY/
        CVE-XXXX-XXXXX.json (với _metadata field)
    iocs/
      YYYY/
        IOC-XXXXX.json
    malwares/
      YYYY/
        MAL-XXXXX.json
    kb_metadata.json (global tracking)
"""

import json
import os
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

KB_ROOT = Path("data/knowledge_base")
KB_CVE_DIR = KB_ROOT / "cves"
KB_IOC_DIR = KB_ROOT / "iocs"
KB_MALWARE_DIR = KB_ROOT / "malwares"
KB_METADATA_FILE = KB_ROOT / "kb_metadata.json"


class KnowledgeBaseManager:
    """Unified KB manager - handles CVE, IOC, Malware storage."""

    def __init__(self):
        """Initialize KB directories."""
        self._ensure_directories()
        self._load_metadata()

    def _ensure_directories(self):
        """Create KB directories if not exists."""
        for dir_path in [KB_CVE_DIR, KB_IOC_DIR, KB_MALWARE_DIR]:
            dir_path.mkdir(parents=True, exist_ok=True)

    def _load_metadata(self):
        """Load global KB metadata."""
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
        """Initialize metadata structure."""
        return {
            "imports": {},  # {year: {count, date, source}}
            "uploads": {},  # {cve_id: {user, date, changes}}
            "auto_cached": {},  # {cve_id: {date, source}} - từ API lấy
            "total_cves": 0,
            "last_updated": None
        }

    def _save_metadata(self):
        """Save metadata."""
        try:
            KB_ROOT.mkdir(parents=True, exist_ok=True)
            with open(KB_METADATA_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save metadata: {e}")

    def save_cve(
        self,
        cve_id: str,
        cve_data: dict,
        user: str = "system",
        source: str = "api",
        changes: str = ""
    ) -> bool:
        """
        Save CVE to KB.

        Args:
            cve_id: "CVE-2021-39904"
            cve_data: Full CVE object from NVD
            user: Username (system|analyst name)
            source: "nvd"|"api"|"user_upload"
            changes: What changed (for updates)

        Returns:
            True if saved
        """
        # Extract year from CVE ID
        parts = cve_id.split('-')
        if len(parts) < 2:
            logger.error(f"Invalid CVE ID: {cve_id}")
            return False

        year = parts[1]
        year_dir = KB_CVE_DIR / year
        year_dir.mkdir(parents=True, exist_ok=True)

        cve_file = year_dir / f"{cve_id}.json"

        try:
            # Load existing if exists
            existing = None
            if cve_file.exists():
                with open(cve_file, 'r', encoding='utf-8') as f:
                    existing = json.load(f)

            # Build CVE object with metadata
            cve_obj = {
                "cve": cve_data,
                "_metadata": {
                    "last_updated": datetime.utcnow().isoformat(),
                    "user": user,
                    "source": source,
                    "changes": changes,
                    "year": year
                }
            }

            # Preserve import history if exists
            if existing and "_import" in existing:
                cve_obj["_import"] = existing["_import"]
            elif "_import" not in cve_obj and source == "api":
                cve_obj["_import"] = {
                    "date": datetime.utcnow().isoformat(),
                    "source": source,
                    "year": year
                }

            # Preserve edit history
            if existing and "_edits" in existing:
                cve_obj["_edits"] = existing["_edits"]
            else:
                cve_obj["_edits"] = []

            # Add this edit to history
            cve_obj["_edits"].append({
                "date": datetime.utcnow().isoformat(),
                "user": user,
                "source": source,
                "changes": changes
            })

            # Save to file
            with open(cve_file, 'w', encoding='utf-8') as f:
                json.dump(cve_obj, f, indent=2)

            # Update metadata
            if cve_id not in self.metadata["uploads"]:
                self.metadata["uploads"][cve_id] = []

            self.metadata["uploads"][cve_id].append({
                "date": datetime.utcnow().isoformat(),
                "user": user,
                "source": source,
                "changes": changes
            })

            self.metadata["last_updated"] = datetime.utcnow().isoformat()
            self._save_metadata()

            logger.info(f"Saved {cve_id} by {user} (source: {source})")
            return True

        except Exception as e:
            logger.error(f"Could not save {cve_id}: {e}")
            return False

    def get_cve(self, cve_id: str) -> Optional[dict]:
        """Get CVE from KB."""
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
        """Search CVEs in KB by keyword and optional year."""
        results = []
        keyword_lower = keyword.lower()

        # Determine search directories
        if year:
            search_dirs = [KB_CVE_DIR / year] if (KB_CVE_DIR / year).exists() else []
        else:
            search_dirs = [d for d in KB_CVE_DIR.iterdir() if d.is_dir()]

        for year_dir in search_dirs:
            for cve_file in year_dir.glob("*.json"):
                try:
                    with open(cve_file, 'r', encoding='utf-8') as f:
                        cve_obj = json.load(f)

                    cve_data = cve_obj.get("cve", {})
                    cve_id = cve_data.get("id", "")

                    # Search in description + ID
                    descriptions = cve_data.get("descriptions", [])
                    desc_text = " ".join([d.get("value", "") for d in descriptions]).lower()

                    if keyword_lower in desc_text or keyword_lower in cve_id.lower():
                        results.append({
                            "cve_id": cve_id,
                            "description": descriptions[0].get("value", "")[:200] if descriptions else "N/A",
                            "year": year_dir.name,
                            "published": cve_data.get("published", "N/A"),
                            "metadata": cve_obj.get("_metadata", {})
                        })

                except Exception as e:
                    logger.debug(f"Error searching {cve_file}: {e}")

        return results

    def save_ioc(
        self,
        ioc_id: str,
        ioc_data: dict,
        user: str = "system"
    ) -> bool:
        """Save IOC to KB (same structure as CVE)."""
        year = datetime.now().year
        year_dir = KB_IOC_DIR / str(year)
        year_dir.mkdir(parents=True, exist_ok=True)

        ioc_file = year_dir / f"{ioc_id}.json"

        try:
            ioc_obj = {
                "ioc": ioc_data,
                "_metadata": {
                    "date": datetime.utcnow().isoformat(),
                    "user": user,
                    "year": str(year)
                }
            }

            with open(ioc_file, 'w', encoding='utf-8') as f:
                json.dump(ioc_obj, f, indent=2)

            logger.info(f"Saved IOC {ioc_id} by {user}")
            return True
        except Exception as e:
            logger.error(f"Could not save IOC {ioc_id}: {e}")
            return False

    def save_malware(
        self,
        malware_id: str,
        malware_data: dict,
        user: str = "system"
    ) -> bool:
        """Save Malware to KB."""
        year = datetime.now().year
        year_dir = KB_MALWARE_DIR / str(year)
        year_dir.mkdir(parents=True, exist_ok=True)

        mal_file = year_dir / f"{malware_id}.json"

        try:
            mal_obj = {
                "malware": malware_data,
                "_metadata": {
                    "date": datetime.utcnow().isoformat(),
                    "user": user,
                    "year": str(year)
                }
            }

            with open(mal_file, 'w', encoding='utf-8') as f:
                json.dump(mal_obj, f, indent=2)

            logger.info(f"Saved Malware {malware_id} by {user}")
            return True
        except Exception as e:
            logger.error(f"Could not save Malware {malware_id}: {e}")
            return False

    def get_kb_stats(self) -> Dict:
        """Get KB statistics."""
        stats = {
            "total_cves": 0,
            "total_iocs": 0,
            "total_malwares": 0,
            "cves_by_year": {},
            "iocs_by_year": {},
            "malwares_by_year": {},
            "user_uploads": len(self.metadata.get("uploads", {})),
            "auto_cached": len(self.metadata.get("auto_cached", {})),
            "last_updated": self.metadata.get("last_updated")
        }

        # Count CVEs by year
        for year_dir in KB_CVE_DIR.iterdir():
            if year_dir.is_dir():
                count = len(list(year_dir.glob("*.json")))
                stats["cves_by_year"][year_dir.name] = count
                stats["total_cves"] += count

        # Count IOCs by year
        for year_dir in KB_IOC_DIR.iterdir():
            if year_dir.is_dir():
                count = len(list(year_dir.glob("*.json")))
                stats["iocs_by_year"][year_dir.name] = count
                stats["total_iocs"] += count

        # Count Malwares by year
        for year_dir in KB_MALWARE_DIR.iterdir():
            if year_dir.is_dir():
                count = len(list(year_dir.glob("*.json")))
                stats["malwares_by_year"][year_dir.name] = count
                stats["total_malwares"] += count

        return stats


# Singleton
_manager = None


def get_kb_manager() -> KnowledgeBaseManager:
    """Get KB manager singleton."""
    global _manager
    if _manager is None:
        _manager = KnowledgeBaseManager()
    return _manager
