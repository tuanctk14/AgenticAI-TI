# -*- coding: utf-8 -*-
"""
tools/kb_populator.py - Đổ dữ liệu IOC vào Knowledge Base

Hệ thống để lưu IOC trích xuất từ malware/campaign vào KB:
- Tạo entry IOC mới
- Cập nhật IOC hiện tại
- Tạo relationship IOC↔Malware/Campaign/CVE
- Deduplication và conflict resolution
"""

import json
from pathlib import Path
from datetime import datetime
from tools.ioc_extractor import IOCExtractor


class KBPopulator:
    """Quản lý việc đổ dữ liệu vào knowledge base."""

    def __init__(self, kb_dir: str = "data/docs"):
        self.kb_dir = Path(kb_dir)
        self.kb_dir.mkdir(parents=True, exist_ok=True)
        self.iocs_file = self.kb_dir / "iocs.json"

    def load_iocs(self) -> list:
        """Tải danh sách IOC hiện tại từ KB."""
        if self.iocs_file.exists():
            try:
                return json.loads(self.iocs_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return []
        return []

    def save_iocs(self, iocs: list) -> bool:
        """Lưu danh sách IOC vào KB."""
        try:
            self.iocs_file.write_text(
                json.dumps(iocs, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
            return True
        except Exception as e:
            print(f"  [KBPopulator] Error saving IOCs: {e}")
            return False

    def add_ioc(self, ioc_dict: dict) -> dict:
        """
        Thêm IOC mới vào KB hoặc cập nhật nếu đã tồn tại.

        Args:
            ioc_dict: {
                "type": "domain",
                "value": "example.com",
                "source": "malware|campaign|cve",
                "malware_name": "...",
                "campaign_name": "...",
                "cve_id": "...",
                "confidence": 90,
                "first_seen": "2021-12-10",
            }

        Returns: {
            "status": "added|updated",
            "ioc": {...}
        }
        """
        iocs = self.load_iocs()

        # Tìm IOC hiện tại
        existing = None
        for idx, ioc in enumerate(iocs):
            if (ioc.get("type") == ioc_dict.get("type") and
                ioc.get("value") == ioc_dict.get("value")):
                existing = (idx, ioc)
                break

        ioc_dict["updated_at"] = datetime.now().isoformat()

        if existing:
            idx, existing_ioc = existing
            # Cập nhật thông tin nếu không có
            if not existing_ioc.get("first_seen"):
                existing_ioc["first_seen"] = ioc_dict.get("first_seen", datetime.now().isoformat()[:10])

            # Thêm relationship mới
            if "relationships" not in existing_ioc:
                existing_ioc["relationships"] = []

            # Tạo relationship object
            rel = {
                "source": ioc_dict.get("source"),
                "malware_name": ioc_dict.get("malware_name"),
                "campaign_name": ioc_dict.get("campaign_name"),
                "cve_id": ioc_dict.get("cve_id"),
                "confidence": ioc_dict.get("confidence", 75),
                "discovered_at": datetime.now().isoformat()
            }

            # Dedup relationships
            rel_key = f"{rel['source']}:{rel.get('malware_name') or rel.get('campaign_name') or rel.get('cve_id')}"
            existing_rel_keys = set()
            for er in existing_ioc["relationships"]:
                er_key = f"{er['source']}:{er.get('malware_name') or er.get('campaign_name') or er.get('cve_id')}"
                existing_rel_keys.add(er_key)

            if rel_key not in existing_rel_keys:
                existing_ioc["relationships"].append(rel)

            # Cập nhật confidence cao nhất
            if ioc_dict.get("confidence", 0) > existing_ioc.get("confidence", 0):
                existing_ioc["confidence"] = ioc_dict.get("confidence")

            existing_ioc["updated_at"] = ioc_dict["updated_at"]
            iocs[idx] = existing_ioc

            status = "updated"
            result_ioc = existing_ioc
        else:
            # Tạo IOC mới
            new_ioc = {
                "id": f"IOC-{ioc_dict.get('type').upper()}-{len(iocs)+1:05d}",
                "type": ioc_dict.get("type"),
                "value": ioc_dict.get("value"),
                "description": ioc_dict.get("description", ""),
                "confidence": ioc_dict.get("confidence", 75),
                "first_seen": ioc_dict.get("first_seen", datetime.now().isoformat()[:10]),
                "relationships": [{
                    "source": ioc_dict.get("source"),
                    "malware_name": ioc_dict.get("malware_name"),
                    "campaign_name": ioc_dict.get("campaign_name"),
                    "cve_id": ioc_dict.get("cve_id"),
                    "confidence": ioc_dict.get("confidence", 75),
                    "discovered_at": ioc_dict["updated_at"]
                }],
                "created_at": ioc_dict["updated_at"],
                "updated_at": ioc_dict["updated_at"],
            }
            iocs.append(new_ioc)
            status = "added"
            result_ioc = new_ioc

        # Lưu
        self.save_iocs(iocs)

        return {
            "status": status,
            "ioc": result_ioc
        }

    def add_iocs_from_extraction(self, extraction_result: dict, cve_id: str = None) -> dict:
        """
        Thêm tất cả IOC từ extraction result vào KB.

        Args:
            extraction_result: Output từ IOCExtractor.extract_from_cve_relationships()
            cve_id: CVE ID (nếu không có trong result)

        Returns: {
            "status": "completed",
            "added": 5,
            "updated": 3,
            "total": 8,
            "iocs": [...]
        }
        """
        cve_id = cve_id or extraction_result.get("cve_id", "Unknown")
        iocs_to_add = extraction_result.get("iocs_extracted", [])

        added_count = 0
        updated_count = 0
        processed_iocs = []

        for ioc in iocs_to_add:
            ioc["cve_id"] = cve_id
            result = self.add_ioc(ioc)
            processed_iocs.append(result["ioc"])

            if result["status"] == "added":
                added_count += 1
            elif result["status"] == "updated":
                updated_count += 1

        return {
            "status": "completed",
            "cve_id": cve_id,
            "added": added_count,
            "updated": updated_count,
            "total_processed": len(iocs_to_add),
            "iocs": processed_iocs
        }

    def get_iocs_by_type(self, ioc_type: str) -> list:
        """Lấy tất cả IOC của một loại."""
        iocs = self.load_iocs()
        return [ioc for ioc in iocs if ioc.get("type") == ioc_type]

    def get_iocs_by_malware(self, malware_name: str) -> list:
        """Lấy tất cả IOC liên quan đến một malware."""
        iocs = self.load_iocs()
        result = []
        for ioc in iocs:
            for rel in ioc.get("relationships", []):
                if rel.get("malware_name") == malware_name:
                    result.append(ioc)
                    break
        return result

    def get_iocs_by_cve(self, cve_id: str) -> list:
        """Lấy tất cả IOC liên quan đến một CVE."""
        iocs = self.load_iocs()
        result = []
        for ioc in iocs:
            for rel in ioc.get("relationships", []):
                if rel.get("cve_id") == cve_id:
                    result.append(ioc)
                    break
        return result

    def get_kb_stats(self) -> dict:
        """Lấy thống kê KB."""
        iocs = self.load_iocs()
        stats = {
            "total_iocs": len(iocs),
            "by_type": {},
            "by_confidence": {
                "high": 0,    # 80-100
                "medium": 0,  # 50-79
                "low": 0      # 0-49
            }
        }

        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            if ioc_type not in stats["by_type"]:
                stats["by_type"][ioc_type] = 0
            stats["by_type"][ioc_type] += 1

            confidence = ioc.get("confidence", 0)
            if confidence >= 80:
                stats["by_confidence"]["high"] += 1
            elif confidence >= 50:
                stats["by_confidence"]["medium"] += 1
            else:
                stats["by_confidence"]["low"] += 1

        return stats


def populate_kb_from_cve(cve_dict: dict) -> dict:
    """
    Hàm tiêu chuẩn để trích xuất và lưu IOC từ CVE enriched.

    Args:
        cve_dict: CVE object với relationships

    Returns: KB population result
    """
    print(f"  [KBPopulator] Đổ dữ liệu IOC vào KB từ {cve_dict.get('id')}...")

    try:
        cve_id = cve_dict.get("id", "Unknown")

        # Trích xuất IOC
        extraction = IOCExtractor.extract_from_cve_relationships(cve_dict)

        if extraction.get("status") == "error":
            print(f"  [KBPopulator] ERROR: {extraction.get('error')}")
            return extraction

        # Thêm vào KB
        populator = KBPopulator()
        result = populator.add_iocs_from_extraction(extraction, cve_id)

        print(f"  [KBPopulator] SUCCESS: {result['added']} added, {result['updated']} updated")

        return {
            "cve_id": cve_id,
            "status": "populated",
            "iocs_added": result["added"],
            "iocs_updated": result["updated"],
            "total_iocs_processed": result["total_processed"],
        }

    except Exception as e:
        print(f"  [KBPopulator] ERROR: {e}")
        return {
            "cve_id": cve_dict.get("id"),
            "status": "error",
            "error": str(e)
        }
