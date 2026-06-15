"""
tools/doc_store.py - Quản lý tài liệu và cơ sở tri thức
Hỗ trợ định dạng .json, .txt (trích xuất CVE ID), .csv
Tích hợp unified KB manager (data/knowledge_base) cho tất cả data

NOTE: Legacy fallback functions (load_knowledge_base, fetch_kb_indicators, fetch_kb_cves) now read from
data/knowledge_base instead of data/docs for backward compatibility. Primary path is unified KB.
"""
import json
import csv
import re
from pathlib import Path
from datetime import datetime, timezone
from .knowledge_base_manager import get_kb_manager

# Legacy compatibility - these functions read from unified KB now
KB_DIR = Path("data/knowledge_base")
KB_FILES = {
    "cves": KB_DIR / "cves",
    "iocs": KB_DIR / "iocs",
    "malwares": KB_DIR / "malwares"
}


def upload_document(file_path: str, user: str = "system") -> dict:
    """
    Phân tích file và lưu vào KB.
    Hỗ trợ .json, .txt (trích CVE ID), .csv

    Args:
        file_path: Path to file
        user: Username uploading

    Returns:
        {"context": {cves, iocs, malwares}, "source": "KB", "total": N}
    """
    path = Path(file_path)
    if not path.exists():
        return {"error": f"File không tồn tại: {file_path}"}

    ext = path.suffix.lower()

    try:
        if ext == ".json":
            records = _parse_json(path)
        elif ext == ".txt":
            records = _parse_txt(path)
        elif ext == ".csv":
            records = _parse_csv(path)
        else:
            return {"error": f"Định dạng không hỗ trợ: {ext}. Dùng .json, .txt, hoặc .csv"}
    except Exception as e:
        return {"error": f"Lỗi phân tích: {e}"}

    if not records:
        return {"error": "Không tìm thấy bản ghi hợp lệ trong file"}

    # Phân loại và lưu vào unified KB
    kb = get_kb_manager()
    saved = {"cves": 0, "iocs": 0, "malwares": 0}

    for r in records:
        category = _classify(r)

        # Save to unified KB
        if category == "cves":
            cve_id = r.get("id", "")
            if cve_id:
                kb.save_cve(cve_id, r, user=user, source="user_upload", changes=f"Uploaded from {path.name}")
                saved["cves"] += 1
        elif category == "iocs":
            ioc_id = r.get("id", "")
            if ioc_id:
                kb.save_ioc(ioc_id, r, user=user)
                saved["iocs"] += 1
        elif category == "malwares":
            mal_id = r.get("id", "")
            if mal_id:
                kb.save_malware(mal_id, r, user=user)
                saved["malwares"] += 1

    return {"context": saved, "source": "KB", "total": sum(saved.values())}


def _parse_json(path: Path) -> list:
    """Phân tích file JSON (mảng hoặc object đơn)"""
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else [data]


def _parse_txt(path: Path) -> list:
    """Trích xuất CVE IDs từ file text"""
    text = path.read_text(encoding="utf-8")
    cve_ids = re.findall(r'CVE-\d{4}-\d+', text)
    return [{"id": cid, "source": "txt_upload"} for cid in set(cve_ids)]


def _parse_csv(path: Path) -> list:
    """Phân tích file CSV thành bản ghi"""
    rows = []
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row:
                rows.append(dict(row))
    return rows


def _classify(record: dict) -> str:
    """Phân loại bản ghi thành cves, iocs, hoặc malwares"""
    rid = str(record.get("id", "")).upper()
    if rid.startswith("CVE-"):
        return "cves"

    # Check ID prefix first
    if rid.startswith("MAL-"):
        return "malwares"
    if rid.startswith("IOC-"):
        return "iocs"

    rtype = str(record.get("type", "") or record.get("indicator_type", "")).lower()

    # Malware types: backdoor, ransomware, trojan, virus, worm, rat, infostealer,
    # credential_dumper, post_exploitation, banking_trojan, dropper, etc.
    malware_keywords = [
        "malware", "ransomware", "trojan", "virus", "worm", "backdoor",
        "rat", "infostealer", "credential_dumper", "post_exploitation",
        "banking_trojan", "dropper", "loader", "spyware"
    ]
    if any(kw in rtype for kw in malware_keywords):
        return "malwares"

    # IOC types: hash, domain, ip, url, email, file, indicator, sha256, sha1, md5, etc.
    ioc_keywords = [
        "hash", "domain", "ip", "url", "indicator", "sha256", "sha1", "md5",
        "email", "file", "ipv4", "ipv6"
    ]
    if any(kw in rtype for kw in ioc_keywords):
        return "iocs"

    # Default: if has malware_family, it's likely malware info
    if record.get("malware_family"):
        return "malwares"

    # Default to IOC if unsure
    return "iocs"


def load_knowledge_base(category: str = "all") -> dict:
    """
    Tải bản ghi KB từ unified knowledge_base.
    Category: 'all', 'cves', 'iocs', 'malwares'
    """
    result = {}
    cats = list(KB_FILES.keys()) if category == "all" else [category]

    for cat in cats:
        cat_dir = KB_FILES.get(cat)
        result[cat] = []

        if cat_dir and cat_dir.exists():
            # Read from YYYY/ subdirectories
            for year_dir in cat_dir.iterdir():
                if year_dir.is_dir():
                    for file_path in year_dir.glob("*.json"):
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                obj = json.load(f)
                                # Extract the actual data (remove metadata fields)
                                if cat == "cves":
                                    obj_data = obj.get("cve", obj)
                                elif cat == "iocs":
                                    obj_data = obj.get("ioc", obj)
                                elif cat == "malwares":
                                    obj_data = obj.get("malware", obj)
                                else:
                                    obj_data = obj
                                result[cat].append(obj_data)
                        except Exception as e:
                            pass  # Skip invalid files

    return {"context": result, "source": "KB"}


def get_knowledge_base_stats() -> dict:
    """Lấy số lượng bản ghi per category và ngày tải lên mới nhất từ unified KB"""
    stats = {}
    for cat, cat_dir in KB_FILES.items():
        count = 0
        latest_date = None

        if cat_dir and cat_dir.exists():
            # Count all files in YYYY/ subdirectories
            for year_dir in cat_dir.iterdir():
                if year_dir.is_dir():
                    for file_path in year_dir.glob("*.json"):
                        count += 1
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                obj = json.load(f)
                                # Get metadata last_updated
                                metadata = obj.get("_metadata", {})
                                last_updated = metadata.get("last_updated")
                                if last_updated:
                                    if not latest_date or last_updated > latest_date:
                                        latest_date = last_updated
                        except:
                            pass

        stats[cat] = {
            "count": count,
            "latest_upload": None
        }

        if latest_date:
            try:
                dt = datetime.fromisoformat(latest_date.replace('Z', '+00:00'))
                stats[cat]["latest_upload"] = dt.strftime("%d-%m-%Y %H:%M")
            except:
                stats[cat]["latest_upload"] = latest_date[:10] if latest_date else None

    return {"context": stats, "source": "KB"}


def fetch_kb_indicators(search_term: str = "", indicator_type: str = "all") -> dict:
    """
    Lấy IOC và Malware từ unified Knowledge Base.
    Tương thích với giao diện OpenCTI để tích hợp agent

    Args:
        search_term: từ khóa tìm kiếm trong description/id/malware_family
        indicator_type: "all" (cả IOC và Malware), "ioc", hoặc "malware"

    Trả về: dict với context chứa danh sách indicators
    """
    results = []
    search_lower = search_term.lower() if search_term else ""

    # Tải IOC nếu được yêu cầu
    if indicator_type in ["all", "ioc"]:
        iocs_dir = KB_FILES["iocs"]
        if iocs_dir and iocs_dir.exists():
            for year_dir in iocs_dir.iterdir():
                if year_dir.is_dir():
                    for file_path in year_dir.glob("*.json"):
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                obj = json.load(f)
                                ioc = obj.get("ioc", obj)
                                if not search_lower or (
                                    search_lower in str(ioc.get("id", "")).lower() or
                                    search_lower in str(ioc.get("description", "")).lower() or
                                    search_lower in str(ioc.get("value", "")).lower() or
                                    search_lower in str(ioc.get("threat_actor", "")).lower()
                                ):
                                    result = {
                                        "entity_type": "Indicator",
                                        "id": ioc.get("id"),
                                        "name": f"{ioc.get('type', 'unknown').upper()}: {ioc.get('value', ioc.get('id', ''))}",
                                        "pattern": ioc.get("value", ""),
                                        "description": ioc.get("description", ""),
                                        "type": ioc.get("type", ""),
                                        "value": ioc.get("value", ""),
                                        "cvss_score": ioc.get("cvss_score", 0),
                                        "threat_actor": ioc.get("threat_actor", ""),
                                        "tags": ioc.get("tags", []),
                                        "confidence": 80,
                                        "score": ioc.get("cvss_score", 0) / 10 if ioc.get("cvss_score") else 8,
                                        "source": "KB",
                                    }
                                    results.append(result)
                        except:
                            pass

    # Tải Malware nếu được yêu cầu
    if indicator_type in ["all", "malware"]:
        malwares_dir = KB_FILES["malwares"]
        if malwares_dir and malwares_dir.exists():
            for year_dir in malwares_dir.iterdir():
                if year_dir.is_dir():
                    for file_path in year_dir.glob("*.json"):
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                obj = json.load(f)
                                mal = obj.get("malware", obj)
                                if not search_lower or (
                                    search_lower in str(mal.get("id", "")).lower() or
                                    search_lower in str(mal.get("malware_family", "")).lower() or
                                    search_lower in str(mal.get("description", "")).lower() or
                                    search_lower in str(mal.get("threat_actor", "")).lower()
                                ):
                                    result = {
                                        "entity_type": "Malware",
                                        "id": mal.get("id"),
                                        "name": mal.get("malware_family", mal.get("id", "")),
                                        "malware_types": [mal.get("type", "")],
                                        "description": mal.get("description", ""),
                                        "cvss_score": mal.get("cvss_score", 0),
                                        "threat_actor": mal.get("threat_actor", ""),
                                        "aliases": [mal.get("id", "")],
                                        "confidence": 85,
                                        "score": mal.get("cvss_score", 0) / 10 if mal.get("cvss_score") else 8,
                                        "source": "KB",
                                    }
                                    results.append(result)
                        except:
                            pass

    return {"context": results, "source": "KB"}


def fetch_kb_cves(search_term: str = "") -> dict:
    """
    Lấy CVE từ unified Knowledge Base

    Args:
        search_term: từ khóa tìm kiếm trong id hoặc description

    Trả về: dict với context chứa danh sách CVE
    """
    results = []
    search_lower = search_term.lower() if search_term else ""

    cves_dir = KB_FILES["cves"]
    if cves_dir and cves_dir.exists():
        for year_dir in cves_dir.iterdir():
            if year_dir.is_dir():
                for file_path in year_dir.glob("*.json"):
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            obj = json.load(f)
                            cve = obj.get("cve", obj)
                            if not search_lower or (
                                search_lower in str(cve.get("id", "")).lower() or
                                search_lower in str(cve.get("description", "")).lower()
                            ):
                                cvss = float(cve.get("cvss_score", 0)) if cve.get("cvss_score") else 0
                                result = {
                                    "id": cve.get("id"),
                                    "description": cve.get("description", ""),
                                    "cvss_score": cvss,
                                    "severity": "CRITICAL" if cvss >= 9.0 else
                                               "HIGH" if cvss >= 7.0 else
                                               "MEDIUM" if cvss >= 4.0 else
                                               "LOW",
                                    "source": "KB",
                                }
                                results.append(result)
                    except:
                        pass

    return {"context": results, "source": "KB"}


def enrich_cmdb_keywords() -> dict:
    """Trích xuất từ khóa từ unified KB CVE để làm phong phú khớp CMDB"""
    keywords = {}
    cves_dir = KB_FILES["cves"]

    if cves_dir and cves_dir.exists():
        for year_dir in cves_dir.iterdir():
            if year_dir.is_dir():
                for file_path in year_dir.glob("*.json"):
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            obj = json.load(f)
                            cve = obj.get("cve", obj)
                            cid = cve.get("id", "")
                            desc = (cve.get("description", "") or "").lower()

                            words = [w for w in re.findall(r'\b\w+\b', desc) if len(w) > 3]
                            if cid and words:
                                keywords[cid] = words[:10]
                    except:
                        pass

    return {"context": keywords, "source": "KB"}


# ═══════════════════════════════════════════════════════════════════════════════
# Unified Knowledge Base Functions (data/knowledge_base for all data)
# ═══════════════════════════════════════════════════════════════════════════════

def get_cve_from_kb(cve_id: str) -> dict:
    """
    Lấy CVE từ KB nội bộ (NVD data hoặc auto-cached từ API).

    Args:
        cve_id: "CVE-2021-39904"

    Returns:
        {
            "cve": {...full NVD data...},
            "_metadata": {user, date, source},
            "_import": {...},
            "_edits": [...]
        }
    """
    kb = get_kb_manager()
    cve = kb.get_cve(cve_id)

    if cve:
        return {
            "context": cve,
            "source": "KB",
            "found": True,
            "metadata": cve.get("_metadata", {})
        }
    else:
        return {
            "context": None,
            "source": "KB",
            "found": False,
            "error": f"CVE {cve_id} not found in KB"
        }


def search_kb_cves(keyword: str, year: str = None) -> dict:
    """
    Tìm kiếm CVE trong KB theo keyword.

    Args:
        keyword: Từ khóa tìm kiếm
        year: Lọc theo năm (None = tất cả)

    Returns:
        {"context": [cves], "source": "KB", "count": N}
    """
    kb = get_kb_manager()
    results = kb.search_cves(keyword, year)

    return {
        "context": results,
        "source": "KB",
        "count": len(results),
        "keyword": keyword,
        "year_filter": year
    }


def save_cve_to_kb(
    cve_id: str,
    cve_data: dict,
    user: str = "system",
    source: str = "user_upload",
    changes: str = ""
) -> dict:
    """
    Lưu CVE vào KB (từ user upload hoặc API cache).

    Args:
        cve_id: CVE ID
        cve_data: Full CVE object
        user: Username
        source: "user_upload"|"api"|"nvd"
        changes: Change description

    Returns:
        {"status": "saved|error", "cve_id": "...", "user": "..."}
    """
    kb = get_kb_manager()
    success = kb.save_cve(cve_id, cve_data, user=user, source=source, changes=changes)

    return {
        "status": "saved" if success else "error",
        "cve_id": cve_id,
        "user": user,
        "source": source,
        "changes": changes,
        "timestamp": datetime.now().isoformat()
    }


def get_kb_status() -> dict:
    """
    Lấy trạng thái KB (tổng CVE/IOC/Malware, theo năm, user uploads).

    Returns:
        {
            "total_cves": 1500,
            "cves_by_year": {"2021": 100, ...},
            "total_iocs": 50,
            "user_uploads": 10,
            "auto_cached": 5,
            "last_updated": "ISO"
        }
    """
    kb = get_kb_manager()
    stats = kb.get_kb_stats()

    return {
        "context": stats,
        "source": "KB",
        "ready": stats.get("total_cves", 0) > 0
    }


def save_ioc_to_kb(ioc_id: str, ioc_data: dict, user: str = "system") -> dict:
    """Lưu IOC vào KB."""
    kb = get_kb_manager()
    success = kb.save_ioc(ioc_id, ioc_data, user=user)

    return {
        "status": "saved" if success else "error",
        "ioc_id": ioc_id,
        "user": user
    }


def save_malware_to_kb(malware_id: str, malware_data: dict, user: str = "system") -> dict:
    """Lưu Malware vào KB."""
    kb = get_kb_manager()
    success = kb.save_malware(malware_id, malware_data, user=user)

    return {
        "status": "saved" if success else "error",
        "malware_id": malware_id,
        "user": user
    }
