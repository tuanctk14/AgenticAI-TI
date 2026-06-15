"""
tools/doc_store.py - Quản lý tài liệu và cơ sở tri thức
Hỗ trợ định dạng .json, .txt (trích xuất CVE ID), .csv
Tích hợp NVD KB loader để import CVE data từ D:\nvdcve
"""
import json
import csv
import re
from pathlib import Path
from datetime import datetime, timezone
from .nvd_knowledge_base_loader import get_kb_loader

KB_DIR = Path("data/docs")
KB_FILES = {
    "cves": KB_DIR / "cves.json",
    "iocs": KB_DIR / "iocs.json",
    "malwares": KB_DIR / "malwares.json"
}


def upload_document(file_path: str) -> dict:
    """Phân tích file và lưu vào KB. Hỗ trợ .json, .txt, .csv"""
    path = Path(file_path)
    if not path.exists():
        return {"error": f"File không tồn tại: {file_path}"}

    KB_DIR.mkdir(parents=True, exist_ok=True)
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

    # Phân loại và lưu
    saved = {"cves": 0, "iocs": 0, "malwares": 0}
    for r in records:
        category = _classify(r)
        _merge_and_save(category, r)
        saved[category] += 1

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


def _merge_and_save(category: str, record: dict):
    """Gộp bản ghi vào file KB (khử trùng theo id) và thêm timestamp tải lên"""
    kb_file = KB_FILES[category]
    existing = []
    if kb_file.exists():
        try:
            text = kb_file.read_text(encoding="utf-8").strip()
            if text:
                existing = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            existing = []

    ids = {r.get("id") for r in existing if r.get("id")}
    if record.get("id") not in ids:
        # Thêm timestamp tải lên nếu chưa có
        if "uploaded_date" not in record:
            record["uploaded_date"] = datetime.now(timezone.utc).isoformat()
        existing.append(record)

    kb_file.write_text(json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8")


def load_knowledge_base(category: str = "all") -> dict:
    """Tải bản ghi KB. category: 'all', 'cves', 'iocs', 'malwares'"""
    result = {}
    cats = list(KB_FILES.keys()) if category == "all" else [category]

    for cat in cats:
        f = KB_FILES.get(cat)
        if f and f.exists():
            result[cat] = json.loads(f.read_text(encoding="utf-8"))
        else:
            result[cat] = []

    return {"context": result, "source": "KB"}


def get_knowledge_base_stats() -> dict:
    """Lấy số lượng bản ghi per category và ngày tải lên mới nhất"""
    stats = {}
    for cat, f in KB_FILES.items():
        if f.exists():
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                # Lấy số lượng
                stats[cat] = {
                    "count": len(data),
                    "latest_upload": None
                }
                # Lấy ngày tải lên mới nhất
                if data:
                    dates = []
                    for record in data:
                        if record.get("uploaded_date"):
                            dates.append(record.get("uploaded_date"))
                    if dates:
                        # Sắp xếp và lấy ngày mới nhất
                        dates.sort(reverse=True)
                        # Định dạng ngày tốt (ISO → DD-MM-YYYY HH:MM)
                        latest_iso = dates[0]
                        try:
                            dt = datetime.fromisoformat(latest_iso.replace('Z', '+00:00'))
                            stats[cat]["latest_upload"] = dt.strftime("%d-%m-%Y %H:%M")
                        except:
                            stats[cat]["latest_upload"] = latest_iso[:10]
            except:
                stats[cat] = {"count": 0, "latest_upload": None}
        else:
            stats[cat] = {"count": 0, "latest_upload": None}

    return {"context": stats, "source": "KB"}


def fetch_kb_indicators(search_term: str = "", indicator_type: str = "all") -> dict:
    """
    Lấy IOC và Malware từ Knowledge Base (lưu trữ cục bộ)
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
        iocs_file = KB_FILES["iocs"]
        if iocs_file.exists():
            iocs = json.loads(iocs_file.read_text(encoding="utf-8"))
            for ioc in iocs:
                if not search_lower or (
                    search_lower in str(ioc.get("id", "")).lower() or
                    search_lower in str(ioc.get("description", "")).lower() or
                    search_lower in str(ioc.get("value", "")).lower() or
                    search_lower in str(ioc.get("threat_actor", "")).lower()
                ):
                    # Chuyển đổi để khớp với định dạng OpenCTI
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
                        "uploaded_date": ioc.get("uploaded_date"),
                        "source": "KB",
                    }
                    results.append(result)

    # Tải Malware nếu được yêu cầu
    if indicator_type in ["all", "malware"]:
        malwares_file = KB_FILES["malwares"]
        if malwares_file.exists():
            malwares = json.loads(malwares_file.read_text(encoding="utf-8"))
            for mal in malwares:
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
                        "uploaded_date": mal.get("uploaded_date"),
                        "source": "KB",
                    }
                    results.append(result)

    return {"context": results, "source": "KB"}


def fetch_kb_cves(search_term: str = "") -> dict:
    """
    Lấy CVE từ Knowledge Base

    Args:
        search_term: từ khóa tìm kiếm trong id hoặc description

    Trả về: dict với context chứa danh sách CVE
    """
    results = []
    search_lower = search_term.lower() if search_term else ""

    cves_file = KB_FILES["cves"]
    if cves_file.exists():
        cves = json.loads(cves_file.read_text(encoding="utf-8"))
        for cve in cves:
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
                    "uploaded_date": cve.get("uploaded_date"),
                    "source": "KB",
                }
                results.append(result)

    return {"context": results, "source": "KB"}


def enrich_cmdb_keywords() -> dict:
    """Trích xuất từ khóa từ KB CVE để làm phong phú khớp CMDB"""
    cves_file = KB_FILES["cves"]
    if not cves_file.exists():
        return {"context": {}, "source": "KB"}

    cves = json.loads(cves_file.read_text(encoding="utf-8"))
    keywords = {}

    for cve in cves:
        cid = cve.get("id", "")
        desc = (cve.get("description", "") or "").lower()

        words = [w for w in re.findall(r'\b\w+\b', desc) if len(w) > 3]
        if cid and words:
            keywords[cid] = words[:10]

    return {"context": keywords, "source": "KB"}


# ═══════════════════════════════════════════════════════════════════════════════
# NVD Knowledge Base Functions (Tích hợp với nvd_knowledge_base_loader)
# ═══════════════════════════════════════════════════════════════════════════════

def import_nvd_knowledge_base(user: str = "system") -> dict:
    """
    Import NVD CVE data từ D:\nvdcve vào KB nội bộ.
    Giữ structure theo năm, track metadata (import date, user, changes)

    Args:
        user: Username thực hiện import

    Returns:
        {
            "status": "success|error",
            "imported": 1500,
            "years": ["2021", "2020", ...],
            "details": {...}
        }
    """
    loader = get_kb_loader()
    result = loader.import_nvd_data(user=user)

    return {
        "context": result,
        "source": "NVD",
        "status": result.get("status", "unknown")
    }


def get_cve_from_kb(cve_id: str) -> dict:
    """
    Lấy CVE từ KB nội bộ (từ NVD data được import).

    Args:
        cve_id: "CVE-2021-39904"

    Returns:
        {
            "cve": {...},
            "_import": {metadata}
        } hoặc {"error": "..."}
    """
    loader = get_kb_loader()
    cve = loader.get_cve(cve_id)

    if cve:
        return {
            "context": cve,
            "source": "KB-NVD",
            "found": True
        }
    else:
        return {
            "context": None,
            "source": "KB-NVD",
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
        {"context": [cves], "source": "KB-NVD", "count": N}
    """
    loader = get_kb_loader()
    results = loader.search_cves(keyword, year)

    return {
        "context": results,
        "source": "KB-NVD",
        "count": len(results),
        "keyword": keyword,
        "year_filter": year
    }


def get_kb_status() -> dict:
    """
    Lấy trạng thái KB (tổng CVE, theo năm, import info, user uploads).

    Returns:
        {
            "total_cves": 1500,
            "years": {"2021": 100, ...},
            "imports": {"2021": {date, file, count}},
            "last_updated": "ISO"
        }
    """
    loader = get_kb_loader()
    stats = loader.get_kb_stats()

    return {
        "context": stats,
        "source": "KB-NVD",
        "ready": stats.get("total_cves", 0) > 0
    }


def record_cve_upload(cve_id: str, user: str, changes: str = "") -> dict:
    """
    Ghi nhận user upload/chỉnh sửa CVE.

    Args:
        cve_id: CVE ID
        user: Username
        changes: Nội dung thay đổi

    Returns:
        {"status": "recorded", "cve_id": "...", "user": "..."}
    """
    loader = get_kb_loader()
    loader.record_user_upload(cve_id, user, changes)

    return {
        "status": "recorded",
        "cve_id": cve_id,
        "user": user,
        "changes": changes,
        "timestamp": datetime.utcnow().isoformat()
    }
