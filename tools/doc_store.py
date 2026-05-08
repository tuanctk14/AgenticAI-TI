"""
tools/doc_store.py - Document upload and knowledge base management
Supports .json, .txt (CVE ID extraction), .csv formats
"""
import json
import csv
import re
from pathlib import Path
from datetime import datetime, timezone

KB_DIR = Path("data/docs")
KB_FILES = {
    "cves": KB_DIR / "cves.json",
    "iocs": KB_DIR / "iocs.json",
    "malwares": KB_DIR / "malwares.json"
}


def upload_document(file_path: str) -> dict:
    """Parse file and save to KB. Supports .json, .txt, .csv"""
    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}"}

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
            return {"error": f"Unsupported format: {ext}. Use .json, .txt, or .csv"}
    except Exception as e:
        return {"error": f"Parse error: {e}"}

    if not records:
        return {"error": "No valid records found in file"}

    # Classify and save
    saved = {"cves": 0, "iocs": 0, "malwares": 0}
    for r in records:
        category = _classify(r)
        _merge_and_save(category, r)
        saved[category] += 1

    return {"context": saved, "source": "KB", "total": sum(saved.values())}


def _parse_json(path: Path) -> list:
    """Parse JSON file (array or single object)"""
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else [data]


def _parse_txt(path: Path) -> list:
    """Extract CVE IDs from text file"""
    text = path.read_text(encoding="utf-8")
    cve_ids = re.findall(r'CVE-\d{4}-\d+', text)
    return [{"id": cid, "source": "txt_upload"} for cid in set(cve_ids)]


def _parse_csv(path: Path) -> list:
    """Parse CSV file into records"""
    rows = []
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row:
                rows.append(dict(row))
    return rows


def _classify(record: dict) -> str:
    """Classify record as cves, iocs, or malwares"""
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
    """Merge record into KB file (dedup by id) and add upload timestamp"""
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
        # Add upload timestamp if not already present
        if "uploaded_date" not in record:
            record["uploaded_date"] = datetime.now(timezone.utc).isoformat()
        existing.append(record)

    kb_file.write_text(json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8")


def load_knowledge_base(category: str = "all") -> dict:
    """Load KB records. category: 'all', 'cves', 'iocs', 'malwares'"""
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
    """Get count of records per category and latest upload date"""
    stats = {}
    for cat, f in KB_FILES.items():
        if f.exists():
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                # Get count
                stats[cat] = {
                    "count": len(data),
                    "latest_upload": None
                }
                # Get latest upload date
                if data:
                    dates = []
                    for record in data:
                        if record.get("uploaded_date"):
                            dates.append(record.get("uploaded_date"))
                    if dates:
                        # Sort and get the latest date
                        dates.sort(reverse=True)
                        # Format the date nicely (ISO format → DD-MM-YYYY HH:MM)
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
    Fetch IOCs and Malwares from Knowledge Base (local storage)
    Compatible with OpenCTI interface for agent integration

    Args:
        search_term: keyword to search in description/id/malware_family
        indicator_type: "all" (both IOC and Malware), "ioc", or "malware"

    Returns: dict with context containing list of indicators
    """
    results = []
    search_lower = search_term.lower() if search_term else ""

    # Load IOCs if requested
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
                    # Transform to match OpenCTI format
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

    # Load Malwares if requested
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
                        "source": "KB",
                    }
                    results.append(result)

    return {"context": results, "source": "KB"}


def fetch_kb_cves(search_term: str = "") -> dict:
    """
    Fetch CVEs from Knowledge Base

    Args:
        search_term: keyword to search in id or description

    Returns: dict with context containing list of CVEs
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
                result = {
                    "id": cve.get("id"),
                    "description": cve.get("description", ""),
                    "cvss_score": cve.get("cvss_score", 0),
                    "severity": "CRITICAL" if cve.get("cvss_score", 0) >= 9.0 else
                               "HIGH" if cve.get("cvss_score", 0) >= 7.0 else
                               "MEDIUM" if cve.get("cvss_score", 0) >= 4.0 else
                               "LOW",
                    "source": "KB",
                }
                results.append(result)

    return {"context": results, "source": "KB"}


def enrich_cmdb_keywords() -> dict:
    """Extract keywords from KB CVEs for CMDB matching enrichment"""
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
