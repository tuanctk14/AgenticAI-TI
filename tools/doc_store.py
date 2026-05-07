"""
tools/doc_store.py - Document upload and knowledge base management
Supports .json, .txt (CVE ID extraction), .csv formats
"""
import json
import csv
import re
from pathlib import Path

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
    """Merge record into KB file (dedup by id)"""
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
    """Get count of records per category"""
    stats = {}
    for cat, f in KB_FILES.items():
        if f.exists():
            data = json.loads(f.read_text(encoding="utf-8"))
            stats[cat] = len(data)
        else:
            stats[cat] = 0

    return {"context": stats, "source": "KB"}


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
