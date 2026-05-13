"""
tools/mitre.py - Tra cuu anh xa MITRE ATT&CK cho CVE tu co so du lieu cu bo
Su dung co so du lieu MITRE chinh thuc voi 858 ky thuat
Fallback den cve_inference khi CVE khong co trong database
"""
import json
from pathlib import Path
from typing import Dict, List, Optional

# Database path
MITRE_DB_PATH = Path(__file__).parent.parent / "data" / "mitre_attack.json"

def load_mitre_database() -> Optional[dict]:
    """Tai co so du lieu MITRE ATT&CK cu bo"""
    if not MITRE_DB_PATH.exists():
        raise FileNotFoundError(f"MITRE database not found: {MITRE_DB_PATH}")

    try:
        with open(MITRE_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Khong the tai co so du lieu MITRE: {e}")
        raise

def get_mitre_attack_info(cve_id: str, cve_description: str = "", cwe_ids: list = None) -> dict:
    """
    Lay anh xa ky thuat MITRE ATT&CK cho CVE

    CWE resolution hierarchy:
    1. cwe_ids parameter (CWE chinh thuc tu NVD weaknesses) - highest priority
    2. Truy van tu co so du lieu CVE cu bo
    3. Inference tu description

    Tra ve:
        dict voi keys: techniques (danh sach), threat_actors (danh sach), metadata, source
    """
    from tools.cwe_mapper import CWEMapper

    # Tai co so du lieu
    db = load_mitre_database()
    techniques_db = db.get("techniques", {})
    cve_mapping = db.get("cve_mapping", {})

    tech_ids = []

    # PHASE 1: Use official CWE IDs from NVD (highest priority)
    if cwe_ids:
        cwe_mapper = CWEMapper()
        # Lam sach CWE IDs
        valid_cwes = [c for c in cwe_ids if c.startswith("CWE-") or c.isdigit()]
        if valid_cwes:
            for cwe_id in valid_cwes:
                techniques = cwe_mapper.cwe_to_mitre_techniques(cwe_id)
                for tech in techniques:
                    if tech["id"] not in tech_ids:
                        tech_ids.append(tech["id"])
            if tech_ids:
                return {
                    "context": {
                        "techniques": _build_technique_details(tech_ids, techniques_db),
                        "threat_actors": [],
                        "source": "cwe_nvd_chinh_thuc",
                        "cwe_ids_used": valid_cwes,
                    }
                }

    # PHASE 2: CVE mapping from local database
    if cve_id in cve_mapping:
        tech_ids = cve_mapping[cve_id]
        techniques = []

        for tech_id in tech_ids:
            if tech_id in techniques_db:
                tech = techniques_db[tech_id]
                techniques.append({
                    "id": tech_id,
                    "name": tech.get("name", "Khong xac dinh"),
                    "tactic": tech.get("tactics", ["Khong xac dinh"])[0] if tech.get("tactics") else "Khong xac dinh",
                    "description": tech.get("description", ""),
                    "mitigations": tech.get("mitigations", []),
                })

        if techniques:
            return {
                "context": {
                    "techniques": techniques,
                    "threat_actors": [],
                    "source": "csdl_mitre_dia_phuong",
                }
            }

    # Khong tim thay du lieu
    return {
        "context": {
            "techniques": [],
            "threat_actors": [],
            "source": "khong_co",
        }
    }


def _build_technique_details(tech_ids: list, techniques_db: dict) -> list:
    """Helper to build technique details from tech IDs"""
    techniques = []
    for tech_id in tech_ids:
        if tech_id in techniques_db:
            tech = techniques_db[tech_id]
            techniques.append({
                "id": tech_id,
                "name": tech.get("name", "Khong xac dinh"),
                "tactic": tech.get("tactics", ["Khong xac dinh"])[0] if tech.get("tactics") else "Khong xac dinh",
                "description": tech.get("description", ""),
                "mitigations": tech.get("mitigations", []),
            })
    return techniques
