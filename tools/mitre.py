"""
tools/mitre.py - Tra cuu anh xa MITRE ATT&CK cho CVE tu co so du lieu cu bo
Su dung co so du lieu MITRE chinh thuc voi 858 ky thuat
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

def get_mitre_attack_info(cve_id: str) -> dict:
    """
    Lay anh xa ky thuat MITRE ATT&CK cho CVE

    Tra ve:
        dict voi keys: techniques (danh sach), threat_actors (danh sach), metadata
    """
    # Tai co so du lieu
    db = load_mitre_database()

    # Truy van tu co so du lieu cu bo
    cve_mapping = db.get("cve_mapping", {})
    techniques_db = db.get("techniques", {})

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
