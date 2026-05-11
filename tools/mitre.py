"""
tools/mitre.py - Tra cứu MITRE ATT&CK mapping cho CVE từ local database
"""
import json
from pathlib import Path
from typing import Dict, List, Optional

# Database path
MITRE_DB_PATH = Path(__file__).parent.parent / "data" / "mitre_attack.json"

# Fallback mock data (for when database unavailable)
MOCK_CVE_TO_ATTACK: dict[str, dict] = {
    "CVE-2021-44228": {
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application",
             "tactic": "Initial Access",
             "description": "Khai thác Log4Shell để có initial access qua JNDI injection."},
            {"id": "T1059", "name": "Command and Scripting Interpreter",
             "tactic": "Execution",
             "description": "Thực thi shell sau khi khai thác thành công Log4Shell RCE."},
        ],
        "threat_actors": ["APT41", "Lazarus Group", "Hafnium"],
    },
    "CVE-2021-41773": {
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application",
             "tactic": "Initial Access",
             "description": "Path traversal trong Apache 2.4.49 cho phép đọc file nhạy cảm."},
        ],
        "threat_actors": ["Various Cybercriminals"],
    },
}

def load_mitre_database() -> Optional[dict]:
    """Load local MITRE ATT&CK database"""
    if not MITRE_DB_PATH.exists():
        return None

    try:
        with open(MITRE_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Failed to load MITRE database: {e}")
        return None

def get_mitre_attack_info(cve_id: str) -> dict:
    """
    Lấy MITRE ATT&CK techniques mapping cho CVE

    Returns:
        dict với keys: techniques (list), threat_actors (list), metadata
    """
    # Load database
    db = load_mitre_database()

    if db:
        # Query from local database
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
                        "name": tech.get("name", "Unknown"),
                        "tactic": tech.get("tactics", ["Unknown"])[0] if tech.get("tactics") else "Unknown",
                        "description": tech.get("description", ""),
                        "mitigations": tech.get("mitigations", []),
                    })

            if techniques:
                return {
                    "context": {
                        "techniques": techniques,
                        "threat_actors": [],  # Can be extended with threat intel
                        "source": "local_mitre_database",
                    }
                }

    # Fallback to mock data
    if cve_id in MOCK_CVE_TO_ATTACK:
        attack_data = MOCK_CVE_TO_ATTACK[cve_id]
        return {
            "context": {
                "techniques": attack_data.get("techniques", []),
                "threat_actors": attack_data.get("threat_actors", []),
                "source": "mock_data",
            }
        }

    # No data found
    return {
        "context": {
            "techniques": [],
            "threat_actors": [],
            "source": "none",
        }
    }
