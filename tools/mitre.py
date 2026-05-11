"""
tools/mitre.py - Tra cứu ánh xạ MITRE ATT&CK cho CVE từ cơ sở dữ liệu cục bộ
Sử dụng cơ sở dữ liệu MITRE chính thức với 858 kỹ thuật
"""
import json
from pathlib import Path
from typing import Dict, List, Optional

# Database path
MITRE_DB_PATH = Path(__file__).parent.parent / "data" / "mitre_attack.json"

# Dữ liệu mock dự phòng (khi cơ sở dữ liệu không có sẵn)
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
    """Tải cơ sở dữ liệu MITRE ATT&CK cục bộ"""
    if not MITRE_DB_PATH.exists():
        return None

    try:
        with open(MITRE_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Không thể tải cơ sở dữ liệu MITRE: {e}")
        return None

def get_mitre_attack_info(cve_id: str) -> dict:
    """
    Lấy ánh xạ kỹ thuật MITRE ATT&CK cho CVE

    Trả về:
        dict với keys: techniques (danh sách), threat_actors (danh sách), metadata
    """
    # Tải cơ sở dữ liệu
    db = load_mitre_database()

    if db:
        # Truy vấn từ cơ sở dữ liệu cục bộ
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
                        "name": tech.get("name", "Không xác định"),
                        "tactic": tech.get("tactics", ["Không xác định"])[0] if tech.get("tactics") else "Không xác định",
                        "description": tech.get("description", ""),
                        "mitigations": tech.get("mitigations", []),
                    })

            if techniques:
                return {
                    "context": {
                        "techniques": techniques,
                        "threat_actors": [],  # Có thể mở rộng bằng threat intel
                        "source": "csdl_mitre_dia_phuong",
                    }
                }

    # Quay lại dữ liệu mock
    if cve_id in MOCK_CVE_TO_ATTACK:
        attack_data = MOCK_CVE_TO_ATTACK[cve_id]
        return {
            "context": {
                "techniques": attack_data.get("techniques", []),
                "threat_actors": attack_data.get("threat_actors", []),
                "source": "du_lieu_mock",
            }
        }

    # Không tìm thấy dữ liệu
    return {
        "context": {
            "techniques": [],
            "threat_actors": [],
            "source": "khong_co",
        }
    }
