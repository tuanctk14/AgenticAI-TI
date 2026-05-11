"""
tools/nist.py - Tra cuu NIST SP 800-53 controls tu co so du lieu cu bo
Su dung co so du lieu NIST chinh thuc voi day du 800-53 controls
"""
import json
from pathlib import Path
from typing import Dict, List, Optional

# Duong dan database
NIST_DB_PATH = Path(__file__).parent.parent / "data" / "nist_controls.json"


def load_nist_database() -> Optional[dict]:
    """Tai co so du lieu NIST SP 800-53 cu bo"""
    if not NIST_DB_PATH.exists():
        raise FileNotFoundError(f"NIST database not found: {NIST_DB_PATH}")

    try:
        with open(NIST_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Khong the tai co so du lieu NIST: {e}")
        raise


def get_nist_controls(cve_id: str = "", keyword: str = "") -> dict:
    """
    Tra cuu NIST SP 800-53 controls cho CVE

    Tra ve:
        dict voi keys: controls (danh sach), priority, timeframe
    """
    print(f"  [NIST] Tra cuu: cve='{cve_id}', keyword='{keyword}'")

    # Tai co so du lieu
    db = load_nist_database()

    # Truy van tu co so du lieu cu bo
    cve_mapping = db.get("cve_mapping", {})
    controls_db = db.get("controls", {})

    if cve_id in cve_mapping:
        ctrl_ids = cve_mapping[cve_id]
        controls = []

        for ctrl_id in ctrl_ids:
            if ctrl_id in controls_db:
                ctrl = controls_db[ctrl_id]
                controls.append({
                    "id": ctrl_id,
                    "title": ctrl.get("title", "Khong xac dinh"),
                    "description": ctrl.get("description", ""),
                    "family": ctrl.get("family", ""),
                })

        if controls:
            return {
                "context": {
                    "controls": controls,
                    "priority": _get_priority_from_controls(ctrl_ids),
                    "timeframe": _get_timeframe_from_priority(_get_priority_from_controls(ctrl_ids)),
                    "source": "csdl_nist_dia_phuong",
                }
            }

    # Khong tim thay du lieu
    return {
        "context": {
            "controls": [],
            "priority": "UNKNOWN",
            "timeframe": "N/A",
            "source": "khong_co",
        }
    }


def _get_priority_from_controls(ctrl_ids: list) -> str:
    """Xac dinh muc uu tien dua tren cac control"""
    # RCE controls = IMMEDIATE
    if any(id in ["SI-2", "SI-3", "SC-7", "IR-4"] for id in ctrl_ids):
        return "IMMEDIATE"
    # Information disclosure = HIGH
    elif any(id in ["SC-8", "IA-5"] for id in ctrl_ids):
        return "HIGH"
    # Path traversal = HIGH
    elif any(id in ["AC-3", "AU-2"] for id in ctrl_ids):
        return "HIGH"
    # DoS = MEDIUM
    elif any(id in ["SC-5", "CP-2"] for id in ctrl_ids):
        return "MEDIUM"
    return "MEDIUM"


def _get_timeframe_from_priority(priority: str) -> str:
    """Lay timeframe dua tren muc uu tien"""
    timeframes = {
        "IMMEDIATE": "24-48 gio",
        "HIGH": "48-72 gio",
        "MEDIUM": "7 ngay",
        "LOW": "30 ngay",
    }
    return timeframes.get(priority, "7 ngay")
