"""
tools/nist.py - Tra cuu NIST SP 800-53 controls tu co so du lieu cu bo
Su dung co so du lieu NIST chinh thuc voi day du 800-53 controls
Fallback den cve_inference khi CVE khong co trong database
"""
import json
from pathlib import Path
from typing import Dict, List, Optional

# Duong dan database
NIST_DB_PATH = Path(__file__).parent.parent / "data" / "nist_controls.json"

# Import inference module as fallback
try:
    from tools.cve_inference import infer_nist_controls as infer_nist_controls_from_cve
except ImportError:
    infer_nist_controls_from_cve = None


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


def get_nist_controls(cve_id: str = "", keyword: str = "", cve_description: str = "", cwe_ids: list = None) -> dict:
    """
    Tra cuu NIST SP 800-53 controls cho CVE

    CWE resolution hierarchy:
    1. cwe_ids parameter (CWE chinh thuc tu NVD weaknesses) - highest priority
    2. Truy van tu co so du lieu CVE cu bo
    3. Inference tu description

    Tra ve:
        dict voi keys: controls (danh sach), priority, timeframe, source
    """
    from tools.cwe_mapper import CWEMapper

    print(f"  [NIST] Tra cuu: cve='{cve_id}', keyword='{keyword}', cwe_ids={cwe_ids}")

    # Tai co so du lieu
    db = load_nist_database()

    # PHASE 1: Use official CWE IDs from NVD (highest priority)
    if cwe_ids:
        cwe_mapper = CWEMapper()
        # Lam sach CWE IDs
        valid_cwes = [c for c in cwe_ids if c.startswith("CWE-") or c.isdigit()]
        if valid_cwes:
            ctrl_ids = []
            for cwe_id in valid_cwes:
                controls = cwe_mapper.cwe_to_nist_controls(cwe_id)
                for ctrl in controls:
                    if ctrl["id"] not in ctrl_ids:
                        ctrl_ids.append(ctrl["id"])

            if ctrl_ids:
                controls_db = db.get("controls", {})
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

                return {
                    "context": {
                        "controls": controls,
                        "priority": _get_priority_from_controls(ctrl_ids),
                        "timeframe": _get_timeframe_from_priority(_get_priority_from_controls(ctrl_ids)),
                        "source": "cwe_nvd_chinh_thuc",
                        "cwe_ids_used": valid_cwes,
                    }
                }

    # PHASE 2: CVE mapping from local database
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

    # PHASE 3: Fallback - khong tim thay
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
