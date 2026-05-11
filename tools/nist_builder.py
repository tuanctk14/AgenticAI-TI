"""
tools/nist_builder.py - Xây dựng cơ sở dữ liệu NIST SP 800-53 cục bộ từ dữ liệu chính thức
Tải xuống NIST SP 800-53 JSON và xây dựng cơ sở dữ liệu được đánh chỉ mục để tra cứu nhanh
"""
import json
import os
from pathlib import Path
from urllib.request import urlopen
from typing import Dict, List, Optional

# Dataset NIST SP 800-53
NIST_DATASETS = {
    "sp800-53-5": "https://raw.githubusercontent.com/usnistgov/oscal-content/master/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
}

NIST_DB_PATH = Path(__file__).parent.parent / "data" / "nist_controls.json"

def download_nist_data(dataset: str = "sp800-53-5") -> dict:
    """Tai xuong du lieu NIST SP 800-53 tu GitHub OSCAL"""
    url = NIST_DATASETS.get(dataset)
    if not url:
        raise ValueError(f"Dataset khong biet: {dataset}")

    print(f"Dang tai xuong NIST SP 800-53 {dataset}...")
    try:
        with urlopen(url, timeout=30) as response:
            data = json.loads(response.read().decode())
        print(f"[OK] Da tai NIST SP 800-53 catalog")
        return data
    except Exception as e:
        print(f"[ERROR] Khong the tai xuong: {e}")
        return None

def build_control_index(oscal_data: dict) -> Dict[str, dict]:
    """Trich xuat va danh chi muc cac controls NIST SP 800-53 tu du lieu OSCAL"""
    controls = {}

    try:
        catalog = oscal_data.get("catalog", {})
        groups = catalog.get("groups", [])

        for group in groups:
            for control in group.get("controls", []):
                ctrl_id = control.get("id", "").upper()
                if not ctrl_id:
                    continue

                # Trich xuat tieu de va mo ta
                title = control.get("title", "")

                # Lay mo ta tu statement hoac phan noi dung dau tien
                description = ""
                parts = control.get("parts", [])
                if parts:
                    # Tim phan co id = "statement" hoac su dung phan dau tien
                    for part in parts:
                        if part.get("id") == "statement":
                            description = part.get("prose", "")[:300]
                            break
                    if not description and parts:
                        description = parts[0].get("prose", "")[:300]

                # Phan loai control theo family (SI-2, SC-7, etc.)
                family = ctrl_id.split("-")[0] if "-" in ctrl_id else ctrl_id

                controls[ctrl_id] = {
                    "id": ctrl_id,
                    "title": title,
                    "description": description,
                    "family": family,
                    "related_controls": [],
                }

        print(f"[OK] Trich xuat {len(controls)} controls")
        return controls
    except Exception as e:
        print(f"[ERROR] Loi khi xu ly OSCAL data: {e}")
        return {}

def build_cve_control_mapping(controls: dict) -> Dict[str, List[str]]:
    """
    Xay dung CVE to Control mapping dua tren cac pattern pho bien
    Day la heuristic mapping - su dung threat intel feeds trong thuc te
    """
    cve_patterns = {
        "CVE-2021-44228": ["SI-2", "SI-3", "SC-7", "CM-6", "RA-5", "IR-4"],
        "CVE-2021-41773": ["SI-2", "SC-7", "AC-3", "AU-2"],
        "CVE-2022-22965": ["SI-2", "SI-3", "SC-7", "CM-6"],
        "CVE-2014-0160":  ["SI-2", "SC-8", "IA-5"],
        "CVE-2019-11510": ["SI-2", "SC-7", "IA-5"],
        "CVE-2020-1938":  ["SI-2", "SI-3", "SC-7"],
        "CVE-2023-44487": ["SI-2", "SC-5", "CP-2"],
    }

    # Kiem tra controls ton tai
    cve_mapping = {}
    for cve, ctrl_ids in cve_patterns.items():
        valid_ctrls = [cid for cid in ctrl_ids if cid in controls]
        if valid_ctrls:
            cve_mapping[cve] = valid_ctrls

    print(f"[OK] Xay dung CVE to Control mapping cho {len(cve_mapping)} CVE")
    return cve_mapping

def build_family_index(controls: dict) -> Dict[str, List[str]]:
    """Xay dung chi muc theo family (SI, SC, AC, etc.)"""
    families = {}
    for ctrl_id, ctrl in controls.items():
        family = ctrl.get("family", "")
        if family not in families:
            families[family] = []
        families[family].append(ctrl_id)

    print(f"[OK] To chuc {len(controls)} controls thanh {len(families)} families")
    return families

def save_database(controls: dict, cve_mapping: dict, families: dict, path: Path):
    """Luu indexed database vao file JSON"""
    db = {
        "controls": controls,
        "cve_mapping": cve_mapping,
        "families": families,
        "metadata": {
            "source": "NIST SP 800-53 Revision 5",
            "oscal_version": "1.0",
            "controls_count": len(controls),
            "cve_mappings_count": len(cve_mapping),
            "families_count": len(families),
        }
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

    print(f"[OK] Luu database vao {path}")
    print(f"  - {len(controls)} controls")
    print(f"  - {len(cve_mapping)} CVE mappings")
    print(f"  - {len(families)} families")

def build_local_database():
    """Main function de xay dung local NIST SP 800-53 database"""
    print("=" * 70)
    print(" Xay dung Local NIST SP 800-53 Database")
    print("=" * 70)

    # Tai NIST data
    oscal_data = download_nist_data("sp800-53-5")
    if not oscal_data:
        print("[ERROR] Khong the tai NIST data")
        return False

    # Xay dung indices
    controls = build_control_index(oscal_data)
    cve_mapping = build_cve_control_mapping(controls)
    families = build_family_index(controls)

    # Luu database
    save_database(controls, cve_mapping, families, NIST_DB_PATH)

    print("=" * 70)
    print(" [OK] Database xay dung thanh cong!")
    print("=" * 70)
    return True

if __name__ == "__main__":
    build_local_database()
