"""
tools/mitre_builder.py - Build local MITRE ATT&CK database from official STIX data
Downloads MITRE ATT&CK JSON and builds indexed database for fast lookups
"""
import json
import os
from pathlib import Path
from urllib.request import urlopen
from typing import Dict, List, Optional

# MITRE ATT&CK datasets
MITRE_DATASETS = {
    "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
}

MITRE_DB_PATH = Path(__file__).parent.parent / "data" / "mitre_attack.json"

def download_mitre_data(dataset: str = "enterprise") -> dict:
    """Download MITRE ATT&CK STIX data from GitHub"""
    url = MITRE_DATASETS.get(dataset)
    if not url:
        raise ValueError(f"Unknown dataset: {dataset}")

    print(f"Downloading MITRE ATT&CK {dataset} dataset...")
    try:
        with urlopen(url, timeout=30) as response:
            data = json.loads(response.read().decode())
        print(f"[OK] Downloaded {len(data.get('objects', []))} STIX objects")
        return data
    except Exception as e:
        print(f"[ERROR] Failed to download: {e}")
        return None

def build_technique_index(stix_data: dict) -> Dict[str, dict]:
    """Extract and index MITRE ATT&CK techniques from STIX data"""
    techniques = {}

    for obj in stix_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        # Extract technique ID (e.g., "T1190" from "attack-pattern--...")
        external_refs = obj.get("external_references", [])
        tech_id = None
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id")
                break

        if not tech_id:
            continue

        # Extract tactic (x-mitre-platforms, kill-chain-phases)
        kill_chain = obj.get("kill_chain_phases", [])
        tactics = [kc.get("phase_name", "").replace("-", " ").title() for kc in kill_chain]

        techniques[tech_id] = {
            "id": tech_id,
            "name": obj.get("name", "Unknown"),
            "description": obj.get("description", "")[:200],  # Truncate for brevity
            "tactics": tactics,
            "platforms": obj.get("x_mitre_platforms", []),
            "mitigations": [],  # Will be populated from course-of-action
            "created": obj.get("created", ""),
            "modified": obj.get("modified", ""),
        }

    print(f"[OK] Extracted {len(techniques)} techniques")
    return techniques

def build_mitigation_index(stix_data: dict) -> Dict[str, dict]:
    """Extract MITRE ATT&CK mitigations (course-of-action) from STIX data"""
    mitigations = {}
    technique_mitigations = {}

    for obj in stix_data.get("objects", []):
        if obj.get("type") != "course-of-action":
            continue

        # Extract mitigation ID (e.g., "M1051")
        external_refs = obj.get("external_references", [])
        mitigation_id = None
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                mitigation_id = ref.get("external_id")
                break

        if not mitigation_id or mitigation_id.startswith("T"):  # Skip technique IDs
            continue

        mitigations[mitigation_id] = {
            "id": mitigation_id,
            "name": obj.get("name", "Unknown"),
            "description": obj.get("description", "")[:200],
        }

    # Build technique->mitigation mapping
    for obj in stix_data.get("objects", []):
        if obj.get("type") != "x-mitre-technique-mapping":
            continue

        technique_ref = obj.get("x_mitre_technique_refs", [])
        mitigation_ref = obj.get("x_mitre_mitigation_refs", [])

        for tech_ref in technique_ref:
            # Extract tech ID from object reference
            tech_id = None
            for ref_obj in stix_data.get("objects", []):
                if ref_obj.get("id") == tech_ref and ref_obj.get("type") == "attack-pattern":
                    for ref in ref_obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            tech_id = ref.get("external_id")
                            break

            if tech_id not in technique_mitigations:
                technique_mitigations[tech_id] = []

            for mit_ref in mitigation_ref:
                for ref_obj in stix_data.get("objects", []):
                    if ref_obj.get("id") == mit_ref and ref_obj.get("type") == "course-of-action":
                        for ref in ref_obj.get("external_references", []):
                            if ref.get("source_name") == "mitre-attack":
                                mit_id = ref.get("external_id")
                                if mit_id in mitigations:
                                    technique_mitigations[tech_id].append({
                                        "id": mit_id,
                                        "name": mitigations[mit_id]["name"],
                                    })
                        break

    print(f"[OK] Extracted {len(mitigations)} mitigations")
    return mitigations, technique_mitigations

def build_cve_technique_mapping(techniques: dict) -> Dict[str, List[str]]:
    """Build CVE -> Technique mapping based on common patterns
    This is a heuristic mapping - real world uses threat intel feeds
    """
    cve_patterns = {
        "CVE-2021-44228": ["T1190", "T1059", "T1071"],  # Log4Shell
        "CVE-2021-41773": ["T1190", "T1083"],  # Apache path traversal
        "CVE-2022-22965": ["T1190", "T1505.003"],  # Spring4Shell
        "CVE-2014-0160": ["T1040", "T1557"],  # Heartbleed
        "CVE-2019-11510": ["T1190", "T1020"],  # Pulse Secure
        "CVE-2020-1938": ["T1190", "T1190"],  # Apache Tomcat
    }

    # Validate techniques exist
    cve_mapping = {}
    for cve, tech_ids in cve_patterns.items():
        valid_techs = [tid for tid in tech_ids if tid in techniques]
        if valid_techs:
            cve_mapping[cve] = valid_techs

    print(f"[OK] Built CVE -> Technique mapping for {len(cve_mapping)} known CVEs")
    return cve_mapping

def save_database(techniques: dict, mitigations: dict, cve_mapping: dict, path: Path):
    """Save indexed database to JSON file"""
    db = {
        "techniques": techniques,
        "mitigations": mitigations,
        "cve_mapping": cve_mapping,
        "metadata": {
            "source": "MITRE ATT&CK",
            "version": "2026-05-11",
            "techniques_count": len(techniques),
            "mitigations_count": len(mitigations),
            "cve_mappings_count": len(cve_mapping),
        }
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

    print(f"[OK] Saved database to {path}")
    print(f"  - {len(techniques)} techniques")
    print(f"  - {len(mitigations)} mitigations")
    print(f"  - {len(cve_mapping)} CVE mappings")

def build_local_database():
    """Main function to build local MITRE ATT&CK database"""
    print("=" * 70)
    print(" Building Local MITRE ATT&CK Database")
    print("=" * 70)

    # Download MITRE data
    stix_data = download_mitre_data("enterprise")
    if not stix_data:
        print("[ERROR] Failed to download MITRE data")
        return False

    # Build indices
    techniques = build_technique_index(stix_data)
    mitigations, technique_mitigations = build_mitigation_index(stix_data)
    cve_mapping = build_cve_technique_mapping(techniques)

    # Add mitigations to techniques
    for tech_id, mits in technique_mitigations.items():
        if tech_id in techniques:
            techniques[tech_id]["mitigations"] = mits

    # Save database
    save_database(techniques, mitigations, cve_mapping, MITRE_DB_PATH)

    print("=" * 70)
    print(" [OK] Database built successfully!")
    print("=" * 70)
    return True

if __name__ == "__main__":
    build_local_database()
