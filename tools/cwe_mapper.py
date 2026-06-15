"""
tools/cwe_mapper.py - Map CWE to MITRE ATT&CK techniques and NIST controls
CONSOLIDATED VERSION: Unified CWE mapper with external JSON data storage
Uses 802 CWEs with complete MITRE and NIST coverage
"""
import json
import os
from typing import Dict, List, Optional

# ═══════════════════════════════════════════════════════════════════════════════
# Load CWE mappings from JSON (data externalized for easier updates)
# ═══════════════════════════════════════════════════════════════════════════════

def _load_cwe_mappings() -> tuple:
    """Load CWE->MITRE and CWE->NIST mappings from JSON file"""
    try:
        mapping_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "data",
            "cwe_mappings.json"
        )
        with open(mapping_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get("cwe_to_mitre", {}), data.get("cwe_to_nist", {})
    except Exception as e:
        print(f"Warning: Could not load CWE mappings from JSON: {e}")
        print("Falling back to empty mappings")
        return {}, {}

# Load mappings at module level
CWE_TO_MITRE, CWE_TO_NIST = _load_cwe_mappings()

# CWEMapper class (unchanged)
class CWEMapper:
    """
    Maps CWE IDs to MITRE ATT&CK techniques and NIST controls
    Uses comprehensive 500+ CWE mappings from cwe_mapper_expanded
    """

    def __init__(self):
        """Initialize mapper with data from files"""
        self.mitre_data = self._load_mitre_data()
        self.nist_data = self._load_nist_data()

    def _load_mitre_data(self) -> Dict:
        """Load MITRE ATT&CK techniques from JSON database"""
        try:
            mitre_path = os.path.join(
                os.path.dirname(__file__),
                "..",
                "data",
                "mitre_attack.json"
            )
            with open(mitre_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load MITRE data: {e}")
            return {"techniques": {}}

    def _load_nist_data(self) -> Dict:
        """Load NIST controls from JSON database"""
        try:
            nist_path = os.path.join(
                os.path.dirname(__file__),
                "..",
                "data",
                "nist_controls.json"
            )
            with open(nist_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load NIST data: {e}")
            return {}

    def cwe_to_mitre_techniques(self, cwe_id: str) -> List[Dict]:
        """
        Map CWE ID to MITRE ATT&CK techniques
        Returns list of techniques with details
        """
        cwe_num = cwe_id.replace("CWE-", "")
        technique_ids = CWE_TO_MITRE.get(cwe_num, [])

        techniques = []
        mitre_techniques = self.mitre_data.get("techniques", {})

        for tech_id in technique_ids:
            tech_data = mitre_techniques.get(tech_id, {})
            techniques.append({
                "id": tech_id,
                "name": tech_data.get("name", f"Technique {tech_id}"),
                "description": tech_data.get("description", ""),
                "tactics": tech_data.get("tactics", []),
            })

        return techniques

    def cwe_to_nist_controls(self, cwe_id: str) -> List[Dict]:
        """
        Map CWE ID to NIST controls
        Returns list of controls with details
        """
        cwe_num = cwe_id.replace("CWE-", "")
        control_ids = CWE_TO_NIST.get(cwe_num, [])

        controls = []
        nist_controls = self.nist_data.get("controls", {})

        for control_id in control_ids:
            control_data = nist_controls.get(control_id, {})
            controls.append({
                "id": control_id,
                "name": control_data.get("title", control_data.get("name", f"Control {control_id}")),
                "description": control_data.get("description", ""),
                "family": control_id.split("-")[0] if "-" in control_id else "",
            })

        return controls

    def analyze_cwe_ids(self, cwe_ids: List[str]) -> Dict:
        """
        Analyze multiple CWE IDs and return consolidated results
        """
        all_techniques = {}
        all_controls = {}

        for cwe_id in cwe_ids:
            # Get techniques
            techniques = self.cwe_to_mitre_techniques(cwe_id)
            for tech in techniques:
                if tech["id"] not in all_techniques:
                    all_techniques[tech["id"]] = tech

            # Get controls
            controls = self.cwe_to_nist_controls(cwe_id)
            for control in controls:
                if control["id"] not in all_controls:
                    all_controls[control["id"]] = control

        return {
            "cwe_ids": cwe_ids,
            "mitre_techniques": list(all_techniques.values()),
            "nist_controls": list(all_controls.values()),
        }


def get_cwe_analysis(cve_dict: Dict) -> Dict:
    """
    Get complete CWE analysis for a CVE
    Integrates with parse_cve_metadata output
    """
    mapper = CWEMapper()
    cwe_ids = cve_dict.get("cwe_ids", [])

    if not cwe_ids:
        return {
            "cwe_ids": [],
            "mitre_techniques": [],
            "nist_controls": [],
        }

    return mapper.analyze_cwe_ids(cwe_ids)


# Global convenience functions (replaces mitre.py and nist.py)
_cwe_mapper_instance = None

def _get_mapper():
    global _cwe_mapper_instance
    if _cwe_mapper_instance is None:
        _cwe_mapper_instance = CWEMapper()
    return _cwe_mapper_instance


def get_mitre_attack_info(cve_id: str, cve_description: str = "", cwe_ids: list = None) -> dict:
    """
    Get MITRE ATT&CK techniques for a CVE.
    Replacement for mitre.py:get_mitre_attack_info()
    If cwe_ids not provided, attempts to fetch from NVD
    """
    mapper = _get_mapper()

    techniques = []
    source = "CWE-based inference"

    # If cwe_ids not provided, try to fetch from NVD
    if not cwe_ids:
        try:
            from tools.nvd_client import fetch_cve_by_id
            nvd_cves = fetch_cve_by_id(cve_id, enrich=False)
            if nvd_cves and nvd_cves[0].get("cwe_ids"):
                cwe_ids = nvd_cves[0]["cwe_ids"]
                source = "CWE from NVD + inference"
        except Exception as e:
            pass  # Fallback to empty results if NVD fetch fails

    # Map CWE IDs to MITRE techniques
    if cwe_ids:
        for cwe in cwe_ids:
            techniques.extend(mapper.cwe_to_mitre_techniques(str(cwe)))

    return {
        "cve_id": cve_id,
        "mitre_techniques": techniques,
        "technique_count": len(techniques),
        "source": source
    }


def get_nist_controls(cve_id: str, cve_description: str = "", cwe_ids: list = None) -> dict:
    """
    Get NIST SP 800-53 controls for a CVE.
    Replacement for nist.py:get_nist_controls()
    If cwe_ids not provided, attempts to fetch from NVD
    """
    mapper = _get_mapper()

    controls = []
    source = "CWE-based inference"

    # If cwe_ids not provided, try to fetch from NVD
    if not cwe_ids:
        try:
            from tools.nvd_client import fetch_cve_by_id
            nvd_cves = fetch_cve_by_id(cve_id, enrich=False)
            if nvd_cves and nvd_cves[0].get("cwe_ids"):
                cwe_ids = nvd_cves[0]["cwe_ids"]
                source = "CWE from NVD + inference"
        except Exception as e:
            pass  # Fallback to empty results if NVD fetch fails

    # Map CWE IDs to NIST controls
    if cwe_ids:
        for cwe in cwe_ids:
            controls.extend(mapper.cwe_to_nist_controls(str(cwe)))

    return {
        "cve_id": cve_id,
        "nist_controls": controls,
        "control_count": len(controls),
        "source": source
    }
