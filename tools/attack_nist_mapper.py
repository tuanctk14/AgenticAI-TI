"""
tools/attack_nist_mapper.py - Map ATT&CK techniques to NIST 800-53 controls

Implements G4: ATT&CK --> NIST mapping (bidirectional)

Source: Center for Threat-Informed Defense
  - Mappings Explorer: https://github.com/center-for-threat-informed-defense/mappings-explorer
  - Rev.5 (SP 800-53 Rev.5): mappings_attack_v13_nist-800-53-rev5.json

Data Format (from JSON):
  {
    "technique_id": "T1190",
    "technique_name": "Exploit Public-Facing Application",
    "controls": [
      {"control_id": "SI-10", "control_name": "Information Input Validation"},
      {"control_id": "DE-3", "control_name": "Analyze User-Generated Content"}
    ]
  }
"""

import os
import json
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AttackNISTMapper:
    """
    Maps ATT&CK techniques to NIST 800-53 controls.
    Lazy-loads mappings from JSON file.
    """

    _instance = None
    _mappings = {}  # {"T1190": {"controls": [...]}, ...}
    _loaded = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AttackNISTMapper, cls).__new__(cls)
        return cls._instance

    def ensure_loaded(self):
        """Load mappings if not already loaded"""
        if not self._loaded:
            self._load_mappings()
            self._loaded = True

    def _load_mappings(self):
        """Load ATT&CK-NIST mappings from JSON file"""
        mapping_paths = [
            "data/cache/attack_nist_mappings_rev5.json",
            "data/attack_nist_mappings_rev5.json",
        ]

        for path in mapping_paths:
            if os.path.exists(path):
                try:
                    logger.info(f"Loading ATT&CK-NIST mappings from {path}")
                    with open(path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        # Expected format: {"T1190": {"controls": [...]}, ...}
                        if isinstance(data, dict):
                            self._mappings = data
                            logger.info(f"Loaded {len(self._mappings)} technique-to-control mappings")
                            return
                except Exception as e:
                    logger.error(f"Error loading mappings from {path}: {e}")

        logger.warning("ATT&CK-NIST mappings not found. Will use fallback.")

    def technique_to_nist_controls(self, t_number: str, nist_controls_data: Dict = None) -> List[Dict]:
        """
        Map ATT&CK technique to NIST controls.

        Args:
            t_number: "T1190" or "T1083.005"
            nist_controls_data: Optional dict of NIST controls for enhancement
                               {control_id: {title, description, ...}}

        Returns: [
            {
                "control": "SI-10",
                "name": "Information Input Validation",
                "type": "Preventive",
                "description": "..."
            }
        ]
        """
        self.ensure_loaded()

        # Normalize T-number (remove subtechnique)
        t_base = t_number.split('.')[0]

        mappings_entry = self._mappings.get(t_base, {})
        controls = mappings_entry.get("controls", [])

        results = []
        for ctrl in controls:
            ctrl_data = {
                "control": ctrl.get("control_id", ""),
                "name": ctrl.get("control_name", ""),
                "type": ctrl.get("type", "Unknown"),
                "description": ""
            }

            # Enhance with NIST controls data if provided
            if nist_controls_data:
                nist_entry = nist_controls_data.get(ctrl_data["control"], {})
                if nist_entry:
                    ctrl_data["name"] = nist_entry.get("title", nist_entry.get("name", ctrl_data["name"]))
                    ctrl_data["description"] = nist_entry.get("description", "")

            results.append(ctrl_data)

        return results

    def techniques_to_nist_controls_deduplicated(self, t_numbers: List[str], nist_controls_data: Dict = None) -> Dict[str, List[str]]:
        """
        Map multiple techniques to deduplicated NIST controls.

        Args:
            t_numbers: ["T1190", "T1083"]
            nist_controls_data: Optional NIST controls metadata

        Returns: {
            "SI-10": {
                "techniques": ["T1190"],
                "weight": 1.0
            },
            "SC-7": {
                "techniques": ["T1190", "T1083"],
                "weight": 2.0
            }
        }
        """
        control_map = {}  # control_id -> {"techniques": [T-codes], "data": {...}}

        for t_num in t_numbers:
            controls = self.technique_to_nist_controls(t_num, nist_controls_data)
            for ctrl in controls:
                ctrl_id = ctrl["control"]

                if ctrl_id not in control_map:
                    control_map[ctrl_id] = {
                        "techniques": [],
                        "data": ctrl
                    }

                if t_num not in control_map[ctrl_id]["techniques"]:
                    control_map[ctrl_id]["techniques"].append(t_num)

        # Convert to simplified format with weight
        results = {}
        for ctrl_id, data in control_map.items():
            results[ctrl_id] = {
                "name": data["data"]["name"],
                "type": data["data"].get("type", "Unknown"),
                "techniques": data["techniques"],
                "weight": float(len(data["techniques"]))  # Simple weight = count
            }

        return results


# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

_mapper = AttackNISTMapper()


def technique_to_nist_controls(t_number: str, nist_controls_data: Dict = None) -> List[Dict]:
    """
    Convenience: Map ATT&CK technique to NIST controls

    Example:
        technique_to_nist_controls("T1190") --> [{"control": "SI-10", ...}]
    """
    return _mapper.technique_to_nist_controls(t_number, nist_controls_data)


def techniques_to_nist_controls_deduplicated(t_numbers: List[str], nist_controls_data: Dict = None) -> Dict[str, List[str]]:
    """
    Convenience: Map multiple techniques to deduplicated NIST controls

    Example:
        techniques_to_nist_controls_deduplicated(["T1190", "T1083"]) -->
        {"SI-10": {...}, "SC-7": {...}}
    """
    return _mapper.techniques_to_nist_controls_deduplicated(t_numbers, nist_controls_data)
