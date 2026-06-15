"""
tools/heimdall_cwe_nist_mapper.py - Load deprecated Heimdall CWE-NIST mapping

Implements G5: CWE --> NIST fallback (when ATT&CK chain not available)

Source: https://github.com/mitre/heimdall_tools/blob/master/lib/data/cwe-nist-mapping.csv
Format: CWE,NIST (e.g., "CWE-20,SI-10")

CAVEAT: Mapping is GENERIC, not threat-informed.
Use ONLY as fallback when:
  1. CWE has no CAPEC relationships
  2. No ATT&CK techniques found

PRIMARY: CWE --> CAPEC --> ATT&CK --> NIST (via attack_nist_mapper)
FALLBACK: CWE --> NIST (via this file)
"""

import os
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class HeimdallCWENISTMapper:
    """
    Maps CWE to NIST controls via deprecated Heimdall CSV.
    Lazy-loads from CSV file.
    """

    _instance = None
    _mappings = {}  # {"20": ["SI-10", "AC-3"], ...}
    _loaded = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(HeimdallCWENISTMapper, cls).__new__(cls)
        return cls._instance

    def ensure_loaded(self):
        """Load mappings if not already loaded"""
        if not self._loaded:
            self._load_csv()
            self._loaded = True

    def _load_csv(self):
        """Load Heimdall CSV mapping"""
        csv_paths = [
            "data/cache/cwe_nist_mapping.csv",
            "data/cwe_nist_mapping.csv",
        ]

        for path in csv_paths:
            if os.path.exists(path):
                try:
                    logger.info(f"Loading Heimdall CWE-NIST mapping from {path}")
                    with open(path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()

                    for line in lines[1:]:  # Skip header
                        line = line.strip()
                        if not line:
                            continue

                        parts = line.split(',')
                        if len(parts) >= 2:
                            cwe_part = parts[0].strip()
                            nist_part = parts[1].strip()

                            # Extract CWE number
                            cwe_num = cwe_part.replace("CWE-", "").replace("cwe-", "")

                            # Extract NIST control
                            nist_ctrl = nist_part

                            if cwe_num not in self._mappings:
                                self._mappings[cwe_num] = []

                            if nist_ctrl not in self._mappings[cwe_num]:
                                self._mappings[cwe_num].append(nist_ctrl)

                    logger.info(f"Loaded {len(self._mappings)} CWEs with NIST mappings from Heimdall CSV")
                    return

                except Exception as e:
                    logger.error(f"Error loading CSV from {path}: {e}")

        logger.warning("Heimdall CWE-NIST mapping not found. CWE fallback disabled.")

    def cwe_to_nist_controls(self, cwe_id: str) -> List[str]:
        """
        Map CWE to NIST control IDs (fallback).

        Args:
            cwe_id: "CWE-20" or "20"

        Returns:
            ["SI-10", "AC-3"] or []
        """
        self.ensure_loaded()
        cwe_num = cwe_id.replace("CWE-", "").replace("cwe-", "")
        return self._mappings.get(cwe_num, [])

    def cwe_to_nist_controls_with_metadata(self, cwe_id: str, nist_controls_data: Dict = None) -> List[Dict]:
        """
        Map CWE to NIST controls with metadata.

        Args:
            cwe_id: "CWE-20" or "20"
            nist_controls_data: Optional dict of NIST controls
                               {control_id: {title, description, ...}}

        Returns: [
            {
                "control": "SI-10",
                "name": "Information Input Validation",
                "confidence": 0.6,  # Lower confidence for fallback
                "source": "heimdall"
            }
        ]
        """
        control_ids = self.cwe_to_nist_controls(cwe_id)
        results = []

        for ctrl_id in control_ids:
            ctrl_data = {
                "control": ctrl_id,
                "name": ctrl_id,  # Default: use control ID
                "confidence": 0.6,  # Lower confidence for fallback
                "source": "heimdall"
            }

            # Enhance with NIST controls data if provided
            if nist_controls_data:
                nist_entry = nist_controls_data.get(ctrl_id, {})
                if nist_entry:
                    ctrl_data["name"] = nist_entry.get("title", nist_entry.get("name", ctrl_id))

            results.append(ctrl_data)

        return results


# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

_mapper = HeimdallCWENISTMapper()


def cwe_to_nist_controls(cwe_id: str) -> List[str]:
    """
    Convenience: Map CWE to NIST controls (fallback)

    Example:
        cwe_to_nist_controls("CWE-20") --> ["SI-10", "AC-3"]
    """
    return _mapper.cwe_to_nist_controls(cwe_id)


def cwe_to_nist_controls_with_metadata(cwe_id: str, nist_controls_data: Dict = None) -> List[Dict]:
    """
    Convenience: Map CWE to NIST controls with metadata

    Example:
        cwe_to_nist_controls_with_metadata("CWE-20") -->
        [{"control": "SI-10", "name": "...", "confidence": 0.6, "source": "heimdall"}]
    """
    return _mapper.cwe_to_nist_controls_with_metadata(cwe_id, nist_controls_data)
