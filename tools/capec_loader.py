"""
tools/capec_loader.py - Load + parse CWE/CAPEC XML dumps

Implements G1 + G2:
  G1: CWE → CAPEC mapping (parse CWE XML Related_Attack_Patterns)
  G2: CAPEC → ATT&CK mapping (parse CAPEC XML Taxonomy_Mappings)

Sources:
  - CWE XML: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
  - CAPEC XML: https://capec.mitre.org/data/xml/capec_latest.xml

Caching: Via tools/data_cache_manager.py (see BƯỚC 3 Plan)

Structure:
  CAPECLoader: Main class, lazy-loads XML from local cache
  - load_cwe_xml(): Parse CWE XML → {"CWE-ID": [CAPEC-IDs]}
  - load_capec_xml(): Parse CAPEC XML → {CAPEC-ID: {name, likelihood, abstraction}}
  - cwe_to_capec_ids(cwe_id): CWE-20 → ["126", "3"]
  - capec_to_attack_techniques(capec_id): CAPEC-126 → ["T1083", "T1190"]
  - get_capec_details(capec_id): CAPEC-126 → {name, likelihood, abstraction}
"""

import os
import json
import logging
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET
from datetime import datetime

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# CAPEC LOADER - Main class
# ═══════════════════════════════════════════════════════════════════════════════

class CAPECLoader:
    """
    Singleton loader for CWE/CAPEC XML data.
    Lazy-loads and caches in memory.
    """

    _instance = None
    _cwe_to_capec = {}  # {"20": ["126", "3"], ...}
    _capec_details = {}  # {"126": {name, likelihood, abstraction}, ...}
    _attack_techniques = {}  # {"126": ["T1083", "T1190"], ...}
    _loaded = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CAPECLoader, cls).__new__(cls)
        return cls._instance

    def ensure_loaded(self):
        """Load XML data if not already loaded"""
        if not self._loaded:
            self._load_all()
            self._loaded = True

    def _load_all(self):
        """Load CWE XML and CAPEC XML"""
        try:
            cwe_xml_path = self._find_cwe_xml()
            if cwe_xml_path:
                logger.info(f"Loading CWE XML from {cwe_xml_path}")
                self._parse_cwe_xml(cwe_xml_path)
            else:
                logger.warning("CWE XML not found. CWE→CAPEC mapping disabled.")

            capec_xml_path = self._find_capec_xml()
            if capec_xml_path:
                logger.info(f"Loading CAPEC XML from {capec_xml_path}")
                self._parse_capec_xml(capec_xml_path)
            else:
                logger.warning("CAPEC XML not found. CAPEC→ATT&CK mapping disabled.")
        except Exception as e:
            logger.error(f"Error loading XML data: {e}")

    @staticmethod
    def _find_cwe_xml() -> Optional[str]:
        """Find CWE XML file in data/cache/ or data/"""
        search_paths = [
            "data/cache/cwec_latest.xml",
            "data/cwec_latest.xml",
            "data/cache/cwec_v4.13.xml",  # Fallback
        ]
        for path in search_paths:
            if os.path.exists(path):
                return path
        return None

    @staticmethod
    def _find_capec_xml() -> Optional[str]:
        """Find CAPEC XML file in data/cache/ or data/"""
        search_paths = [
            "data/cache/capec_latest.xml",
            "data/capec_latest.xml",
            "data/cache/capec_v3.0.xml",  # Fallback
        ]
        for path in search_paths:
            if os.path.exists(path):
                return path
        return None

    def _parse_cwe_xml(self, xml_path: str):
        """
        Parse CWE XML to extract CWE-ID → [CAPEC-IDs]

        XML Structure:
        <Weaknesses>
          <CWE ID="20" Name="...">
            <Related_Attack_Patterns>
              <Related_Attack_Pattern CAPEC_ID="126"/>
              <Related_Attack_Pattern CAPEC_ID="3"/>
            </Related_Attack_Patterns>
          </CWE>
          ...
        </Weaknesses>
        """
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            # Handle namespace if present
            ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}

            for cwe_elem in root.findall('.//CWE', ns) or root.findall('.//cwe:CWE', ns) or root.findall('.//CWE'):
                cwe_id = cwe_elem.get('ID')
                if not cwe_id:
                    continue

                capec_ids = []

                # Try with namespace
                patterns = cwe_elem.findall('.//Related_Attack_Pattern', ns)
                if not patterns:
                    patterns = cwe_elem.findall('.//cwe:Related_Attack_Pattern', ns)
                if not patterns:
                    patterns = cwe_elem.findall('.//Related_Attack_Pattern')

                for pattern in patterns:
                    capec_id = pattern.get('CAPEC_ID')
                    if capec_id and capec_id not in capec_ids:
                        capec_ids.append(capec_id)

                if capec_ids:
                    self._cwe_to_capec[cwe_id] = capec_ids
                    logger.debug(f"CWE-{cwe_id} → {capec_ids}")

            logger.info(f"Loaded {len(self._cwe_to_capec)} CWEs with CAPEC mappings")

        except Exception as e:
            logger.error(f"Error parsing CWE XML: {e}")

    def _parse_capec_xml(self, xml_path: str):
        """
        Parse CAPEC XML to extract:
        1. CAPEC-ID → {name, likelihood, abstraction}
        2. CAPEC-ID → [ATT&CK T-codes]

        XML Structure:
        <Attack_Patterns>
          <Attack_Pattern ID="126" Name="Forceful Browsing" Abstraction="Standard">
            <Likelihood_Of_Attack>High</Likelihood_Of_Attack>
            <Taxonomy_Mappings>
              <Taxonomy_Mapping>
                <Taxonomy_Name>ATT&amp;CK</Taxonomy_Name>
                <Entry_ID>T1083</Entry_ID>
              </Taxonomy_Mapping>
              <Taxonomy_Mapping>
                <Taxonomy_Name>ATT&amp;CK</Taxonomy_Name>
                <Entry_ID>T1190</Entry_ID>
              </Taxonomy_Mapping>
            </Taxonomy_Mappings>
          </Attack_Pattern>
          ...
        </Attack_Patterns>
        """
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            ns = {'capec': 'http://capec.mitre.org/capec-3'}

            for pattern in root.findall('.//Attack_Pattern', ns) or root.findall('.//capec:Attack_Pattern', ns) or root.findall('.//Attack_Pattern'):
                capec_id = pattern.get('ID')
                if not capec_id:
                    continue

                # Extract basic info
                name = pattern.get('Name', f'CAPEC-{capec_id}')
                abstraction = pattern.get('Abstraction', 'Unknown')  # Meta, Category, Standard, Detailed

                # Extract likelihood
                likelihood = 'Unknown'
                likelihood_elem = pattern.find('.//Likelihood_Of_Attack', ns)
                if likelihood_elem is None:
                    likelihood_elem = pattern.find('.//capec:Likelihood_Of_Attack', ns)
                if likelihood_elem is None:
                    likelihood_elem = pattern.find('.//Likelihood_Of_Attack')
                if likelihood_elem is not None and likelihood_elem.text:
                    likelihood = likelihood_elem.text

                self._capec_details[capec_id] = {
                    'name': name,
                    'likelihood': likelihood,
                    'abstraction': abstraction
                }

                # Extract ATT&CK T-codes from Taxonomy_Mappings
                attack_codes = []

                # Try with namespace
                mappings = pattern.findall('.//Taxonomy_Mapping', ns)
                if not mappings:
                    mappings = pattern.findall('.//capec:Taxonomy_Mapping', ns)
                if not mappings:
                    mappings = pattern.findall('.//Taxonomy_Mapping')

                for mapping in mappings:
                    # Check taxonomy name
                    taxonomy_name = None
                    name_elem = mapping.find('.//Taxonomy_Name', ns)
                    if name_elem is None:
                        name_elem = mapping.find('.//capec:Taxonomy_Name', ns)
                    if name_elem is None:
                        name_elem = mapping.find('.//Taxonomy_Name')

                    if name_elem is not None:
                        taxonomy_name = name_elem.text

                    # Only extract ATT&CK mappings
                    if taxonomy_name and 'ATT&CK' in taxonomy_name:
                        entry_id_elem = mapping.find('.//Entry_ID', ns)
                        if entry_id_elem is None:
                            entry_id_elem = mapping.find('.//capec:Entry_ID', ns)
                        if entry_id_elem is None:
                            entry_id_elem = mapping.find('.//Entry_ID')

                        if entry_id_elem is not None and entry_id_elem.text:
                            entry_id = entry_id_elem.text
                            if entry_id not in attack_codes:
                                attack_codes.append(entry_id)

                if attack_codes:
                    self._attack_techniques[capec_id] = attack_codes
                    logger.debug(f"CAPEC-{capec_id} → {attack_codes}")

            logger.info(f"Loaded {len(self._capec_details)} CAPECs with details")
            logger.info(f"Loaded {len(self._attack_techniques)} CAPECs with ATT&CK mappings")

        except Exception as e:
            logger.error(f"Error parsing CAPEC XML: {e}")

    def cwe_to_capec_ids(self, cwe_id: str) -> List[str]:
        """
        Map CWE to CAPEC IDs.

        Args:
            cwe_id: "CWE-20" or "20"

        Returns:
            ["126", "3"] or []
        """
        self.ensure_loaded()
        cwe_num = cwe_id.replace("CWE-", "").replace("cwe-", "")
        return self._cwe_to_capec.get(cwe_num, [])

    def capec_to_attack_techniques(self, capec_id: str) -> List[str]:
        """
        Map CAPEC to ATT&CK T-codes.

        Args:
            capec_id: "126" or "CAPEC-126"

        Returns:
            ["T1083", "T1190"] or []
        """
        self.ensure_loaded()
        capec_num = capec_id.replace("CAPEC-", "").replace("capec-", "")
        return self._attack_techniques.get(capec_num, [])

    def get_capec_details(self, capec_id: str) -> Dict:
        """
        Get CAPEC details (name, likelihood, abstraction).

        Args:
            capec_id: "126" or "CAPEC-126"

        Returns:
            {
                "name": "Forceful Browsing",
                "likelihood": "High",  # High, Medium, Low, Unknown
                "abstraction": "Standard"  # Meta, Category, Standard, Detailed
            }
        """
        self.ensure_loaded()
        capec_num = capec_id.replace("CAPEC-", "").replace("capec-", "")
        return self._capec_details.get(capec_num, {
            "name": f"CAPEC-{capec_num}",
            "likelihood": "Unknown",
            "abstraction": "Unknown"
        })


# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS - Module-level API
# ═══════════════════════════════════════════════════════════════════════════════

_loader = CAPECLoader()

def cwe_to_capec_ids(cwe_id: str) -> List[str]:
    """
    Convenience: Map CWE to CAPEC IDs

    Example:
        cwe_to_capec_ids("CWE-22") → ["3", "126"]
    """
    return _loader.cwe_to_capec_ids(cwe_id)


def capec_to_attack_techniques(capec_id: str) -> List[str]:
    """
    Convenience: Map CAPEC to ATT&CK T-codes

    Example:
        capec_to_attack_techniques("CAPEC-126") → ["T1083"]
    """
    return _loader.capec_to_attack_techniques(capec_id)


def get_capec_details(capec_id: str) -> Dict:
    """
    Convenience: Get CAPEC details

    Example:
        get_capec_details("CAPEC-126") → {name, likelihood, abstraction}
    """
    return _loader.get_capec_details(capec_id)


def cwe_to_capec_details(cwe_id: str) -> List[Dict]:
    """
    Convenience: Get full CAPEC details for a CWE

    Returns: [
        {
            "id": "126",
            "name": "Forceful Browsing",
            "likelihood": "High",
            "abstraction": "Standard",
            "attack_techniques": ["T1083"]
        }
    ]
    """
    capec_ids = cwe_to_capec_ids(cwe_id)
    results = []

    for capec_id in capec_ids:
        details = get_capec_details(capec_id)
        techniques = capec_to_attack_techniques(capec_id)

        results.append({
            "id": capec_id,
            "name": details.get("name"),
            "likelihood": details.get("likelihood"),
            "abstraction": details.get("abstraction"),
            "attack_techniques": techniques
        })

    return results
