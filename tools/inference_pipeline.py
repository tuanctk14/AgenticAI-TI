"""
tools/inference_pipeline.py - Multi-Layer Inference Pipeline for Analyst-Grade TI

Architecture:
  Layer 1: Exact Mapping (EXACT_CVE_MAP)
  Layer 2: CWE Mapping (CWE → MITRE/NIST)
  Layer 3: Vulnerability Ontology (semantic normalization)
  Layer 4: Product-Aware Context (device-specific ATT&CK)
  Layer 5: Semantic/NLP Classification
  Layer 6: Generic Fallback (default controls)
"""
from typing import Dict, List, Optional, Tuple
from tools.vuln_ontology import classify_vulnerability, get_vuln_class_info
from tools.product_context import get_product_category, remap_technique_for_context
from tools.cve_parser import parse_cve_metadata
from tools.cve_inference import CVEInference


class InferencePipeline:
    """Multi-layer inference pipeline for analyst-grade threat intelligence."""

    # Layer 1: Exact CVE mappings (hardcoded for critical CVEs)
    EXACT_CVE_MAP = {
        "CVE-2021-44228": {
            "name": "Apache Log4j2 RCE",
            "cwe": ["CWE-502", "CWE-78"],
            "affected_product": "apache:log4j",
            "mitre_techniques": [
                ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.95),
                ("T1059", "Command and Scripting Interpreter", "Execution", 0.90),
            ],
            "nist_controls": ["AC-3", "CM-6", "SI-3"],
            "context": "framework",
        },
        "CVE-2023-20198": {
            "name": "Cisco IOS XE Web UI Privilege Escalation",
            "cwe": ["CWE-250", "CWE-269"],
            "affected_product": "cisco:ios_xe",
            "mitre_techniques": [
                ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.95),
                ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", 0.90),
            ],
            "nist_controls": ["AC-3", "SC-7", "AC-6"],
            "context": "network_device",
        },
    }

    def __init__(self):
        self.cve_inference = CVEInference()

    def infer_cve_context(
        self,
        cve_id: str,
        description: str,
        cwe_ids: List[str] = None,
        affected_product: str = None
    ) -> Dict:
        """
        Multi-layer inference pipeline for complete CVE context.

        Returns: {
            cve_id, name, vuln_class, cwe_ids,
            mitre_techniques: [{id, name, tactic, confidence, layer}],
            nist_controls: [{id, family, title}],
            product_context, recommendations
        }
        """
        result = {
            "cve_id": cve_id,
            "description": description,
            "inference_layers_used": [],
            "vuln_class": None,
            "cwe_ids": cwe_ids or [],
            "affected_product": affected_product,
            "product_context": None,
            "mitre_techniques": [],
            "nist_controls": [],
            "confidence": 0.0,
            "recommendations": []
        }

        # ────────────────────────────────────────────────────────────
        # LAYER 1: EXACT MAPPING (highest priority, highest confidence)
        # ────────────────────────────────────────────────────────────
        if cve_id.upper() in self.EXACT_CVE_MAP:
            exact_data = self.EXACT_CVE_MAP[cve_id.upper()]
            result["inference_layers_used"].append("exact_mapping")
            result["cwe_ids"] = exact_data.get("cwe", [])
            result["affected_product"] = exact_data.get("affected_product", affected_product)

            # Get exact MITRE techniques
            for tech_id, tech_name, tactic, confidence in exact_data.get("mitre_techniques", []):
                result["mitre_techniques"].append({
                    "id": tech_id,
                    "name": tech_name,
                    "tactic": tactic,
                    "confidence": confidence,
                    "layer": "exact_mapping"
                })

            # Get exact NIST controls
            result["nist_controls"] = exact_data.get("nist_controls", [])
            result["product_context"] = exact_data.get("context", "unknown")
            result["confidence"] = 0.95  # Exact mapping highest confidence
            return result

        # ────────────────────────────────────────────────────────────
        # LAYER 2: CWE MAPPING (if CWE IDs available)
        # ────────────────────────────────────────────────────────────
        if cwe_ids:
            result["inference_layers_used"].append("cwe_mapping")
            all_techniques = set()
            all_controls = set()

            for cwe_id in cwe_ids:
                # Get MITRE techniques from CWE
                cwe_mitre = self.cve_inference.CWE_MITRE_MAP.get(cwe_id, {})
                for tech_id, confidence, tech_name in cwe_mitre.get("techniques", []):
                    all_techniques.add((tech_id, tech_name, confidence, "cwe_mapping"))

                # Get NIST controls from CWE
                cwe_nist = self.cve_inference.CWE_NIST_MAP.get(cwe_id, [])
                all_controls.update(cwe_nist)

            # Add MITRE techniques from CWE
            for tech_id, tech_name, confidence, layer in all_techniques:
                # Get tactic from CWE mapping
                cwe_mitre = next(
                    (v for k, v in self.cve_inference.CWE_MITRE_MAP.items() if any(t[0] == tech_id for t in v.get("techniques", []))),
                    {}
                )
                tactics = cwe_mitre.get("tactics", ["Unknown"])

                result["mitre_techniques"].append({
                    "id": tech_id,
                    "name": tech_name,
                    "tactic": tactics[0] if tactics else "Unknown",
                    "confidence": confidence,
                    "layer": layer
                })

            result["nist_controls"] = list(all_controls)
            if not result["confidence"]:
                result["confidence"] = 0.85  # CWE mapping confidence

        # ────────────────────────────────────────────────────────────
        # LAYER 3: VULNERABILITY ONTOLOGY (semantic normalization)
        # ────────────────────────────────────────────────────────────
        if not result["mitre_techniques"] and description:
            result["inference_layers_used"].append("vulnerability_ontology")
            vuln_classification = classify_vulnerability(description, cwe_ids)

            if vuln_classification.get("class"):
                result["vuln_class"] = vuln_classification["class"]
                vuln_info = get_vuln_class_info(vuln_classification["class"])

                # Get techniques from ontology
                for tech_item in vuln_info.get("mitre_techniques", []):
                    result["mitre_techniques"].append({
                        "id": tech_item.get("id"),
                        "name": tech_item.get("name"),
                        "tactic": tech_item.get("tactic"),
                        "confidence": vuln_classification.get("confidence", 0.75),
                        "layer": "vulnerability_ontology"
                    })

                # Get controls from ontology
                result["nist_controls"] = vuln_info.get("nist_controls", [])
                result["confidence"] = vuln_classification.get("confidence", 0.75)

        # ────────────────────────────────────────────────────────────
        # LAYER 4: PRODUCT-AWARE CONTEXT (refine ATT&CK for device type)
        # ────────────────────────────────────────────────────────────
        if affected_product or result["affected_product"]:
            product_id = (affected_product or result["affected_product"]).lower().replace(" ", "_")
            product_context = get_product_category(product_id)

            if product_context != "unknown":
                result["inference_layers_used"].append("product_context")
                result["product_context"] = product_context

                # Remap techniques for product context
                updated_techniques = []
                for tech in result["mitre_techniques"]:
                    remapped_id = remap_technique_for_context(tech["id"], product_context)
                    tech["id"] = remapped_id
                    tech["layer"] = f"{tech['layer']}→product_context"
                    updated_techniques.append(tech)

                result["mitre_techniques"] = updated_techniques

        # ────────────────────────────────────────────────────────────
        # LAYER 5: Generic fallback (if no techniques found)
        # ────────────────────────────────────────────────────────────
        if not result["mitre_techniques"]:
            result["inference_layers_used"].append("generic_fallback")
            result["mitre_techniques"] = [
                {
                    "id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactic": "Initial Access",
                    "confidence": 0.40,
                    "layer": "generic_fallback"
                }
            ]
            result["nist_controls"] = ["AC-3", "SI-2"]
            result["confidence"] = 0.40

        return result

    def generate_analyst_report(self, cve_context: Dict) -> Dict:
        """Generate analyst-grade report from inference pipeline results."""
        return {
            "cve_id": cve_context.get("cve_id"),
            "inference_chain": " → ".join(cve_context.get("inference_layers_used", [])),
            "vulnerability_class": cve_context.get("vuln_class", "Unknown"),
            "affected_product": cve_context.get("affected_product", "Unknown"),
            "product_category": cve_context.get("product_context", "unknown"),
            "confidence_score": cve_context.get("confidence", 0.0),
            "cwe_ids": cve_context.get("cwe_ids", []),
            "mitre_techniques": cve_context.get("mitre_techniques", []),
            "nist_controls": cve_context.get("nist_controls", []),
        }
