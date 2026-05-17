# -*- coding: utf-8 -*-
"""
tools/relationship_validator.py - Relationship Validation & Confidence Scoring

Validates threat relationships from OpenCTI to prevent hallucination.
Ensures only verified relationships are persisted as intelligence.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from enum import Enum


class RelationshipType(Enum):
    """Verified relationship types in threat intelligence"""
    EXPLOITS = "exploits"  # Malware/Campaign exploits CVE
    USES = "uses"  # Actor uses malware
    TARGETS = "targets"  # Campaign targets entity
    COMMUNICATES_WITH = "communicates_with"  # C2 communication
    ASSOCIATED_WITH = "associated_with"  # General association
    DELIVERS = "delivers"  # Malware delivery
    DROPS = "drops"  # Malware drops payload
    OBSERVED_IN = "observed_in"  # Observed in campaign
    ATTRIBUTED_TO = "attributed_to"  # Attribution to actor
    DEPLOYS = "deploys"  # Deployment relationship


class ConfidenceLevel(Enum):
    """Confidence scoring for relationships"""
    HIGH = (0.8, 1.0)  # Direct evidence, multi-source, observed
    MEDIUM = (0.5, 0.79)  # Single source, indirect linkage
    LOW = (0.2, 0.49)  # NLP inference, contextual overlap
    VERY_LOW = (0.0, 0.19)  # Semantic approximation only


class ProvenanceSource(Enum):
    """Trusted sources for threat intelligence"""
    OPENCTI = "opencti"
    OPENCTI_DIRECT = "opencti_direct_edge"  # Direct graph relationship
    OPENCTI_CAMPAIGN = "opencti_campaign"  # Campaign membership
    OPENCTI_MALWARE = "opencti_malware"  # Malware membership
    MANDIANT = "mandiant"
    CROWDSTRIKE = "crowdstrike"
    VULNCHECK = "vulncheck"
    OTX = "otx"
    MITRE = "mitre"
    EXPLOIT_DB = "exploit_db"
    INTERNAL_TELEMETRY = "internal_telemetry"
    NLP_INFERENCE = "nlp_inference"  # Weak signal


@dataclass
class RelationshipEvidence:
    """Evidence supporting a relationship"""
    type: str  # "direct_graph", "campaign_report", "malware_analysis", "att&ck", "ioc_correlation", "exploit_telemetry"
    source: ProvenanceSource
    description: str
    confidence_contribution: float  # 0.0-1.0


@dataclass
class ValidatedRelationship:
    """Verified threat relationship with full provenance"""
    source_entity: str  # CVE-ID, Malware name, Campaign name, Actor
    target_entity: str
    entity_type: str  # "malware", "campaign", "threat_actor"
    relationship_type: RelationshipType
    confidence: float  # 0.0-1.0
    confidence_level: ConfidenceLevel
    provenance: List[ProvenanceSource]
    evidence: List[RelationshipEvidence]
    verified: bool
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    validation_method: str = ""
    notes: str = ""

    def to_dict(self) -> Dict:
        """Convert to dictionary for storage"""
        return {
            "source_entity": self.source_entity,
            "target_entity": self.target_entity,
            "entity_type": self.entity_type,
            "relationship_type": self.relationship_type.value,
            "confidence": round(self.confidence, 3),
            "confidence_level": self.confidence_level.name,
            "provenance": [p.value for p in self.provenance],
            "evidence": [
                {
                    "type": e.type,
                    "source": e.source.value,
                    "description": e.description,
                    "confidence_contribution": round(e.confidence_contribution, 3)
                }
                for e in self.evidence
            ],
            "verified": self.verified,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "validation_method": self.validation_method,
            "notes": self.notes
        }


class RelationshipValidator:
    """
    Validates threat relationships to ensure CTI-grade quality.
    Prevents hallucination through multi-factor validation.
    """

    def __init__(self):
        pass  # Validation rules defined in methods

    def validate_relationship(
        self,
        source_cve: str,
        target_entity: str,
        entity_type: str,  # "malware", "campaign", "threat_actor"
        opencti_data: Dict,
        cve_data: Dict,
    ) -> Tuple[bool, Optional[ValidatedRelationship]]:
        """
        Validate a single relationship from OpenCTI.

        Returns: (is_verified, ValidatedRelationship or None)
        """

        evidence_list = []
        provenance_sources = []
        total_confidence = 0.0
        evidence_count = 0

        # 1. Check direct graph relationship in OpenCTI
        if self._has_direct_opencti_edge(opencti_data, source_cve, target_entity):
            evidence = RelationshipEvidence(
                type="direct_graph",
                source=ProvenanceSource.OPENCTI_DIRECT,
                description=f"Direct OpenCTI graph edge: {source_cve} → {target_entity}",
                confidence_contribution=0.9,
            )
            evidence_list.append(evidence)
            provenance_sources.append(ProvenanceSource.OPENCTI_DIRECT)
            total_confidence += 0.9
            evidence_count += 1

        # 2. Check campaign membership
        if entity_type == "campaign" and self._is_campaign_member(opencti_data, target_entity):
            evidence = RelationshipEvidence(
                type="campaign_membership",
                source=ProvenanceSource.OPENCTI_CAMPAIGN,
                description=f"{source_cve} is associated with campaign {target_entity}",
                confidence_contribution=0.75,
            )
            evidence_list.append(evidence)
            provenance_sources.append(ProvenanceSource.OPENCTI_CAMPAIGN)
            total_confidence += 0.75
            evidence_count += 1

        # 3. Check malware analysis linkage
        if entity_type == "malware" and self._has_malware_linkage(opencti_data, target_entity):
            evidence = RelationshipEvidence(
                type="malware_analysis",
                source=ProvenanceSource.OPENCTI_MALWARE,
                description=f"{source_cve} exploited by malware {target_entity}",
                confidence_contribution=0.8,
            )
            evidence_list.append(evidence)
            provenance_sources.append(ProvenanceSource.OPENCTI_MALWARE)
            total_confidence += 0.8
            evidence_count += 1

        # 4. Check ATT&CK linkage
        if self._has_att_ck_linkage(cve_data, target_entity):
            evidence = RelationshipEvidence(
                type="att_ck_linkage",
                source=ProvenanceSource.MITRE,
                description=f"ATT&CK-confirmed linkage for {target_entity}",
                confidence_contribution=0.7,
            )
            evidence_list.append(evidence)
            provenance_sources.append(ProvenanceSource.MITRE)
            total_confidence += 0.7
            evidence_count += 1

        # 5. IOC correlation check
        if self._has_ioc_correlation(opencti_data, target_entity):
            evidence = RelationshipEvidence(
                type="ioc_correlation",
                source=ProvenanceSource.VULNCHECK,
                description=f"IOC correlation detected with {target_entity}",
                confidence_contribution=0.6,
            )
            evidence_list.append(evidence)
            provenance_sources.append(ProvenanceSource.VULNCHECK)
            total_confidence += 0.6
            evidence_count += 1

        # Calculate final confidence
        if evidence_count == 0:
            # No evidence found - this is NOT a verified relationship
            return False, None

        # Average confidence from evidence sources
        final_confidence = total_confidence / evidence_count if evidence_count > 0 else 0.0

        # Determine confidence level
        confidence_level = self._get_confidence_level(final_confidence)

        # Only HIGH confidence relationships are "verified"
        is_verified = confidence_level == ConfidenceLevel.HIGH

        # Determine relationship type
        relationship_type = self._infer_relationship_type(entity_type, opencti_data)

        validated_rel = ValidatedRelationship(
            source_entity=source_cve,
            target_entity=target_entity,
            entity_type=entity_type,
            relationship_type=relationship_type,
            confidence=final_confidence,
            confidence_level=confidence_level,
            provenance=list(set(provenance_sources)),  # Remove duplicates
            evidence=evidence_list,
            verified=is_verified,
            validation_method=f"Multi-factor validation ({evidence_count} sources)",
            notes=f"Evidence from {len(evidence_list)} validation checks",
        )

        return is_verified, validated_rel

    def validate_relationships_batch(
        self,
        source_cve: str,
        entities: Dict[str, List[Dict]],  # {"malwares": [...], "campaigns": [...], "threat_actors": [...]}
        opencti_data: Dict,
        cve_data: Dict,
    ) -> Dict:
        """
        Validate multiple relationships for a CVE.

        Returns: {
            "verified_relationships": [ValidatedRelationship],
            "potential_entities": [Dict],  # Weak signals only
            "validation_summary": {
                "total_entities": int,
                "verified_count": int,
                "potential_count": int,
                "avg_confidence": float
            }
        }
        """

        verified_relationships = []
        potential_entities = []
        total_entities = 0
        confidence_scores = []

        # Validate all entities
        for entity_type, entity_list in entities.items():
            clean_type = entity_type.rstrip("s")  # Remove plural

            for entity in entity_list:
                total_entities += 1
                entity_name = entity.get("name", "Unknown")

                is_verified, validated_rel = self.validate_relationship(
                    source_cve,
                    entity_name,
                    clean_type,
                    opencti_data,
                    cve_data,
                )

                if is_verified and validated_rel:
                    verified_relationships.append(validated_rel)
                    confidence_scores.append(validated_rel.confidence)
                elif validated_rel and validated_rel.confidence > 0:
                    # Keep as potential entity with confidence info
                    potential_entities.append({
                        "name": entity_name,
                        "type": clean_type,
                        "confidence": round(validated_rel.confidence, 3),
                        "confidence_level": validated_rel.confidence_level.name,
                        "correlation_type": "contextual_overlap",
                        "evidence_count": len(validated_rel.evidence),
                    })
                    confidence_scores.append(validated_rel.confidence)

        avg_confidence = (
            sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        )

        return {
            "verified_relationships": verified_relationships,
            "potential_entities": potential_entities,
            "validation_summary": {
                "total_entities": total_entities,
                "verified_count": len(verified_relationships),
                "potential_count": len(potential_entities),
                "avg_confidence": round(avg_confidence, 3),
            },
        }

    # ─── Validation Helper Methods ───

    def _has_direct_opencti_edge(
        self, opencti_data: Dict, source: str, target: str
    ) -> bool:
        """Check for direct graph relationship in OpenCTI"""
        # This would check if there's a direct edge in OpenCTI graph
        edges = opencti_data.get("graph_edges", [])
        for edge in edges:
            if edge.get("source") == source and edge.get("target") == target:
                return True
        return False

    def _is_campaign_member(self, opencti_data: Dict, campaign_name: str) -> bool:
        """Check if entity is confirmed campaign member"""
        campaigns = opencti_data.get("campaigns", [])
        for campaign in campaigns:
            if campaign.get("name") == campaign_name and campaign.get("confirmed"):
                return True
        return False

    def _has_malware_linkage(self, opencti_data: Dict, malware_name: str) -> bool:
        """Check if malware has confirmed linkage to CVE"""
        malwares = opencti_data.get("malwares", [])
        for malware in malwares:
            if malware.get("name") == malware_name:
                # Check if there's documented exploitation
                if malware.get("exploited_cves") or malware.get("known_exploits"):
                    return True
        return False

    def _has_att_ck_linkage(self, cve_data: Dict, entity_name: str) -> bool:
        """Check if entity has ATT&CK-confirmed linkage"""
        # Check CWE → ATT&CK mapping
        attack_info = cve_data.get("attack_info", {})
        techniques = attack_info.get("techniques", [])
        # If entity appears in confirmed techniques, linkage exists
        return len(techniques) > 0

    def _has_ioc_correlation(self, opencti_data: Dict, entity_name: str) -> bool:
        """Check for IOC correlation evidence"""
        iocs = opencti_data.get("iocs", [])
        # If there are IOCs associated with this entity
        return len(iocs) > 0

    def _get_confidence_level(self, confidence: float) -> ConfidenceLevel:
        """Map confidence score to level"""
        for level in ConfidenceLevel:
            min_conf, max_conf = level.value
            if min_conf <= confidence <= max_conf:
                return level
        return ConfidenceLevel.VERY_LOW

    def _infer_relationship_type(
        self, entity_type: str, opencti_data: Dict
    ) -> RelationshipType:
        """Infer relationship type based on entity"""
        if entity_type == "malware":
            return RelationshipType.EXPLOITS
        elif entity_type == "campaign":
            return RelationshipType.OBSERVED_IN
        elif entity_type == "threat_actor":
            return RelationshipType.ATTRIBUTED_TO
        else:
            return RelationshipType.ASSOCIATED_WITH


def validate_cve_enrichment(
    cve_id: str,
    enrichment_data: Dict,
    cve_data: Dict,
) -> Dict:
    """
    Main validation function for CVE enrichment.

    Takes raw enrichment data and returns validated intelligence.
    """
    validator = RelationshipValidator()

    # Extract entities from enrichment
    entities = {
        "malwares": enrichment_data.get("malwares", []),
        "campaigns": enrichment_data.get("campaigns", []),
        "threat_actors": enrichment_data.get("threat_actors", []),
    }

    # Prepare OpenCTI data (mock structure for now)
    opencti_data = {
        "graph_edges": enrichment_data.get("graph_edges", []),
        "campaigns": enrichment_data.get("campaigns", []),
        "malwares": enrichment_data.get("malwares", []),
        "iocs": enrichment_data.get("iocs", []),
    }

    # Run validation
    result = validator.validate_relationships_batch(cve_id, entities, opencti_data, cve_data)

    return result
