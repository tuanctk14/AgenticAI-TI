# -*- coding: utf-8 -*-
"""
tools/relationship_confidence_engine.py - Confidence Scoring Engine

Calculates confidence scores for relationships based on evidence quality,
provenance, and multi-factor validation. Prevents hallucination through
rigorous scoring.
"""

from typing import Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class ConfidenceFactor:
    """Single factor contributing to confidence score"""
    name: str
    weight: float  # 0.0-1.0
    score: float  # 0.0-1.0
    reason: str


class ConfidenceEngine:
    """
    Multi-factor confidence scoring for threat relationships.

    Factors:
    1. Evidence Quality (40%) - type and count of evidence
    2. Provenance Trust (30%) - source trustworthiness
    3. Temporal Freshness (15%) - how recent is the intelligence
    4. Cross-Validation (15%) - confirmation from multiple sources
    """

    # Source trust scores
    SOURCE_TRUST_SCORES = {
        "opencti_direct_edge": 0.95,  # Direct graph relationship
        "mandiant": 0.90,
        "crowdstrike": 0.88,
        "vulncheck": 0.85,
        "mitre_att_ck": 0.85,
        "exploit_db": 0.75,
        "otx": 0.70,
        "internal_telemetry": 0.80,
        "nlp_inference": 0.35,  # Weak signal
        "contextual_overlap": 0.40,  # Very weak
        "keyword_similarity": 0.25,  # Hallucination risk
    }

    # Evidence type weights
    EVIDENCE_WEIGHTS = {
        "direct_graph": 1.0,  # Perfect evidence
        "campaign_report": 0.85,
        "malware_analysis": 0.80,
        "att_ck_observation": 0.75,
        "exploit_telemetry": 0.80,
        "ioc_correlation": 0.70,
        "campaign_membership": 0.75,
        "semantic_correlation": 0.30,  # Weak
        "keyword_match": 0.20,  # Very weak
    }

    def __init__(self):
        self.factors: List[ConfidenceFactor] = []

    def calculate_confidence(
        self,
        source_entity: str,
        target_entity: str,
        evidence_list: List[Dict],
        provenance_sources: List[str],
        cross_validation_count: int = 0,
        temporal_days_old: int = 0,
    ) -> Tuple[float, List[ConfidenceFactor], str]:
        """
        Calculate confidence score (0.0-1.0) for a relationship.

        Args:
            source_entity: CVE or source entity
            target_entity: Malware, Campaign, or Actor
            evidence_list: List of evidence items with types
            provenance_sources: List of evidence sources
            cross_validation_count: Number of independent sources agreeing
            temporal_days_old: Days since intelligence was collected

        Returns:
            (confidence_score, factors_breakdown, assessment)
        """
        self.factors = []

        # 1. Evidence Quality Score (40% weight)
        evidence_score = self._score_evidence_quality(evidence_list)
        self._add_factor("Evidence Quality", 0.40, evidence_score, f"{len(evidence_list)} evidence items")

        # 2. Provenance Trust Score (30% weight)
        provenance_score = self._score_provenance(provenance_sources)
        trust_sources = ", ".join(provenance_sources[:3])
        self._add_factor("Provenance Trust", 0.30, provenance_score, f"Sources: {trust_sources}")

        # 3. Temporal Freshness Score (15% weight)
        temporal_score = self._score_temporal_freshness(temporal_days_old)
        self._add_factor("Temporal Freshness", 0.15, temporal_score, f"{temporal_days_old} days old")

        # 4. Cross-Validation Score (15% weight)
        cross_val_score = self._score_cross_validation(cross_validation_count)
        self._add_factor("Cross-Validation", 0.15, cross_val_score, f"{cross_validation_count} independent sources")

        # Calculate final confidence
        total_confidence = sum(f.weight * f.score for f in self.factors)

        # Generate assessment
        assessment = self._generate_assessment(total_confidence)

        return round(total_confidence, 3), self.factors, assessment

    def _score_evidence_quality(self, evidence_list: List[Dict]) -> float:
        """Score based on evidence type and quality"""
        if not evidence_list:
            return 0.0

        evidence_scores = []

        for evidence in evidence_list:
            ev_type = evidence.get("type", "unknown")
            weight = self.EVIDENCE_WEIGHTS.get(ev_type, 0.5)
            evidence_scores.append(weight)

        # Average evidence quality, with bonus for multiple sources
        avg_score = sum(evidence_scores) / len(evidence_scores)

        # Bonus: multiple evidence types boost confidence
        if len(evidence_scores) >= 3:
            avg_score = min(1.0, avg_score * 1.2)  # 20% boost
        elif len(evidence_scores) >= 2:
            avg_score = min(1.0, avg_score * 1.1)  # 10% boost

        return min(1.0, avg_score)

    def _score_provenance(self, provenance_sources: List[str]) -> float:
        """Score based on source trustworthiness"""
        if not provenance_sources:
            return 0.0

        source_scores = []

        for source in provenance_sources:
            score = self.SOURCE_TRUST_SCORES.get(source, 0.5)
            source_scores.append(score)

        # Average of source scores, with bonus for multiple trusted sources
        avg_score = sum(source_scores) / len(source_scores)

        # Bonus: multiple independent sources increase trust
        if len(source_scores) >= 3:
            avg_score = min(1.0, avg_score * 1.15)  # 15% boost
        elif len(source_scores) >= 2:
            avg_score = min(1.0, avg_score * 1.08)  # 8% boost

        return min(1.0, avg_score)

    def _score_temporal_freshness(self, days_old: int) -> float:
        """Score based on how recent the intelligence is"""
        # Fresh intelligence (0-30 days): 1.0
        # Recent (30-90 days): 0.9
        # Older (90-365 days): 0.7
        # Very old (>365 days): 0.4

        if days_old <= 30:
            return 1.0
        elif days_old <= 90:
            return 0.9
        elif days_old <= 365:
            return 0.7
        else:
            return max(0.4, 1.0 - (days_old - 365) / 3650)  # Decay over time

    def _score_cross_validation(self, cross_validation_count: int) -> float:
        """Score based on independent source agreement"""
        # 0 sources: 0.0
        # 1 source: 0.5
        # 2 sources: 0.8
        # 3+ sources: 1.0

        if cross_validation_count == 0:
            return 0.0
        elif cross_validation_count == 1:
            return 0.5
        elif cross_validation_count == 2:
            return 0.8
        else:
            return 1.0

    def _add_factor(self, name: str, weight: float, score: float, reason: str) -> None:
        """Add a confidence factor"""
        self.factors.append(ConfidenceFactor(
            name=name,
            weight=weight,
            score=score,
            reason=reason
        ))

    def _generate_assessment(self, confidence: float) -> str:
        """Generate qualitative assessment from confidence score"""
        if confidence >= 0.8:
            return "HIGH - Direct evidence from trusted sources"
        elif confidence >= 0.6:
            return "MEDIUM - Single source or indirect linkage"
        elif confidence >= 0.4:
            return "LOW - Contextual correlation only"
        elif confidence >= 0.2:
            return "VERY_LOW - Semantic similarity only"
        else:
            return "REJECTED - Insufficient evidence"


class ConfidenceThresholds:
    """Define minimum confidence thresholds for different use cases"""

    # Intelligence must meet these thresholds to be persisted as "verified"
    VERIFIED_THRESHOLD = 0.75  # HIGH confidence minimum

    # Intelligence can be shown as "potential" if above this
    POTENTIAL_THRESHOLD = 0.4  # LOW confidence minimum

    # Intelligence below this is rejected
    REJECTION_THRESHOLD = 0.2  # VERY_LOW

    @staticmethod
    def should_verify(confidence: float) -> bool:
        """Should this be shown as verified relationship?"""
        return confidence >= ConfidenceThresholds.VERIFIED_THRESHOLD

    @staticmethod
    def should_show_as_potential(confidence: float) -> bool:
        """Should this be shown as potential/contextual entity?"""
        return (
            confidence >= ConfidenceThresholds.POTENTIAL_THRESHOLD
            and confidence < ConfidenceThresholds.VERIFIED_THRESHOLD
        )

    @staticmethod
    def should_reject(confidence: float) -> bool:
        """Should this be rejected entirely?"""
        return confidence < ConfidenceThresholds.POTENTIAL_THRESHOLD


def score_relationship(
    source_entity: str,
    target_entity: str,
    evidence: List[Dict],
    provenance: List[str],
    days_old: int = 0,
) -> Dict:
    """
    Simple API to score a single relationship.

    Returns comprehensive scoring breakdown.
    """
    engine = ConfidenceEngine()

    confidence, factors, assessment = engine.calculate_confidence(
        source_entity=source_entity,
        target_entity=target_entity,
        evidence_list=evidence,
        provenance_sources=provenance,
        temporal_days_old=days_old,
    )

    return {
        "confidence": confidence,
        "assessment": assessment,
        "is_verified": ConfidenceThresholds.should_verify(confidence),
        "is_potential": ConfidenceThresholds.should_show_as_potential(confidence),
        "factors": [
            {
                "name": f.name,
                "weight": f.weight,
                "score": f.score,
                "contribution": round(f.weight * f.score, 3),
                "reason": f.reason,
            }
            for f in factors
        ],
    }
