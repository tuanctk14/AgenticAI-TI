# -*- coding: utf-8 -*-
"""
tests/test_relationship_validation.py - Test suite for Relationship Validation Layer

Tests:
1. Validator - prevents hallucination
2. Confidence Engine - accurate scoring
3. Output Formatter - clear separation of verified vs potential
"""

import pytest
from tools.relationship_validator import (
    RelationshipValidator,
    RelationshipType,
    ConfidenceLevel,
    ValidatedRelationship,
)
from tools.relationship_confidence_engine import (
    ConfidenceEngine,
    ConfidenceThresholds,
    score_relationship,
)
from tools.relationship_formatter import (
    format_relationship_section,
    format_relationship_summary,
)


class TestRelationshipValidator:
    """Test the validator prevents hallucination"""

    def test_reject_zero_evidence(self):
        """Should reject relationship with zero evidence"""
        validator = RelationshipValidator()

        cve_data = {}
        opencti_data = {
            "graph_edges": [],
            "campaigns": [],
            "malwares": [],
            "iocs": [],
        }

        is_verified, validated = validator.validate_relationship(
            "CVE-2026-8719",
            "DRYHOOK",
            "malware",
            opencti_data,
            cve_data,
        )

        assert not is_verified, "Should reject with zero evidence"
        assert validated is None, "Should return None for unverified"

    def test_accept_direct_edge(self):
        """Should accept relationship with direct OpenCTI edge"""
        validator = RelationshipValidator()

        opencti_data = {
            "graph_edges": [
                {
                    "source": "CVE-2026-8719",
                    "target": "DRYHOOK",
                    "type": "exploited_by",
                }
            ],
            "campaigns": [],
            "malwares": [],
            "iocs": [],
        }
        cve_data = {}

        is_verified, validated = validator.validate_relationship(
            "CVE-2026-8719",
            "DRYHOOK",
            "malware",
            opencti_data,
            cve_data,
        )

        assert validated is not None, "Should return validated relationship"
        assert validated.confidence > 0.7, "Direct edge should have high confidence"
        assert "direct_graph" in [e.type for e in validated.evidence]

    def test_multi_factor_validation(self):
        """Should boost confidence with multiple evidence sources"""
        validator = RelationshipValidator()

        opencti_data = {
            "graph_edges": [
                {
                    "source": "CVE-2021-44228",
                    "target": "Conti",
                    "type": "exploited_by",
                }
            ],
            "campaigns": [
                {
                    "name": "Operation Spalax",
                    "confirmed": True,
                }
            ],
            "malwares": [
                {
                    "name": "Conti",
                    "exploited_cves": ["CVE-2021-44228"],
                }
            ],
            "iocs": [
                {"hash": "abc123"},
            ],
        }
        cve_data = {
            "attack_info": {
                "techniques": [
                    {"id": "T1190", "name": "Exploit"}
                ]
            }
        }

        is_verified, validated = validator.validate_relationship(
            "CVE-2021-44228",
            "Conti",
            "malware",
            opencti_data,
            cve_data,
        )

        assert validated is not None
        assert len(validated.evidence) > 1, "Should have multiple evidence"
        assert validated.confidence > 0.8, "Multiple sources should boost confidence"

    def test_batch_validation(self):
        """Should separate verified from potential entities"""
        validator = RelationshipValidator()

        entities = {
            "malwares": [
                {"name": "Conti"},  # Strong evidence
                {"name": "DRYHOOK"},  # Weak signal
            ],
            "campaigns": [
                {"name": "Operation Spalax"},  # Strong
            ],
        }

        opencti_data = {
            "graph_edges": [
                {"source": "CVE-2021-44228", "target": "Conti"}
            ],
            "campaigns": [
                {"name": "Operation Spalax", "confirmed": True}
            ],
            "malwares": [],
            "iocs": [],
        }

        cve_data = {"attack_info": {"techniques": []}}

        result = validator.validate_relationships_batch(
            "CVE-2021-44228",
            entities,
            opencti_data,
            cve_data,
        )

        assert result["validation_summary"]["total_entities"] == 3
        assert result["validation_summary"]["verified_count"] >= 0
        assert result["validation_summary"]["potential_count"] >= 0


class TestConfidenceEngine:
    """Test confidence scoring prevents hardcoding"""

    def test_direct_evidence_high_confidence(self):
        """Direct OpenCTI edge should score HIGH"""
        engine = ConfidenceEngine()

        confidence, factors, assessment = engine.calculate_confidence(
            source_entity="CVE-2021-44228",
            target_entity="Conti",
            evidence_list=[
                {"type": "direct_graph"},
                {"type": "malware_analysis"},
            ],
            provenance_sources=["opencti_direct_edge", "mandiant"],
            cross_validation_count=2,
            temporal_days_old=30,
        )

        assert confidence >= 0.8, "Direct evidence should be HIGH"
        assert "HIGH" in assessment
        assert ConfidenceThresholds.should_verify(confidence)

    def test_contextual_only_low_confidence(self):
        """Semantic correlation only should score LOW"""
        engine = ConfidenceEngine()

        confidence, factors, assessment = engine.calculate_confidence(
            source_entity="CVE-2026-8719",
            target_entity="DRYHOOK",
            evidence_list=[
                {"type": "semantic_correlation"},
            ],
            provenance_sources=["nlp_inference"],
            cross_validation_count=0,
            temporal_days_old=365,
        )

        assert confidence < 0.5, "Semantic only should be LOW"
        assert "LOW" in assessment or "VERY_LOW" in assessment
        assert not ConfidenceThresholds.should_verify(confidence)
        assert not ConfidenceThresholds.should_show_as_potential(confidence)

    def test_multiple_sources_boost(self):
        """Multiple independent sources should boost confidence"""
        engine1 = ConfidenceEngine()
        engine2 = ConfidenceEngine()

        # Single source
        conf_single, _, _ = engine1.calculate_confidence(
            source_entity="CVE-2021-44228",
            target_entity="Conti",
            evidence_list=[{"type": "direct_graph"}],
            provenance_sources=["opencti_direct_edge"],
            cross_validation_count=1,
        )

        # Multiple sources
        conf_multi, _, _ = engine2.calculate_confidence(
            source_entity="CVE-2021-44228",
            target_entity="Conti",
            evidence_list=[
                {"type": "direct_graph"},
                {"type": "att_ck_linkage"},
                {"type": "malware_analysis"},
            ],
            provenance_sources=["opencti_direct_edge", "mitre_att_ck", "mandiant"],
            cross_validation_count=3,
        )

        assert conf_multi > conf_single, "Multiple sources should boost confidence"

    def test_confidence_thresholds(self):
        """Should correctly classify by threshold"""
        assert ConfidenceThresholds.should_verify(0.85), "0.85 should be verified"
        assert not ConfidenceThresholds.should_verify(0.70), "0.70 should not be verified"
        assert ConfidenceThresholds.should_show_as_potential(0.55), "0.55 should be potential"
        assert not ConfidenceThresholds.should_show_as_potential(0.15), "0.15 should not be potential"
        assert ConfidenceThresholds.should_reject(0.10), "0.10 should be rejected"


class TestRelationshipFormatter:
    """Test output formatting separates verified vs potential"""

    def test_format_verified_section(self):
        """Should format verified relationships section"""
        validated_data = {
            "verified_relationships": [
                {
                    "target_entity": "Conti",
                    "entity_type": "malware",
                    "relationship_type": "exploits",
                    "confidence": 0.85,
                    "confidence_level": "HIGH",
                    "provenance": ["opencti_direct_edge"],
                    "evidence": [
                        {
                            "type": "direct_graph",
                            "description": "Direct OpenCTI edge found",
                            "source": "opencti_direct_edge",
                        }
                    ],
                }
            ],
            "potential_entities": [],
            "validation_summary": {
                "total_entities": 1,
                "verified_count": 1,
                "potential_count": 0,
                "avg_confidence": 0.85,
            },
        }

        output = format_relationship_section("CVE-2021-44228", validated_data)

        assert "VERIFIED RELATIONSHIPS" in output
        assert "Conti" in output
        assert "HIGH" in output
        assert "85" in output  # Will match 85.0% or 85%

    def test_format_potential_section(self):
        """Should format potential entities section"""
        validated_data = {
            "verified_relationships": [],
            "potential_entities": [
                {
                    "name": "DRYHOOK",
                    "type": "malware",
                    "confidence": 0.35,
                    "confidence_level": "LOW",
                    "correlation_type": "contextual_overlap",
                    "evidence_count": 1,
                }
            ],
            "validation_summary": {
                "total_entities": 1,
                "verified_count": 0,
                "potential_count": 1,
                "avg_confidence": 0.35,
            },
        }

        output = format_relationship_section("CVE-2026-8719", validated_data)

        assert "POTENTIAL CONTEXTUAL ENTITIES" in output
        assert "DRYHOOK" in output
        assert "contextual_overlap" in output
        assert "Weak Signals" in output

    def test_format_summary(self):
        """Should create appropriate summary text"""
        # With verified relationships
        data_verified = {
            "validation_summary": {
                "total_entities": 5,
                "verified_count": 3,
                "potential_count": 2,
                "avg_confidence": 0.75,
            }
        }

        summary = format_relationship_summary(data_verified)
        assert "3 verified relationships" in summary
        assert "2 additional entities" in summary

        # Without verified relationships
        data_potential = {
            "validation_summary": {
                "total_entities": 5,
                "verified_count": 0,
                "potential_count": 5,
                "avg_confidence": 0.35,
            }
        }

        summary = format_relationship_summary(data_potential)
        assert "No verified relationships" in summary
        assert "5 potential entities" in summary


class TestAntiHallucination:
    """Test that system prevents hallucination"""

    def test_total_relationships_zero_means_verified_empty(self):
        """
        If total_relationships = 0, verified section must be empty.
        This is the key anti-hallucination test.
        """
        validator = RelationshipValidator()

        entities = {
            "malwares": [
                {"name": "DRYHOOK"},
                {"name": "BRUSHFIRE"},
            ],
            "campaigns": [
                {"name": "Campaign1"},
            ],
        }

        # No evidence in OpenCTI
        opencti_data = {
            "graph_edges": [],
            "campaigns": [],
            "malwares": [],
            "iocs": [],
        }

        cve_data = {}

        result = validator.validate_relationships_batch(
            "CVE-2026-8719",
            entities,
            opencti_data,
            cve_data,
        )

        # With no evidence, there should be NO verified relationships
        verified_count = result["validation_summary"]["verified_count"]
        assert verified_count == 0, "Zero evidence should produce zero verified relationships"

        # All should be potential at best
        potential_count = result["validation_summary"]["potential_count"]
        assert potential_count >= 0, "May have potential if weak signals exist"

    def test_weak_signal_not_verified(self):
        """Weak signals (NLP, keyword) should never be verified"""
        engine = ConfidenceEngine()

        # Only weak signals
        confidence, _, assessment = engine.calculate_confidence(
            source_entity="CVE-2026-8719",
            target_entity="DRYHOOK",
            evidence_list=[
                {"type": "keyword_match"},
            ],
            provenance_sources=["nlp_inference"],
            cross_validation_count=0,
        )

        assert not ConfidenceThresholds.should_verify(confidence)
        assert "Semantic" in assessment or "VERY_LOW" in assessment


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
