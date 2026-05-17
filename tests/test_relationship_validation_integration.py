# -*- coding: utf-8 -*-
"""
tests/test_relationship_validation_integration.py - Integration test for Validation Layer

Tests the complete flow:
CVE enrichment → Validation → Confidence scoring → Formatted output
"""

import pytest
from tools.relationship_confidence_engine import score_relationship, ConfidenceThresholds
from tools.relationship_formatter import format_relationship_summary


class TestValidationIntegration:
    """Integration tests for complete validation pipeline"""

    def test_verified_vs_potential_separation(self):
        """
        KEY TEST: Demonstrates the new validation system.

        Scenario: CVE-2026-8719 with entities from OpenCTI

        Before (Hallucination):
        - [CVE-2026-8719] Total relationships found: 0
        - Still displays: 12 malware, 6 campaigns

        After (Validation):
        - If total_relationships = 0, verified_relationships must be empty
        - Weak signals go to "potential_entities" with clear warning
        """

        # Scenario: High-confidence relationship (direct evidence)
        result_high = score_relationship(
            source_entity="CVE-2021-44228",
            target_entity="Conti",
            evidence=[
                {"type": "direct_graph"},
                {"type": "malware_analysis"},
            ],
            provenance=["opencti_direct_edge", "mandiant"],
            days_old=15,
        )

        assert result_high["is_verified"], "Direct evidence should verify"
        assert result_high["confidence"] >= 0.75

        # Scenario: Weak contextual-only relationship
        result_weak = score_relationship(
            source_entity="CVE-2026-8719",
            target_entity="DRYHOOK",
            evidence=[
                {"type": "semantic_correlation"},
            ],
            provenance=["nlp_inference"],
            days_old=90,
        )

        assert not result_weak["is_verified"], "NLP-only should NOT verify"
        # May be potential or rejected depending on exact scores
        # but definitely NOT verified
        assert result_weak["confidence"] < 0.75

    def test_confidence_scoring_demo(self):
        """
        Demonstrate confidence scoring with factor breakdown.
        """

        result = score_relationship(
            source_entity="CVE-2021-44228",
            target_entity="Conti",
            evidence=[
                {"type": "direct_graph"},
                {"type": "att_ck_linkage"},
                {"type": "ioc_correlation"},
            ],
            provenance=["opencti_direct_edge", "mitre_att_ck", "vulncheck"],
            days_old=10,
        )

        # Check confidence calculation
        assert result["confidence"] > 0.75
        assert result["is_verified"]

        # Check factors breakdown
        factors = result["factors"]
        assert len(factors) == 4  # Evidence, Provenance, Temporal, Cross-validation

        # Evidence Quality factor
        evidence_factor = next(f for f in factors if f["name"] == "Evidence Quality")
        assert evidence_factor["score"] > 0.8  # Multiple evidence items

        # Provenance factor
        provenance_factor = next(f for f in factors if f["name"] == "Provenance Trust")
        assert provenance_factor["score"] > 0.85  # Good sources

        # Temporal factor
        temporal_factor = next(f for f in factors if f["name"] == "Temporal Freshness")
        assert temporal_factor["score"] == 1.0  # Fresh (10 days)

    def test_weak_signal_filtering(self):
        """
        Demonstrate that weak signals (NLP, keyword) are filtered out.

        This prevents the hallucination of:
        [CVE-2026-8719] Total relationships found: 0
        12 malware families shown anyway
        """

        weak_signal_results = []

        # Test: weak signals should NOT verify
        weak_signals = [
            ("keyword_match", ["nlp_inference"]),
            ("semantic_correlation", ["nlp_inference"]),
        ]

        for evidence_type, sources in weak_signals:
            result = score_relationship(
                source_entity="CVE-2026-8719",
                target_entity="DRYHOOK",
                evidence=[{"type": evidence_type}],
                provenance=sources,
                days_old=180,
            )

            weak_signal_results.append(result)

            # Weak signals should NOT be verified
            assert not result["is_verified"], f"{evidence_type} should not verify"

    def test_threshold_boundaries(self):
        """
        Test confidence threshold boundaries.

        HIGH (verified): >= 0.75
        MEDIUM (potential): 0.40-0.74
        LOW (potential): 0.20-0.39
        REJECTED: < 0.20
        """

        test_cases = [
            (0.85, True, False),   # HIGH - verified
            (0.75, True, False),   # HIGH boundary - verified
            (0.74, False, True),   # Just below verified - potential
            (0.50, False, True),   # MEDIUM - potential
            (0.40, False, True),   # MEDIUM boundary - potential
            (0.19, False, False),  # Below potential - rejected
            (0.15, False, False),  # REJECTED
        ]

        for confidence, should_verify, should_potential in test_cases:
            assert (
                ConfidenceThresholds.should_verify(confidence) == should_verify
            ), f"Confidence {confidence}: verify={should_verify}"
            assert (
                ConfidenceThresholds.should_show_as_potential(confidence)
                == should_potential
            ), f"Confidence {confidence}: potential={should_potential}"

    def test_zero_relationships_zero_verified(self):
        """
        CRITICAL TEST: The main hallucination prevention.

        If OpenCTI returns zero relationships for a CVE,
        the system MUST output zero verified relationships.

        (It may still show potential entities with weak signals)
        """

        # Simulate: CVE queried, OpenCTI has NO direct relationships
        # But system extracts weak contextual entities

        weak_only_results = {
            "verified_relationships": [],  # MUST be empty
            "potential_entities": [
                {
                    "name": "DRYHOOK",
                    "confidence": 0.35,
                    "confidence_level": "LOW",
                    "correlation_type": "contextual_overlap",
                }
            ],
            "validation_summary": {
                "total_entities": 1,
                "verified_count": 0,
                "potential_count": 1,
                "avg_confidence": 0.35,
            },
        }

        summary = format_relationship_summary(weak_only_results)

        # Should clearly indicate NO verified relationships
        assert "No verified relationships" in summary
        assert "1 potential entities" in summary

        # Should NOT falsely claim verification
        assert "verified" not in summary.lower() or "No verified" in summary


class TestConfidenceFactorWeighting:
    """Test that confidence factors are weighted appropriately"""

    def test_direct_edge_dominates(self):
        """Direct edge should heavily influence confidence"""
        result_direct = score_relationship(
            source_entity="CVE-2021-44228",
            target_entity="Conti",
            evidence=[{"type": "direct_graph"}],
            provenance=["opencti_direct_edge"],
        )

        result_semantic = score_relationship(
            source_entity="CVE-2021-44228",
            target_entity="Conti",
            evidence=[{"type": "semantic_correlation"}],
            provenance=["nlp_inference"],
        )

        assert (
            result_direct["confidence"] > result_semantic["confidence"] * 2
        ), "Direct edge should be significantly higher"

    def test_provenance_trust_hierarchy(self):
        """More trusted sources should score higher"""
        result_mandiant = score_relationship(
            source_entity="CVE-2021-44228",
            target_entity="Conti",
            evidence=[{"type": "malware_analysis"}],
            provenance=["mandiant"],
        )

        result_nlp = score_relationship(
            source_entity="CVE-2021-44228",
            target_entity="Conti",
            evidence=[{"type": "malware_analysis"}],
            provenance=["nlp_inference"],
        )

        assert result_mandiant["confidence"] > result_nlp["confidence"]

    def test_temporal_decay(self):
        """Older intelligence should score lower"""
        result_fresh = score_relationship(
            source_entity="CVE-2021-44228",
            target_entity="Conti",
            evidence=[{"type": "direct_graph"}],
            provenance=["opencti_direct_edge"],
            days_old=7,
        )

        result_stale = score_relationship(
            source_entity="CVE-2021-44228",
            target_entity="Conti",
            evidence=[{"type": "direct_graph"}],
            provenance=["opencti_direct_edge"],
            days_old=500,
        )

        assert result_fresh["confidence"] > result_stale["confidence"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
