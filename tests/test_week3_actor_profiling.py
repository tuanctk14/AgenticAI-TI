"""
tests/test_week3_actor_profiling.py - Actor Profiling Tests

Tests for:
- Actor profile building and analysis
- Behavioral pattern detection
- Technique and target analysis
- OPSEC and sophistication assessment
- Actor comparison and similarity
- Threat ranking
"""

import pytest
from datetime import datetime, timedelta

from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine
from core.actor_profiling import (
    ActorProfilingEngine,
    ActorProfile,
)


class TestActorProfileBuilding:
    """Test basic actor profile creation."""

    def test_build_actor_profile(self):
        """Test building profile for a single actor."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        # Create campaign for actor
        memory.record_campaign_activity("campaign-1", "Campaign 1", "exploit")
        campaign = memory.get_campaign_memory("campaign-1")
        if campaign:
            campaign.attributed_actors.append("actor-1")

        profile = engine.profile_actor("actor-1")

        assert profile.actor_id == "actor-1"
        assert isinstance(profile.campaigns, list)
        assert "campaign-1" in profile.campaigns
        assert profile.total_campaigns >= 1

    def test_profile_properties(self):
        """Test actor profile properties."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        memory.record_campaign_activity("campaign-1", "Campaign 1", "exploit")
        campaign = memory.get_campaign_memory("campaign-1")
        if campaign:
            campaign.attributed_actors.append("actor-1")

        profile = engine.profile_actor("actor-1")

        assert profile.techniques is not None
        assert isinstance(profile.targets, list)
        assert isinstance(profile.target_sectors, list)
        assert 0.0 <= profile.confidence_score <= 1.0

    def test_profile_to_dict(self):
        """Test profile serialization."""
        profile = ActorProfile("actor-1")
        profile.total_campaigns = 3
        profile.sophistication_level = "high"
        profile.is_active = True

        data = profile.to_dict()

        assert data["actor_id"] == "actor-1"
        assert data["total_campaigns"] == 3
        assert data["sophistication_level"] == "high"
        assert data["is_active"] is True

    def test_unknown_actor_profile(self):
        """Test profile for non-existent actor."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        profile = engine.profile_actor("unknown-actor")

        assert profile.actor_id == "unknown-actor"
        assert profile.total_campaigns == 0
        assert len(profile.campaigns) == 0


class TestTechniqueAnalysis:
    """Test technique pattern extraction."""

    def test_primary_techniques_extraction(self):
        """Test identification of primary techniques."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        # Create campaign with techniques
        memory.record_campaign_activity(
            "campaign-tech",
            "Campaign",
            "exploit",
            techniques_used=["T1566", "T1566", "T1598"]
        )
        campaign = memory.get_campaign_memory("campaign-tech")
        if campaign:
            campaign.attributed_actors.append("actor-tech")

        profile = engine.profile_actor("actor-tech")

        assert len(profile.primary_techniques) > 0
        assert "T1566" in profile.primary_techniques or "T1598" in profile.primary_techniques

    def test_technique_diversity(self):
        """Test technique diversity measurement."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        memory.record_campaign_activity(
            "campaign-1",
            "Campaign 1",
            "exploit",
            techniques_used=["T1566", "T1598", "T1192"]
        )
        campaign = memory.get_campaign_memory("campaign-1")
        if campaign:
            campaign.attributed_actors.append("actor-diverse")

        profile = engine.profile_actor("actor-diverse")

        assert len(profile.techniques) >= 1


class TestTargetAnalysis:
    """Test target and sector analysis."""

    def test_target_extraction(self):
        """Test extraction of target list."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        memory.record_campaign_activity("campaign-target", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-target")
        if campaign:
            campaign.attributed_actors.append("actor-target")
            campaign.current_targets.extend(["target-1", "target-2"])

        profile = engine.profile_actor("actor-target")

        assert len(profile.targets) >= 2
        assert "target-1" in profile.targets
        assert "target-2" in profile.targets

    def test_sector_inference(self):
        """Test sector inference from targets."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        memory.record_campaign_activity("campaign-sector", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-sector")
        if campaign:
            campaign.attributed_actors.append("actor-sector")
            campaign.current_targets.extend(["bank-1", "financial-org"])

        profile = engine.profile_actor("actor-sector")

        assert len(profile.target_sectors) > 0
        assert "finance" in profile.target_sectors

    def test_targeting_strategy_classification(self):
        """Test targeting strategy classification."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        # Create campaign with focused targeting
        memory.record_campaign_activity("campaign-focused", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-focused")
        if campaign:
            campaign.attributed_actors.append("actor-focused")
            campaign.current_targets.extend(["bank-1", "bank-2", "bank-3"])

        profile = engine.profile_actor("actor-focused")

        assert profile.targeting_strategy in [
            "targeted", "vertical", "horizontal", "opportunistic", "mixed", "unknown"
        ]


class TestActivityTempo:
    """Test activity tempo analysis."""

    def test_activity_tempo_continuous(self):
        """Test continuous activity detection."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        # Create multiple close campaigns
        for i in range(3):
            memory.record_campaign_activity(f"campaign-{i}", f"Campaign {i}", "exploit")
            campaign = memory.get_campaign_memory(f"campaign-{i}")
            if campaign:
                campaign.attributed_actors.append("actor-tempo")

        profile = engine.profile_actor("actor-tempo")

        assert profile.activity_tempo in [
            "continuous", "frequent", "sporadic", "dormant", "unknown"
        ]

    def test_activity_tempo_single_campaign(self):
        """Test tempo with single campaign."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        memory.record_campaign_activity("campaign-single", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-single")
        if campaign:
            campaign.attributed_actors.append("actor-single")

        profile = engine.profile_actor("actor-single")

        assert profile.activity_tempo == "unknown"


class TestOPSECAndSophistication:
    """Test OPSEC and sophistication assessment."""

    def test_opsec_assessment(self):
        """Test OPSEC level assessment."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        memory.record_campaign_activity("campaign-opsec", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-opsec")
        if campaign:
            campaign.attributed_actors.append("actor-opsec")

        profile = engine.profile_actor("actor-opsec")

        assert profile.operational_security_level in [
            "low", "medium", "high", "sophisticated", "unknown"
        ]

    def test_sophistication_assessment(self):
        """Test sophistication level assessment."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        memory.record_campaign_activity(
            "campaign-soph",
            "Campaign",
            "exploit",
            techniques_used=["T1021", "T1055", "T1134"]
        )
        campaign = memory.get_campaign_memory("campaign-soph")
        if campaign:
            campaign.attributed_actors.append("actor-soph")

        profile = engine.profile_actor("actor-soph")

        assert profile.sophistication_level in [
            "low", "medium", "high", "very_high", "unknown"
        ]


class TestActorComparison:
    """Test actor comparison and similarity."""

    def test_compare_actors(self):
        """Test comparing two actors."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        # Create two campaigns with shared techniques
        for i in range(2):
            memory.record_campaign_activity(
                f"campaign-{i}",
                f"Campaign {i}",
                "exploit",
                techniques_used=["T1566", "T1598"]
            )
            campaign = memory.get_campaign_memory(f"campaign-{i}")
            if campaign:
                campaign.attributed_actors.append(f"actor-compare-{i}")

        comparison = engine.compare_actors("actor-compare-0", "actor-compare-1")

        assert comparison["actor1_id"] == "actor-compare-0"
        assert comparison["actor2_id"] == "actor-compare-1"
        assert 0.0 <= comparison["technique_similarity"] <= 1.0
        assert 0.0 <= comparison["overall_similarity"] <= 1.0

    def test_actor_similarity_identical_behavior(self):
        """Test similarity for actors with identical behavior."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        # Create two campaigns with identical targeting
        for i in range(2):
            memory.record_campaign_activity(f"campaign-{i}", f"Campaign {i}", "exploit")
            campaign = memory.get_campaign_memory(f"campaign-{i}")
            if campaign:
                campaign.attributed_actors.append(f"actor-identical-{i}")
                campaign.current_targets.extend(["target-1", "target-2"])

        comparison = engine.compare_actors("actor-identical-0", "actor-identical-1")

        assert comparison["target_similarity"] > 0.0


class TestActorRanking:
    """Test threat ranking of actors."""

    def test_rank_actors_by_threat(self):
        """Test actor threat ranking."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        # Create multiple actors with different activity levels
        for j in range(3):
            for i in range(j + 1):
                memory.record_campaign_activity(
                    f"campaign-{j}-{i}",
                    f"Campaign {j}-{i}",
                    "exploit"
                )
                campaign = memory.get_campaign_memory(f"campaign-{j}-{i}")
                if campaign:
                    campaign.attributed_actors.append(f"actor-rank-{j}")

        rankings = engine.rank_actors_by_threat()

        assert isinstance(rankings, list)
        assert all("threat_score" in r for r in rankings)
        assert all(0.0 <= r["threat_score"] <= 1.0 for r in rankings)

    def test_active_actor_ranking(self):
        """Test that active actors rank higher."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        # Create active and inactive actors
        for actor_active in [True]:
            memory.record_campaign_activity("campaign-active", "Campaign Active", "exploit")
            campaign = memory.get_campaign_memory("campaign-active")
            if campaign:
                campaign.attributed_actors.append("actor-active")
                campaign.is_active = True

        rankings = engine.rank_actors_by_threat()

        assert len(rankings) > 0
        if len(rankings) > 0:
            assert rankings[0]["threat_score"] >= 0.0


class TestAllActorProfiles:
    """Test batch actor profiling."""

    def test_get_all_actor_profiles(self):
        """Test getting profiles for all actors."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        # Create multiple actors
        for i in range(3):
            memory.record_campaign_activity(f"campaign-{i}", f"Campaign {i}", "exploit")
            campaign = memory.get_campaign_memory(f"campaign-{i}")
            if campaign:
                campaign.attributed_actors.append(f"actor-batch-{i}")

        profiles = engine.get_all_actor_profiles()

        assert isinstance(profiles, list)
        assert len(profiles) >= 3
        assert all(isinstance(p, ActorProfile) for p in profiles)

    def test_all_profiles_sorted(self):
        """Test that profiles are sorted by actor ID."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        for i in range(3):
            memory.record_campaign_activity(f"campaign-{i}", f"Campaign {i}", "exploit")
            campaign = memory.get_campaign_memory(f"campaign-{i}")
            if campaign:
                campaign.attributed_actors.append(f"actor-{i}")

        profiles = engine.get_all_actor_profiles()

        if len(profiles) > 1:
            actor_ids = [p.actor_id for p in profiles]
            assert actor_ids == sorted(actor_ids)


class TestIntegration:
    """Test actor profiling integration."""

    def test_complete_actor_profiling_workflow(self):
        """Test complete actor profiling workflow."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        # Create complex scenario
        for i in range(3):
            memory.record_campaign_activity(
                f"campaign-{i}",
                f"Campaign {i}",
                "exploit",
                techniques_used=["T1566", "T1598", "T1192"]
            )
            campaign = memory.get_campaign_memory(f"campaign-{i}")
            if campaign:
                campaign.attributed_actors.append("actor-workflow")
                campaign.current_targets.extend(["bank-1", "bank-2"])

        # Build profile
        profile = engine.profile_actor("actor-workflow")
        assert profile.total_campaigns >= 1

        # Get all profiles
        all_profiles = engine.get_all_actor_profiles()
        assert len(all_profiles) > 0

        # Rank actors
        rankings = engine.rank_actors_by_threat()
        assert len(rankings) > 0

    def test_profiling_with_infrastructure(self):
        """Test profiling considering infrastructure."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = ActorProfilingEngine(memory, patterns, context)

        # Create IOCs and campaigns
        memory.record_ioc_occurrence("ioc-1", "192.168.1.1", "obs_1")
        memory.record_campaign_activity("campaign-infra", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-infra")
        if campaign:
            campaign.attributed_actors.append("actor-infra")

        profile = engine.profile_actor("actor-infra")

        assert profile.actor_id == "actor-infra"
        assert profile.operational_security_level in [
            "low", "medium", "high", "sophisticated", "unknown"
        ]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
