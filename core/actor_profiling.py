"""
core/actor_profiling.py - Threat Actor Profiling Engine

Builds behavioral profiles of threat actors:
- Attack pattern analysis from campaigns
- Infrastructure preference analysis
- Target selection strategy discovery
- Temporal behavior profiling
- TTPs (techniques, tactics, procedures)
- Attribution confidence scoring
"""

from typing import Dict, List, Set, Tuple, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import math

from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine


class ActorProfile:
    """Behavioral profile of a threat actor."""

    def __init__(self, actor_id: str):
        """Initialize actor profile.

        Args:
            actor_id: Unique actor identifier
        """
        self.actor_id = actor_id
        self.campaigns = []
        self.total_campaigns = 0
        self.techniques = []
        self.primary_techniques = []
        self.targets = []
        self.target_sectors = []
        self.infrastructure_nodes = []
        self.avg_campaign_duration_days = 0.0
        self.activity_tempo = "unknown"
        self.targeting_strategy = "unknown"
        self.preferred_ttps = []
        self.operational_security_level = "unknown"
        self.sophistication_level = "unknown"
        self.first_observed = None
        self.last_observed = None
        self.is_active = False
        self.confidence_score = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "actor_id": self.actor_id,
            "campaigns": self.campaigns,
            "total_campaigns": self.total_campaigns,
            "techniques": self.techniques,
            "primary_techniques": self.primary_techniques,
            "targets": self.targets,
            "target_sectors": self.target_sectors,
            "avg_campaign_duration_days": self.avg_campaign_duration_days,
            "activity_tempo": self.activity_tempo,
            "targeting_strategy": self.targeting_strategy,
            "preferred_ttps": self.preferred_ttps,
            "operational_security_level": self.operational_security_level,
            "sophistication_level": self.sophistication_level,
            "first_observed": self.first_observed,
            "last_observed": self.last_observed,
            "is_active": self.is_active,
            "confidence_score": self.confidence_score,
        }


class ActorProfilingEngine:
    """Engine for building and analyzing threat actor profiles."""

    def __init__(
        self,
        memory_engine: ThreatMemoryEngine,
        pattern_engine: PatternDetectionEngine,
        context_engine: HistoricalContextEngine,
    ):
        """Initialize actor profiling engine.

        Args:
            memory_engine: Threat memory engine
            pattern_engine: Pattern detection engine
            context_engine: Historical context engine
        """
        self.memory = memory_engine
        self.patterns = pattern_engine
        self.context = context_engine

    def profile_actor(self, actor_id: str) -> ActorProfile:
        """Build comprehensive profile of a threat actor.

        Args:
            actor_id: Threat actor ID

        Returns:
            ActorProfile with behavioral analysis
        """
        profile = ActorProfile(actor_id)

        # Collect actor's campaigns
        actor_campaigns = []
        for campaign_id, camp_mem in self.memory.campaign_memory.items():
            if actor_id in camp_mem.attributed_actors:
                actor_campaigns.append((campaign_id, camp_mem))

        profile.campaigns = [c[0] for c in actor_campaigns]
        profile.total_campaigns = len(actor_campaigns)

        if not actor_campaigns:
            return profile

        # Analyze techniques
        all_techniques = []
        all_targets = set()
        campaign_durations = []

        for campaign_id, camp_mem in actor_campaigns:
            all_techniques.extend(camp_mem.techniques_evolution)
            all_targets.update(camp_mem.current_targets)

            # Calculate campaign duration
            if camp_mem.activities:
                first = camp_mem.activities[0].date
                last = camp_mem.activities[-1].date
                duration = (last - first).days
                campaign_durations.append(max(duration, 1))

            # Track activity dates
            if camp_mem.first_observed:
                if not profile.first_observed or camp_mem.first_observed < profile.first_observed:
                    profile.first_observed = camp_mem.first_observed
            if camp_mem.last_observed:
                if not profile.last_observed or camp_mem.last_observed > profile.last_observed:
                    profile.last_observed = camp_mem.last_observed

        # Analyze techniques
        profile.techniques = list(set(all_techniques))
        technique_counts = Counter(all_techniques)
        profile.primary_techniques = [t for t, _ in technique_counts.most_common(5)]

        # Analyze targets
        profile.targets = list(all_targets)
        profile.target_sectors = self._infer_target_sectors(all_targets)

        # Campaign duration analysis
        if campaign_durations:
            profile.avg_campaign_duration_days = sum(campaign_durations) / len(campaign_durations)

        # Activity tempo (based on inter-campaign intervals)
        profile.activity_tempo = self._analyze_activity_tempo(actor_campaigns)

        # Targeting strategy
        profile.targeting_strategy = self._analyze_targeting_strategy(all_targets, profile.target_sectors)

        # OPSEC level (based on infrastructure diversity and technique sophistication)
        profile.operational_security_level = self._assess_opsec_level(actor_campaigns)

        # Sophistication level
        profile.sophistication_level = self._assess_sophistication(
            profile.primary_techniques,
            profile.operational_security_level,
            profile.avg_campaign_duration_days
        )

        # Confidence score
        profile.confidence_score = self._calculate_confidence_score(actor_campaigns)

        # Activity status
        profile.is_active = any(c.is_active for _, c in actor_campaigns)

        return profile

    def _infer_target_sectors(self, targets: Set[str]) -> List[str]:
        """Infer target sectors from target list.

        Args:
            targets: Set of target identifiers

        Returns:
            List of inferred sectors
        """
        sector_map = {
            "finance": ["bank", "fin", "exchange", "payment", "crypto", "trading"],
            "healthcare": ["hospital", "pharma", "clinic", "medical", "health"],
            "energy": ["power", "oil", "gas", "utility", "grid"],
            "government": ["gov", "agency", "federal", "state", "defense"],
            "technology": ["tech", "software", "cloud", "data", "security"],
            "manufacturing": ["factory", "plant", "industrial", "supply"],
            "retail": ["store", "commerce", "shop", "mall"],
            "education": ["university", "school", "college", "research"],
        }

        sectors = set()
        target_str = " ".join(targets).lower()

        for sector, keywords in sector_map.items():
            if any(kw in target_str for kw in keywords):
                sectors.add(sector)

        return list(sectors) if sectors else ["unknown"]

    def _analyze_activity_tempo(self, actor_campaigns: List[Tuple[str, Any]]) -> str:
        """Analyze campaign activity tempo (frequency).

        Args:
            actor_campaigns: List of (campaign_id, campaign_memory) tuples

        Returns:
            Tempo classification: continuous/frequent/sporadic/dormant
        """
        if len(actor_campaigns) < 2:
            return "unknown"

        # Sort by first observed date
        sorted_campaigns = sorted(
            actor_campaigns,
            key=lambda x: x[1].first_observed or datetime.utcnow()
        )

        # Calculate inter-campaign intervals (in days)
        intervals = []
        for i in range(len(sorted_campaigns) - 1):
            curr_last = sorted_campaigns[i][1].last_observed or datetime.utcnow()
            next_first = sorted_campaigns[i + 1][1].first_observed or datetime.utcnow()
            interval = (next_first - curr_last).days
            if interval > 0:
                intervals.append(interval)

        if not intervals:
            return "unknown"

        avg_interval = sum(intervals) / len(intervals)

        if avg_interval < 30:
            return "continuous"
        elif avg_interval < 90:
            return "frequent"
        elif avg_interval < 365:
            return "sporadic"
        else:
            return "dormant"

    def _analyze_targeting_strategy(self, targets: Set[str], sectors: List[str]) -> str:
        """Analyze targeting strategy.

        Args:
            targets: Set of targets
            sectors: List of target sectors

        Returns:
            Strategy classification: targeted/vertical/horizontal/opportunistic
        """
        if len(targets) == 0:
            return "unknown"

        # Focused targeting: same sector
        if len(sectors) == 1 and sectors[0] != "unknown":
            return "targeted"

        # Vertical targeting: multiple organizations in same sector
        if len(sectors) == 1:
            return "vertical"

        # Horizontal targeting: multiple sectors
        if len(sectors) > 1 and len(targets) <= 5:
            return "horizontal"

        # Opportunistic: many varied targets
        if len(targets) > 10:
            return "opportunistic"

        return "mixed"

    def _assess_opsec_level(self, actor_campaigns: List[Tuple[str, Any]]) -> str:
        """Assess operational security maturity.

        Args:
            actor_campaigns: List of (campaign_id, campaign_memory) tuples

        Returns:
            OPSEC level: low/medium/high/sophisticated
        """
        if not actor_campaigns:
            return "unknown"

        # Collect infrastructure nodes
        infrastructure_set = set()
        for campaign_id, camp_mem in actor_campaigns:
            # Get IOCs used in this campaign
            for ioc_id, ioc_mem in self.memory.ioc_memory.items():
                if campaign_id in ioc_mem.associated_campaigns:
                    infrastructure_set.add(ioc_id)

        # Assess based on infrastructure reuse and technique diversity
        avg_ioc_reuse = 0.0
        if infrastructure_set:
            ioc_reuse_counts = []
            for ioc_id in infrastructure_set:
                ioc_mem = self.memory.get_ioc_memory(ioc_id)
                if ioc_mem:
                    ioc_reuse_counts.append(ioc_mem.occurrence_count)

            if ioc_reuse_counts:
                avg_ioc_reuse = sum(ioc_reuse_counts) / len(ioc_reuse_counts)

        # Low reuse = higher OPSEC
        if avg_ioc_reuse < 2:
            return "sophisticated"
        elif avg_ioc_reuse < 4:
            return "high"
        elif avg_ioc_reuse < 8:
            return "medium"
        else:
            return "low"

    def _assess_sophistication(
        self,
        techniques: List[str],
        opsec_level: str,
        avg_duration: float
    ) -> str:
        """Assess actor sophistication level.

        Args:
            techniques: List of techniques used
            opsec_level: OPSEC level assessment
            avg_duration: Average campaign duration

        Returns:
            Sophistication level: low/medium/high/very_high
        """
        score = 0.0

        # Technique diversity (0-33 points)
        if len(techniques) > 10:
            score += 33
        elif len(techniques) > 5:
            score += 20
        elif len(techniques) > 2:
            score += 10

        # Advanced techniques (0-33 points)
        advanced_techniques = {
            "T1021", "T1055", "T1134", "T1547", "T1056", "T1557",  # Lateral movement, privilege escalation
            "T1140", "T1197", "T1535", "T1566", "T1598",  # Defense evasion, initial access
        }
        if any(t in advanced_techniques for t in techniques):
            score += 15

        # OPSEC assessment (0-34 points)
        opsec_scores = {
            "sophisticated": 34,
            "high": 25,
            "medium": 15,
            "low": 5,
            "unknown": 0,
        }
        score += opsec_scores.get(opsec_level, 0)

        # Campaign duration (0-10 points, longer = more sustained = more sophisticated)
        if avg_duration > 180:
            score += 10
        elif avg_duration > 90:
            score += 7
        elif avg_duration > 30:
            score += 4

        if score >= 70:
            return "very_high"
        elif score >= 50:
            return "high"
        elif score >= 25:
            return "medium"
        else:
            return "low"

    def _calculate_confidence_score(self, actor_campaigns: List[Tuple[str, Any]]) -> float:
        """Calculate attribution confidence score (0.0-1.0).

        Args:
            actor_campaigns: List of (campaign_id, campaign_memory) tuples

        Returns:
            Confidence score between 0.0 and 1.0
        """
        if not actor_campaigns:
            return 0.0

        # Base score: number of campaigns (up to 1.0)
        campaign_score = min(len(actor_campaigns) / 5.0, 1.0)

        # Technique consistency (high=higher confidence)
        all_techniques = []
        for _, camp_mem in actor_campaigns:
            all_techniques.extend(camp_mem.techniques_evolution)

        if all_techniques:
            technique_consistency = len(set(all_techniques)) / len(all_techniques)
        else:
            technique_consistency = 0.0

        # Time span (sustained activity = higher confidence)
        if actor_campaigns:
            first_dates = [c[1].first_observed for c in actor_campaigns if c[1].first_observed]
            last_dates = [c[1].last_observed for c in actor_campaigns if c[1].last_observed]

            if first_dates and last_dates:
                earliest = min(first_dates)
                latest = max(last_dates)
                time_span_days = (latest - earliest).days
                time_span_score = min(time_span_days / 365.0, 1.0)
            else:
                time_span_score = 0.0
        else:
            time_span_score = 0.0

        # Weighted combination
        confidence = (
            campaign_score * 0.4 +
            technique_consistency * 0.3 +
            time_span_score * 0.3
        )

        return min(confidence, 1.0)

    def get_all_actor_profiles(self) -> List[ActorProfile]:
        """Get profiles for all actors in memory.

        Returns:
            List of ActorProfile objects
        """
        actors = set()
        for camp_mem in self.memory.campaign_memory.values():
            actors.update(camp_mem.attributed_actors)

        profiles = []
        for actor_id in sorted(actors):
            profile = self.profile_actor(actor_id)
            profiles.append(profile)

        return profiles

    def compare_actors(self, actor_id1: str, actor_id2: str) -> Dict[str, Any]:
        """Compare two threat actors.

        Args:
            actor_id1: First actor ID
            actor_id2: Second actor ID

        Returns:
            Dict with comparison metrics
        """
        profile1 = self.profile_actor(actor_id1)
        profile2 = self.profile_actor(actor_id2)

        # Technique overlap
        tech1 = set(profile1.techniques)
        tech2 = set(profile2.techniques)
        tech_intersection = len(tech1 & tech2)
        tech_union = len(tech1 | tech2)
        technique_similarity = tech_intersection / tech_union if tech_union > 0 else 0.0

        # Target overlap
        targets1 = set(profile1.targets)
        targets2 = set(profile2.targets)
        target_intersection = len(targets1 & targets2)
        target_union = len(targets1 | targets2)
        target_similarity = target_intersection / target_union if target_union > 0 else 0.0

        # Sector overlap
        sectors1 = set(profile1.target_sectors)
        sectors2 = set(profile2.target_sectors)
        sector_intersection = len(sectors1 & sectors2)
        sector_union = len(sectors1 | sectors2)
        sector_similarity = sector_intersection / sector_union if sector_union > 0 else 0.0

        # Overall similarity
        overall_similarity = (
            technique_similarity * 0.5 +
            target_similarity * 0.3 +
            sector_similarity * 0.2
        )

        return {
            "actor1_id": actor_id1,
            "actor2_id": actor_id2,
            "technique_similarity": technique_similarity,
            "target_similarity": target_similarity,
            "sector_similarity": sector_similarity,
            "overall_similarity": overall_similarity,
            "shared_techniques": list(tech1 & tech2),
            "shared_targets": list(targets1 & targets2),
            "shared_sectors": list(sectors1 & sectors2),
        }

    def rank_actors_by_threat(self) -> List[Dict[str, Any]]:
        """Rank all actors by threat level.

        Returns:
            List of actor rankings with threat scores
        """
        profiles = self.get_all_actor_profiles()

        ranked = []
        for profile in profiles:
            # Threat score: combination of activity, sophistication, and targeting
            activity_score = min(profile.total_campaigns / 10.0, 1.0)

            sophistication_scores = {
                "very_high": 1.0,
                "high": 0.75,
                "medium": 0.5,
                "low": 0.25,
                "unknown": 0.0,
            }
            soph_score = sophistication_scores.get(profile.sophistication_level, 0.0)

            is_active_score = 1.0 if profile.is_active else 0.5

            threat_score = (
                activity_score * 0.4 +
                soph_score * 0.4 +
                is_active_score * 0.2
            )

            ranked.append({
                "actor_id": profile.actor_id,
                "threat_score": threat_score,
                "total_campaigns": profile.total_campaigns,
                "sophistication": profile.sophistication_level,
                "is_active": profile.is_active,
                "confidence": profile.confidence_score,
            })

        return sorted(ranked, key=lambda x: x["threat_score"], reverse=True)
