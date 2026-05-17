"""
core/community_detection.py - Community Detection Engine

Discovers threat actor groups and campaign clusters:
- Actor clustering based on shared infrastructure
- Campaign grouping by technique similarity
- Community strength analysis
- Hierarchical clustering visualization
"""

from typing import Dict, List, Set, Tuple, Optional, Any
from datetime import datetime
from collections import defaultdict
import math

from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine


class ActorCommunity:
    """Represents a community of threat actors."""

    def __init__(self, community_id: str, actor_ids: List[str]):
        """Initialize actor community.

        Args:
            community_id: Unique community identifier
            actor_ids: List of actor IDs in community
        """
        self.community_id = community_id
        self.actor_ids = actor_ids
        self.shared_campaigns = []
        self.shared_iocs = []
        self.shared_techniques = []
        self.community_strength = 0.0
        self.size = len(actor_ids)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "community_id": self.community_id,
            "actor_ids": self.actor_ids,
            "size": self.size,
            "shared_campaigns": self.shared_campaigns,
            "shared_iocs": len(self.shared_iocs),
            "shared_techniques": self.shared_techniques,
            "community_strength": self.community_strength,
        }


class CampaignCluster:
    """Represents a cluster of related campaigns."""

    def __init__(self, cluster_id: str, campaign_ids: List[str]):
        """Initialize campaign cluster.

        Args:
            cluster_id: Unique cluster identifier
            campaign_ids: List of campaign IDs in cluster
        """
        self.cluster_id = cluster_id
        self.campaign_ids = campaign_ids
        self.shared_actors = []
        self.shared_targets = []
        self.shared_techniques = []
        self.cluster_cohesion = 0.0
        self.size = len(campaign_ids)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "cluster_id": self.cluster_id,
            "campaign_ids": self.campaign_ids,
            "size": self.size,
            "shared_actors": self.shared_actors,
            "shared_targets": self.shared_targets,
            "shared_techniques": self.shared_techniques,
            "cluster_cohesion": self.cluster_cohesion,
        }


class CommunityDetectionEngine:
    """Engine for detecting communities in threat graph."""

    def __init__(
        self,
        memory_engine: ThreatMemoryEngine,
        pattern_engine: PatternDetectionEngine,
        context_engine: HistoricalContextEngine,
    ):
        """Initialize community detection engine.

        Args:
            memory_engine: Threat memory engine
            pattern_engine: Pattern detection engine
            context_engine: Historical context engine
        """
        self.memory = memory_engine
        self.patterns = pattern_engine
        self.context = context_engine

    def detect_actor_communities(
        self,
        similarity_threshold: float = 0.3,
    ) -> List[ActorCommunity]:
        """Detect communities of threat actors.

        Uses shared campaigns and IOCs to cluster actors.

        Args:
            similarity_threshold: Minimum similarity (0.0-1.0) to link actors

        Returns:
            List of ActorCommunity objects
        """
        # Build actor relationship graph
        actor_similarity = self._calculate_actor_similarity()

        communities = []
        visited = set()
        community_counter = 0

        for actor_id in actor_similarity:
            if actor_id in visited:
                continue

            # Start new community with this actor
            community_actors = {actor_id}
            visited.add(actor_id)
            queue = [actor_id]

            # BFS to find all similar actors
            while queue:
                current = queue.pop(0)
                for other_actor, similarity in actor_similarity[current].items():
                    if other_actor not in visited and similarity >= similarity_threshold:
                        community_actors.add(other_actor)
                        visited.add(other_actor)
                        queue.append(other_actor)

            if len(community_actors) > 0:
                community = ActorCommunity(f"community-{community_counter}", list(community_actors))
                self._analyze_community(community)
                communities.append(community)
                community_counter += 1

        return communities

    def _calculate_actor_similarity(self) -> Dict[str, Dict[str, float]]:
        """Calculate similarity between all actors.

        Uses Jaccard similarity on shared infrastructure.

        Returns:
            Dict with actor pairs and similarity scores (0.0-1.0)
        """
        similarity = defaultdict(dict)
        actors = set()
        actor_iocs = defaultdict(set)
        actor_campaigns = defaultdict(set)

        # Collect actor data
        for campaign_id, camp_mem in self.memory.campaign_memory.items():
            for actor_id in camp_mem.attributed_actors:
                actors.add(actor_id)
                actor_campaigns[actor_id].add(campaign_id)

        # Collect IOCs per actor (via campaigns)
        for ioc_id, ioc_mem in self.memory.ioc_memory.items():
            for campaign_id in ioc_mem.associated_campaigns:
                camp_mem = self.memory.get_campaign_memory(campaign_id)
                if camp_mem:
                    for actor_id in camp_mem.attributed_actors:
                        actor_iocs[actor_id].add(ioc_id)

        # Initialize similarity map for all actors
        for actor_id in actors:
            if actor_id not in similarity:
                similarity[actor_id] = {}

        # Calculate Jaccard similarity
        actors_list = list(actors)
        for i, actor1 in enumerate(actors_list):
            for actor2 in actors_list[i+1:]:
                iocs1 = actor_iocs[actor1]
                iocs2 = actor_iocs[actor2]
                camps1 = actor_campaigns[actor1]
                camps2 = actor_campaigns[actor2]

                # Jaccard: intersection / union
                ioc_intersection = len(iocs1 & iocs2)
                ioc_union = len(iocs1 | iocs2)
                ioc_similarity = ioc_intersection / ioc_union if ioc_union > 0 else 0.0

                camp_intersection = len(camps1 & camps2)
                camp_union = len(camps1 | camps2)
                camp_similarity = camp_intersection / camp_union if camp_union > 0 else 0.0

                # Combined similarity (weighted average)
                combined = (ioc_similarity * 0.6 + camp_similarity * 0.4)

                similarity[actor1][actor2] = combined
                similarity[actor2][actor1] = combined

        return similarity

    def _analyze_community(self, community: ActorCommunity) -> None:
        """Analyze and enrich community data.

        Args:
            community: ActorCommunity to analyze
        """
        shared_campaigns = set()
        shared_iocs = set()
        shared_techniques = set()

        # Find shared campaigns
        for actor_id in community.actor_ids:
            for campaign_id, camp_mem in self.memory.campaign_memory.items():
                if actor_id in camp_mem.attributed_actors:
                    shared_campaigns.add(campaign_id)
                    shared_techniques.update(camp_mem.techniques_evolution)

        # Find shared IOCs
        for ioc_id, ioc_mem in self.memory.ioc_memory.items():
            ioc_in_all_campaigns = all(
                any(
                    actor_id in self.memory.get_campaign_memory(camp_id).attributed_actors
                    for camp_id in ioc_mem.associated_campaigns
                )
                for actor_id in community.actor_ids
            )
            if ioc_in_all_campaigns:
                shared_iocs.add(ioc_id)

        community.shared_campaigns = list(shared_campaigns)
        community.shared_iocs = list(shared_iocs)
        community.shared_techniques = list(shared_techniques)

        # Calculate community strength (0.0-1.0)
        if community.size > 1:
            overlap_factor = len(shared_campaigns) / max(
                sum(
                    len([c for c, m in self.memory.campaign_memory.items()
                         if actor_id in m.attributed_actors])
                    for actor_id in community.actor_ids
                ),
                1
            )
            community.community_strength = min(overlap_factor, 1.0)
        else:
            community.community_strength = 0.5

    def detect_campaign_clusters(
        self,
        similarity_threshold: float = 0.4,
    ) -> List[CampaignCluster]:
        """Detect clusters of related campaigns.

        Uses shared actors, targets, and techniques.

        Args:
            similarity_threshold: Minimum similarity (0.0-1.0) to link campaigns

        Returns:
            List of CampaignCluster objects
        """
        campaign_similarity = self._calculate_campaign_similarity()

        clusters = []
        visited = set()
        cluster_counter = 0

        for campaign_id in campaign_similarity:
            if campaign_id in visited:
                continue

            # Start new cluster with this campaign
            cluster_campaigns = {campaign_id}
            visited.add(campaign_id)
            queue = [campaign_id]

            # BFS to find all similar campaigns
            while queue:
                current = queue.pop(0)
                for other_campaign, similarity in campaign_similarity[current].items():
                    if other_campaign not in visited and similarity >= similarity_threshold:
                        cluster_campaigns.add(other_campaign)
                        visited.add(other_campaign)
                        queue.append(other_campaign)

            if len(cluster_campaigns) > 0:
                cluster = CampaignCluster(f"cluster-{cluster_counter}", list(cluster_campaigns))
                self._analyze_cluster(cluster)
                clusters.append(cluster)
                cluster_counter += 1

        return clusters

    def _calculate_campaign_similarity(self) -> Dict[str, Dict[str, float]]:
        """Calculate similarity between all campaigns.

        Uses Jaccard similarity on actors, targets, and techniques.

        Returns:
            Dict with campaign pairs and similarity scores (0.0-1.0)
        """
        similarity = defaultdict(dict)
        campaigns_list = list(self.memory.campaign_memory.items())

        for i, (campaign1_id, camp1_mem) in enumerate(campaigns_list):
            for campaign2_id, camp2_mem in campaigns_list[i+1:]:
                actors1 = set(camp1_mem.attributed_actors)
                actors2 = set(camp2_mem.attributed_actors)
                targets1 = set(camp1_mem.current_targets)
                targets2 = set(camp2_mem.current_targets)
                techs1 = set(camp1_mem.techniques_evolution)
                techs2 = set(camp2_mem.techniques_evolution)

                # Jaccard similarities
                actor_sim = self._jaccard(actors1, actors2)
                target_sim = self._jaccard(targets1, targets2)
                tech_sim = self._jaccard(techs1, techs2)

                # Weighted average
                combined = (actor_sim * 0.3 + target_sim * 0.3 + tech_sim * 0.4)

                similarity[campaign1_id][campaign2_id] = combined
                similarity[campaign2_id][campaign1_id] = combined

        return similarity

    def _jaccard(self, set1: Set[str], set2: Set[str]) -> float:
        """Calculate Jaccard similarity between sets.

        Args:
            set1: First set
            set2: Second set

        Returns:
            Jaccard similarity (0.0-1.0)
        """
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        return intersection / union if union > 0 else 0.0

    def _analyze_cluster(self, cluster: CampaignCluster) -> None:
        """Analyze and enrich cluster data.

        Args:
            cluster: CampaignCluster to analyze
        """
        shared_actors = set()
        shared_targets = set()
        shared_techniques = set()

        for campaign_id in cluster.campaign_ids:
            camp_mem = self.memory.get_campaign_memory(campaign_id)
            if camp_mem:
                shared_actors.update(camp_mem.attributed_actors)
                shared_targets.update(camp_mem.current_targets)
                shared_techniques.update(camp_mem.techniques_evolution)

        cluster.shared_actors = list(shared_actors)
        cluster.shared_targets = list(shared_targets)
        cluster.shared_techniques = list(shared_techniques)

        # Calculate cluster cohesion
        if cluster.size > 1:
            avg_similarity = sum(
                self._calculate_campaign_similarity().get(cluster.campaign_ids[0], {}).get(c, 0.0)
                for c in cluster.campaign_ids[1:]
            ) / max(cluster.size - 1, 1)
            cluster.cluster_cohesion = min(avg_similarity, 1.0)
        else:
            cluster.cluster_cohesion = 0.5

    def find_isolated_actors(self, min_connections: int = 1) -> List[Dict[str, Any]]:
        """Find actors with few connections (isolated or fringe).

        Args:
            min_connections: Minimum number of shared IOCs/campaigns to include

        Returns:
            List of isolated actor dicts
        """
        isolated = []

        for actor_id in self._get_all_actors():
            actor_data = self._get_actor_connections(actor_id)
            if len(actor_data["shared_campaigns"]) <= min_connections:
                isolated.append({
                    "actor_id": actor_id,
                    "shared_campaigns": actor_data["shared_campaigns"],
                    "shared_iocs": len(actor_data["shared_iocs"]),
                    "is_isolated": len(actor_data["shared_campaigns"]) <= min_connections,
                })

        return isolated

    def _get_all_actors(self) -> Set[str]:
        """Get all actors in memory."""
        actors = set()
        for camp_mem in self.memory.campaign_memory.values():
            actors.update(camp_mem.attributed_actors)
        return actors

    def _get_actor_connections(self, actor_id: str) -> Dict[str, Any]:
        """Get all connections for an actor."""
        campaigns = []
        iocs = set()

        for campaign_id, camp_mem in self.memory.campaign_memory.items():
            if actor_id in camp_mem.attributed_actors:
                campaigns.append(campaign_id)

        # Get IOCs from actor's campaigns
        for ioc_id, ioc_mem in self.memory.ioc_memory.items():
            for campaign_id in campaigns:
                if campaign_id in ioc_mem.associated_campaigns:
                    iocs.add(ioc_id)

        return {
            "actor_id": actor_id,
            "shared_campaigns": campaigns,
            "shared_iocs": iocs,
        }

    def detect_campaign_evolution(self, campaign_id: str) -> Dict[str, Any]:
        """Detect evolution patterns in a campaign.

        Args:
            campaign_id: Campaign ID to analyze

        Returns:
            Dict with evolution metrics
        """
        camp_mem = self.memory.get_campaign_memory(campaign_id)
        if not camp_mem:
            return {"campaign_id": campaign_id, "evolution": "unknown"}

        # Analyze activity evolution
        activities = camp_mem.activities
        if len(activities) < 2:
            return {
                "campaign_id": campaign_id,
                "evolution": "insufficient_data",
                "activity_count": len(activities),
            }

        # Calculate activity rate over time
        first_activity = activities[0].date
        last_activity = activities[-1].date
        duration_days = max((last_activity - first_activity).days, 1)
        activity_rate = len(activities) / duration_days

        # Detect acceleration/deceleration
        if len(activities) > 4:
            mid_point = len(activities) // 2
            early_rate = mid_point / max((activities[mid_point-1].date - first_activity).days, 1)
            late_rate = (len(activities) - mid_point) / max(
                (last_activity - activities[mid_point].date).days, 1
            )
            trend = "accelerating" if late_rate > early_rate * 1.2 else (
                "decelerating" if early_rate > late_rate * 1.2 else "stable"
            )
        else:
            trend = "unknown"

        return {
            "campaign_id": campaign_id,
            "activity_count": len(activities),
            "duration_days": duration_days,
            "activity_rate_per_day": activity_rate,
            "evolution_trend": trend,
            "first_activity": first_activity,
            "last_activity": last_activity,
        }

    def get_community_graph(self) -> Dict[str, Any]:
        """Get complete community graph visualization data.

        Returns:
            Dict with nodes and edges for graph visualization
        """
        communities = self.detect_actor_communities(similarity_threshold=0.2)
        clusters = self.detect_campaign_clusters(similarity_threshold=0.2)

        return {
            "communities": [c.to_dict() for c in communities],
            "clusters": [c.to_dict() for c in clusters],
            "total_communities": len(communities),
            "total_clusters": len(clusters),
            "community_count": len([c for c in communities if c.size > 1]),
            "cluster_count": len([c for c in clusters if c.size > 1]),
        }
