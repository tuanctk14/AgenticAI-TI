"""
core/graph_query_engine.py - SPARQL-like Graph Query Engine

Enables complex threat relationship queries across memory:
- Entity search and traversal
- Pattern-based queries
- Relationship traversal (multi-hop)
- Aggregation and filtering
- Community detection
"""

from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime
from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine


class GraphQueryEngine:
    """Query engine for threat relationship graphs."""

    def __init__(
        self,
        memory_engine: ThreatMemoryEngine,
        pattern_engine: PatternDetectionEngine,
        context_engine: HistoricalContextEngine,
    ):
        """Initialize graph query engine.

        Args:
            memory_engine: Threat memory engine
            pattern_engine: Pattern detection engine
            context_engine: Historical context engine
        """
        self.memory = memory_engine
        self.patterns = pattern_engine
        self.context = context_engine

    def find_ioc_by_value(self, value: str) -> Optional[Dict[str, Any]]:
        """Find IOC by its value (IP, domain, hash, etc).

        Args:
            value: IOC value to search for

        Returns:
            IOC memory record if found, None otherwise
        """
        for ioc_id, ioc_mem in self.memory.ioc_memory.items():
            if ioc_mem.ioc_value == value:
                return {
                    "ioc_id": ioc_id,
                    "ioc_value": ioc_mem.ioc_value,
                    "first_observed": ioc_mem.first_observed,
                    "last_observed": ioc_mem.last_observed,
                    "occurrence_count": ioc_mem.occurrence_count,
                    "associated_campaigns": ioc_mem.associated_campaigns,
                    "associated_actors": ioc_mem.associated_actors,
                }
        return None

    def find_campaign_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Find campaign by name.

        Args:
            name: Campaign name to search for

        Returns:
            Campaign memory record if found, None otherwise
        """
        for campaign_id, camp_mem in self.memory.campaign_memory.items():
            if camp_mem.campaign_name.lower() == name.lower():
                return {
                    "campaign_id": campaign_id,
                    "campaign_name": camp_mem.campaign_name,
                    "first_observed": camp_mem.first_observed,
                    "last_observed": camp_mem.last_observed,
                    "is_active": camp_mem.is_active,
                    "activity_count": camp_mem.activity_count,
                    "attributed_actors": camp_mem.attributed_actors,
                }
        return None

    def find_asset_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Find asset by name.

        Args:
            name: Asset name to search for

        Returns:
            Asset memory record if found, None otherwise
        """
        for asset_id, asset_mem in self.memory.asset_memory.items():
            if asset_mem.asset_name.lower() == name.lower():
                return {
                    "asset_id": asset_id,
                    "asset_name": asset_mem.asset_name,
                    "exposure_count": asset_mem.exposure_count,
                    "is_currently_exposed": asset_mem.is_currently_exposed,
                }
        return None

    def find_related_iocs(self, ioc_id: str, max_hops: int = 2) -> Dict[str, List[str]]:
        """Find IOCs related through campaigns/actors.

        Args:
            ioc_id: Source IOC ID
            max_hops: Maximum relationship hops to traverse

        Returns:
            Dict with related_iocs, related_campaigns, related_actors
        """
        ioc_mem = self.memory.get_ioc_memory(ioc_id)
        if not ioc_mem:
            return {
                "ioc_id": ioc_id,
                "related_iocs": [],
                "related_campaigns": [],
                "related_actors": [],
            }

        related_iocs = set()
        related_campaigns = set(ioc_mem.associated_campaigns)
        related_actors = set(ioc_mem.associated_actors)

        # 1-hop: IOCs in same campaigns
        for campaign_id in ioc_mem.associated_campaigns:
            camp_mem = self.memory.get_campaign_memory(campaign_id)
            if camp_mem:
                related_actors.update(camp_mem.attributed_actors)

        # Get all IOCs in related campaigns (if max_hops >= 2)
        if max_hops >= 2:
            all_iocs = self.memory.ioc_memory
            for camp_id in ioc_mem.associated_campaigns:
                for other_ioc_id, other_ioc_mem in all_iocs.items():
                    if other_ioc_id != ioc_id and camp_id in other_ioc_mem.associated_campaigns:
                        related_iocs.add(other_ioc_id)

        return {
            "ioc_id": ioc_id,
            "related_iocs": list(related_iocs),
            "related_campaigns": list(related_campaigns),
            "related_actors": list(related_actors),
            "hops_traversed": min(max_hops, 2 if related_iocs else 1),
        }

    def find_actor_campaigns(self, actor_id: str) -> Dict[str, Any]:
        """Find all campaigns attributed to actor.

        Args:
            actor_id: Threat actor ID

        Returns:
            Dict with actor_id, campaign_ids, total_campaigns, is_active
        """
        all_campaigns = self.memory.campaign_memory
        actor_campaigns = []
        is_active = False

        for campaign_id, camp_mem in all_campaigns.items():
            if actor_id in camp_mem.attributed_actors:
                actor_campaigns.append(campaign_id)
                if camp_mem.is_active:
                    is_active = True

        return {
            "actor_id": actor_id,
            "campaign_ids": actor_campaigns,
            "total_campaigns": len(actor_campaigns),
            "is_active": is_active,
        }

    def find_campaign_infrastructure(self, campaign_id: str) -> Dict[str, Any]:
        """Find infrastructure used in campaign (via IOCs).

        Args:
            campaign_id: Campaign ID

        Returns:
            Dict with campaign_id, ioc_ids, actor_ids, asset_targets
        """
        camp_mem = self.memory.get_campaign_memory(campaign_id)
        if not camp_mem:
            return {"campaign_id": campaign_id, "ioc_ids": [], "actor_ids": [], "asset_targets": []}

        ioc_ids = []
        all_iocs = self.memory.ioc_memory
        for ioc_id, ioc_mem in all_iocs.items():
            if campaign_id in ioc_mem.associated_campaigns:
                ioc_ids.append(ioc_id)

        return {
            "campaign_id": campaign_id,
            "ioc_ids": ioc_ids,
            "actor_ids": camp_mem.attributed_actors,
            "asset_targets": camp_mem.current_targets,
            "techniques_used": camp_mem.techniques_evolution,
        }

    def find_asset_threat_landscape(self, asset_id: str) -> Dict[str, Any]:
        """Find all threats targeting an asset.

        Args:
            asset_id: Asset ID

        Returns:
            Dict with asset_id, campaigns, iocs, actors, exposures
        """
        asset_mem = self.memory.get_asset_memory(asset_id)
        if not asset_mem:
            return {
                "asset_id": asset_id,
                "campaigns": [],
                "iocs": [],
                "actors": [],
            }

        iocs = []
        actors = set()
        campaigns = set()

        # Get IOCs associated with asset exposures
        for exposure in asset_mem.exposures:
            if exposure.ioc_id:
                iocs.append(exposure.ioc_id)
                # Find campaigns involving this IOC
                ioc_mem = self.memory.get_ioc_memory(exposure.ioc_id)
                if ioc_mem:
                    campaigns.update(ioc_mem.associated_campaigns)
                    actors.update(ioc_mem.associated_actors)

        # Get actors from campaigns
        for campaign_id in campaigns:
            camp_mem = self.memory.get_campaign_memory(campaign_id)
            if camp_mem:
                actors.update(camp_mem.attributed_actors)

        return {
            "asset_id": asset_id,
            "asset_name": asset_mem.asset_name,
            "campaigns": list(campaigns),
            "iocs": list(set(iocs)),
            "actors": list(actors),
            "exposure_count": asset_mem.exposure_count,
            "is_exposed": asset_mem.is_currently_exposed,
        }

    def get_threat_actors(self) -> List[Dict[str, Any]]:
        """Get all threat actors in memory.

        Returns:
            List of actor dicts with id, campaigns, techniques
        """
        all_campaigns = self.memory.campaign_memory
        actors_map = {}

        for campaign_id, camp_mem in all_campaigns.items():
            for actor_id in camp_mem.attributed_actors:
                if actor_id not in actors_map:
                    actors_map[actor_id] = {
                        "actor_id": actor_id,
                        "campaigns": [],
                        "techniques": set(),
                        "targets": set(),
                    }
                actors_map[actor_id]["campaigns"].append(campaign_id)
                actors_map[actor_id]["techniques"].update(camp_mem.techniques_evolution)
                actors_map[actor_id]["targets"].update(camp_mem.current_targets)

        # Convert sets to lists
        result = []
        for actor_id, data in actors_map.items():
            result.append({
                "actor_id": actor_id,
                "campaign_count": len(data["campaigns"]),
                "campaigns": data["campaigns"],
                "techniques": list(data["techniques"]),
                "targets": list(data["targets"]),
            })

        return result

    def get_active_campaigns(self) -> List[Dict[str, Any]]:
        """Get all active campaigns.

        Returns:
            List of active campaign dicts
        """
        all_campaigns = self.memory.campaign_memory
        active = []

        for campaign_id, camp_mem in all_campaigns.items():
            if camp_mem.is_active:
                active.append({
                    "campaign_id": campaign_id,
                    "campaign_name": camp_mem.campaign_name,
                    "activity_count": camp_mem.activity_count,
                    "attributed_actors": camp_mem.attributed_actors,
                    "targets": camp_mem.current_targets,
                    "last_observed": camp_mem.last_observed,
                })

        return sorted(active, key=lambda x: x["last_observed"], reverse=True)

    def get_exposed_assets(self) -> List[Dict[str, Any]]:
        """Get all currently exposed assets.

        Returns:
            List of exposed asset dicts
        """
        all_assets = self.memory.asset_memory
        exposed = []

        for asset_id, asset_mem in all_assets.items():
            if asset_mem.is_currently_exposed:
                exposed.append({
                    "asset_id": asset_id,
                    "asset_name": asset_mem.asset_name,
                    "exposure_count": asset_mem.exposure_count,
                    "exposure_duration_days": asset_mem.current_exposure_duration_days,
                    "last_exposure": asset_mem.last_exposure,
                })

        return sorted(exposed, key=lambda x: x["last_exposure"], reverse=True)

    def find_common_infrastructure(
        self,
        actor_ids: List[str],
    ) -> Dict[str, Any]:
        """Find infrastructure shared between multiple actors.

        Args:
            actor_ids: List of threat actor IDs

        Returns:
            Dict with shared_iocs, shared_campaigns, commonality_score
        """
        if not actor_ids:
            return {
                "actor_ids": [],
                "shared_iocs": [],
                "shared_campaigns": [],
                "commonality_score": 0.0,
            }

        # Get campaigns for each actor
        actor_campaigns = {}
        for actor_id in actor_ids:
            result = self.find_actor_campaigns(actor_id)
            actor_campaigns[actor_id] = set(result["campaign_ids"])

        # Find common campaigns
        if len(actor_campaigns) == 1:
            common_campaigns = list(actor_campaigns[actor_ids[0]])
        else:
            common_campaigns = list(
                set.intersection(*actor_campaigns.values())
            )

        # Find IOCs in common campaigns
        common_iocs = set()
        all_iocs = self.memory.ioc_memory
        for ioc_id, ioc_mem in all_iocs.items():
            for campaign_id in common_campaigns:
                if campaign_id in ioc_mem.associated_campaigns:
                    common_iocs.add(ioc_id)

        commonality = (
            len(common_campaigns) / max(sum(len(c) for c in actor_campaigns.values()), 1)
            if actor_campaigns
            else 0.0
        )

        return {
            "actor_ids": actor_ids,
            "shared_campaigns": common_campaigns,
            "shared_iocs": list(common_iocs),
            "commonality_score": min(commonality, 1.0),
        }

    def query_iocs_by_criteria(
        self,
        min_occurrence_count: int = 1,
        activity_trend: Optional[str] = None,
        min_likelihood: float = 0.0,
    ) -> List[Dict[str, Any]]:
        """Query IOCs by pattern criteria.

        Args:
            min_occurrence_count: Minimum number of occurrences
            activity_trend: Filter by trend (rising/stable/declining)
            min_likelihood: Minimum reuse likelihood

        Returns:
            List of matching IOCs with their patterns
        """
        results = []
        all_iocs = self.memory.ioc_memory

        for ioc_id, ioc_mem in all_iocs.items():
            if ioc_mem.occurrence_count < min_occurrence_count:
                continue

            if activity_trend and ioc_mem.activity_trend != activity_trend:
                continue

            if ioc_mem.next_reuse_likelihood < min_likelihood:
                continue

            pattern = self.patterns.detect_ioc_reusage_pattern(ioc_id)

            results.append({
                "ioc_id": ioc_id,
                "ioc_value": ioc_mem.ioc_value,
                "occurrence_count": ioc_mem.occurrence_count,
                "activity_trend": ioc_mem.activity_trend,
                "next_reuse_likelihood": ioc_mem.next_reuse_likelihood,
                "reuse_frequency": pattern.reuse_frequency if pattern else 0.0,
            })

        return sorted(results, key=lambda x: x["next_reuse_likelihood"], reverse=True)

    def export_graph_snapshot(self) -> Dict[str, Any]:
        """Export current threat graph snapshot.

        Returns:
            Dict with nodes (entities) and edges (relationships)
        """
        nodes = {
            "iocs": [],
            "campaigns": [],
            "assets": [],
            "actors": [],
        }

        edges = {
            "ioc_campaign": [],
            "campaign_actor": [],
            "campaign_asset": [],
            "ioc_asset": [],
        }

        # Collect nodes
        for ioc_id in self.memory.ioc_memory:
            nodes["iocs"].append(ioc_id)

        for campaign_id in self.memory.campaign_memory:
            nodes["campaigns"].append(campaign_id)

        for asset_id in self.memory.asset_memory:
            nodes["assets"].append(asset_id)

        # Collect unique actors
        actors = set()
        for camp_mem in self.memory.campaign_memory.values():
            actors.update(camp_mem.attributed_actors)
        nodes["actors"] = list(actors)

        # Collect edges
        for ioc_id, ioc_mem in self.memory.ioc_memory.items():
            for campaign_id in ioc_mem.associated_campaigns:
                edges["ioc_campaign"].append((ioc_id, campaign_id))

        for campaign_id, camp_mem in self.memory.campaign_memory.items():
            for actor_id in camp_mem.attributed_actors:
                edges["campaign_actor"].append((campaign_id, actor_id))
            for asset_id in camp_mem.current_targets:
                edges["campaign_asset"].append((campaign_id, asset_id))

        for asset_id, asset_mem in self.memory.asset_memory.items():
            for ioc_id in [e.ioc_id for e in asset_mem.exposures if e.ioc_id]:
                edges["ioc_asset"].append((ioc_id, asset_id))

        return {
            "nodes": nodes,
            "edges": edges,
            "node_counts": {k: len(v) for k, v in nodes.items()},
            "edge_counts": {k: len(v) for k, v in edges.items()},
            "total_nodes": sum(len(v) for v in nodes.values()),
            "total_edges": sum(len(v) for v in edges.values()),
        }
