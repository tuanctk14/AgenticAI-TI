"""
core/agent_memory_bridge.py - Bridge between threat memory system and LangGraph agents

Provides memory-aware threat reasoning through:
- Persistent threat memory access for agents
- Pattern-based correlation and prediction
- Historical context enrichment
- Memory-augmented threat intelligence
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine


class MemoryAwareThreatsAgent:
    """Agent that reasons about threats using persistent memory and patterns."""

    def __init__(
        self,
        memory_engine: ThreatMemoryEngine,
        pattern_engine: PatternDetectionEngine,
        context_engine: HistoricalContextEngine,
    ):
        """Initialize memory-aware threat agent.

        Args:
            memory_engine: Threat memory engine with 5 memory types
            pattern_engine: Pattern detection engine for trend analysis
            context_engine: Historical context engine for actor profiling
        """
        self.memory = memory_engine
        self.patterns = pattern_engine
        self.context = context_engine

    def correlate_ioc_with_history(self, ioc_id: str) -> Dict[str, Any]:
        """Correlate IOC with historical memory and patterns.

        Returns:
            Dict with:
            - ioc_id, ioc_value
            - recurring_status (recurring/new)
            - occurrence_count
            - activity_trend (rising/stable/declining)
            - next_reuse_likelihood (0.0-1.0)
            - associated_campaigns
            - associated_actors
            - risk_level
        """
        ioc_memory = self.memory.get_ioc_memory(ioc_id)
        if not ioc_memory:
            return {"status": "unknown", "ioc_id": ioc_id}

        pattern = self.patterns.detect_ioc_reusage_pattern(ioc_id)
        timeline = self.context.build_threat_timeline(ioc_id)
        risk = self.context.build_risk_context(ioc_id)

        return {
            "ioc_id": ioc_id,
            "ioc_value": ioc_memory.ioc_value,
            "recurring_status": "recurring" if ioc_memory.occurrence_count > 1 else "new",
            "occurrence_count": ioc_memory.occurrence_count,
            "last_observed": ioc_memory.last_observed,
            "activity_trend": pattern.activity_trend if pattern else "unknown",
            "reuse_frequency": pattern.reuse_frequency if pattern else 0.0,
            "next_reuse_likelihood": pattern.next_reuse_likelihood if pattern else 0.0,
            "dormancy_periods": timeline.dormancy_periods if timeline else [],
            "predictability_score": timeline.predictability_score if timeline else 0.0,
            "associated_campaigns": ioc_memory.associated_campaigns,
            "associated_actors": ioc_memory.associated_actors,
            "associated_malware": ioc_memory.associated_malware,
            "historical_risk_score": risk.historical_risk_score if risk else 0.0,
            "contextual_severity": risk.contextual_severity if risk else "unknown",
            "threat_actor_count": risk.threat_actor_count if risk else 0,
        }

    def correlate_campaign_with_history(self, campaign_id: str) -> Dict[str, Any]:
        """Correlate campaign with historical memory and patterns.

        Returns:
            Dict with:
            - campaign_id, campaign_name
            - activity_count, last_observed
            - is_active
            - activity_frequency_per_month
            - activity_pattern (continuous/intermittent/seasonal)
            - peak_periods
            - next_activity_likelihood
            - attributed_actors
            - techniques_evolution
            - current_targets
            - evolution_trajectory
            - risk_level
        """
        camp_memory = self.memory.get_campaign_memory(campaign_id)
        if not camp_memory:
            return {"status": "unknown", "campaign_id": campaign_id}

        pattern = self.patterns.detect_campaign_activity_pattern(campaign_id)
        actor_profile = self.context.build_actor_profile(campaign_id, campaign_id)
        timeline = self.context.build_threat_timeline(campaign_id)
        risk = self.context.build_risk_context(campaign_id)

        return {
            "campaign_id": campaign_id,
            "campaign_name": camp_memory.campaign_name,
            "activity_count": camp_memory.activity_count,
            "last_observed": camp_memory.last_observed,
            "is_active": camp_memory.is_active,
            "activity_frequency_per_month": pattern.activity_frequency if pattern else 0.0,
            "activity_pattern": pattern.activity_pattern if pattern else "unknown",
            "peak_periods": pattern.peak_periods if pattern else [],
            "next_activity_likelihood": pattern.next_activity_likelihood if pattern else 0.0,
            "attributed_actors": camp_memory.attributed_actors,
            "techniques_evolution": camp_memory.techniques_evolution,
            "current_targets": camp_memory.current_targets,
            "evolution_trajectory": actor_profile.evolution_trajectory if actor_profile else "unknown",
            "dormancy_periods": timeline.dormancy_periods if timeline else [],
            "predictability_score": timeline.predictability_score if timeline else 0.0,
            "historical_risk_score": risk.historical_risk_score if risk else 0.0,
            "contextual_severity": risk.contextual_severity if risk else "unknown",
        }

    def correlate_asset_with_history(self, asset_id: str) -> Dict[str, Any]:
        """Correlate asset exposure with historical memory and patterns.

        Returns:
            Dict with:
            - asset_id, asset_name
            - exposure_count
            - exposure_frequency_per_month
            - exposure_trend (rising/stable/declining)
            - high_risk_window
            - next_exposure_likelihood
            - last_exposure, is_currently_exposed
            - current_exposure_duration_days
            - remediation_success_rate
            - risk_level
        """
        asset_memory = self.memory.get_asset_memory(asset_id)
        if not asset_memory:
            return {"status": "unknown", "asset_id": asset_id}

        pattern = self.patterns.detect_asset_exposure_pattern(asset_id)
        timeline = self.context.build_threat_timeline(asset_id)
        risk = self.context.build_risk_context(asset_id)

        return {
            "asset_id": asset_id,
            "asset_name": asset_memory.asset_name,
            "exposure_count": asset_memory.exposure_count,
            "last_exposure": asset_memory.last_exposure,
            "exposure_frequency_per_month": pattern.exposure_frequency if pattern else 0.0,
            "exposure_trend": pattern.exposure_trend if pattern else "unknown",
            "high_risk_window": asset_memory.high_risk_window,
            "next_exposure_likelihood": pattern.next_exposure_likelihood if pattern else 0.0,
            "is_currently_exposed": asset_memory.is_currently_exposed,
            "current_exposure_duration_days": asset_memory.current_exposure_duration_days,
            "remediation_success_rate": asset_memory.remediation_success_rate,
            "dormancy_periods": timeline.dormancy_periods if timeline else [],
            "predictability_score": timeline.predictability_score if timeline else 0.0,
            "historical_risk_score": risk.historical_risk_score if risk else 0.0,
            "contextual_severity": risk.contextual_severity if risk else "unknown",
        }

    def find_related_threats(self, ioc_id: str) -> Dict[str, List[Any]]:
        """Find all threats related to an IOC through memory graph.

        Returns:
            Dict with:
            - related_campaigns: campaigns involving this IOC
            - related_actors: threat actors involved
            - related_malware: malware associated
        """
        ioc_memory = self.memory.get_ioc_memory(ioc_id)
        if not ioc_memory:
            return {"status": "unknown", "ioc_id": ioc_id}

        result = {
            "ioc_id": ioc_id,
            "related_campaigns": [],
            "related_actors": [],
            "related_malware": [],
        }

        # Related campaigns
        for campaign_id in ioc_memory.associated_campaigns:
            camp_corr = self.correlate_campaign_with_history(campaign_id)
            if camp_corr.get("campaign_id"):
                result["related_campaigns"].append(camp_corr)

        # Related actors
        for actor_id in ioc_memory.associated_actors:
            actor_memory = self.memory.get_threat_actor_memory(actor_id)
            if actor_memory:
                result["related_actors"].append({
                    "actor_id": actor_id,
                    "actor_name": actor_memory.actor_name if actor_memory else "Unknown",
                })

        # Related malware
        for malware_id in ioc_memory.associated_malware:
            result["related_malware"].append({
                "malware_id": malware_id,
                "associated_with_ioc": ioc_id,
            })

        return result

    def predict_next_threat_activity(self) -> Dict[str, Any]:
        """Predict next threat activity based on patterns and history.

        Returns:
            Dict with:
            - iocs_at_risk: IOCs likely to reappear soon
            - campaigns_resuming: Campaigns likely to resume
            - assets_exposed: Assets at exposure risk
            - predicted_timeline: Timeline of predicted activities
            - confidence_levels: Confidence scores for predictions
        """
        results = {
            "iocs_at_risk": [],
            "campaigns_resuming": [],
            "assets_exposed": [],
            "predicted_timeline": [],
        }

        # Get all high-risk entities from patterns
        high_risk = self.patterns.get_high_risk_entities(likelihood_threshold=0.6)

        # IOCs at risk
        for ioc_id in high_risk.get("iocs", []):
            pattern = self.patterns.detect_ioc_reusage_pattern(ioc_id)
            if pattern and pattern.predicted_next_use:
                results["iocs_at_risk"].append({
                    "ioc_id": ioc_id,
                    "likelihood": pattern.next_reuse_likelihood,
                    "predicted_date": pattern.predicted_next_use,
                    "trend": pattern.activity_trend,
                })

        # Campaigns resuming
        for campaign_id in high_risk.get("campaigns", []):
            pattern = self.patterns.detect_campaign_activity_pattern(campaign_id)
            if pattern and pattern.predicted_next_activity:
                results["campaigns_resuming"].append({
                    "campaign_id": campaign_id,
                    "likelihood": pattern.next_activity_likelihood,
                    "predicted_date": pattern.predicted_next_activity,
                    "activity_pattern": pattern.activity_pattern,
                })

        # Assets at exposure risk
        for asset_id in high_risk.get("assets", []):
            pattern = self.patterns.detect_asset_exposure_pattern(asset_id)
            if pattern and pattern.predicted_next_exposure:
                results["assets_exposed"].append({
                    "asset_id": asset_id,
                    "likelihood": pattern.next_exposure_likelihood,
                    "predicted_date": pattern.predicted_next_exposure,
                    "trend": pattern.exposure_trend,
                })

        # Sort by predicted date to create timeline
        all_predictions = []
        all_predictions.extend([
            {"type": "IOC", **p} for p in results["iocs_at_risk"]
        ])
        all_predictions.extend([
            {"type": "Campaign", **p} for p in results["campaigns_resuming"]
        ])
        all_predictions.extend([
            {"type": "Asset Exposure", **p} for p in results["assets_exposed"]
        ])

        all_predictions.sort(key=lambda x: x.get("predicted_date", datetime.utcnow()))
        results["predicted_timeline"] = all_predictions

        return results

    def get_memory_enrichment_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary of memory and patterns.

        Returns:
            Dict with:
            - memory_summary: Overall memory statistics
            - pattern_statistics: Pattern analysis results
            - anomalies: Detected anomalies
            - high_risk_entities: Entities requiring attention
        """
        memory_summary = self.memory.get_memory_summary()
        pattern_stats = self.patterns.get_pattern_statistics()
        anomalies = self.context.detect_historical_anomalies(stddev_threshold=2.0)
        high_risk = self.patterns.get_high_risk_entities(likelihood_threshold=0.7)

        return {
            "memory_summary": memory_summary,
            "pattern_statistics": pattern_stats,
            "anomalies": anomalies,
            "high_risk_entities": high_risk,
            "updated_at": datetime.utcnow().isoformat(),
        }


class MemoryAwareAgentState:
    """Manages agent state augmented with memory context."""

    def __init__(self, memory_agent: MemoryAwareThreatsAgent):
        """Initialize memory-aware state manager.

        Args:
            memory_agent: MemoryAwareThreatsAgent instance
        """
        self.agent = memory_agent
        self.state = {}

    def enrich_with_memory(self, entity_type: str, entity_id: str) -> Dict[str, Any]:
        """Enrich entity information with memory and pattern data.

        Args:
            entity_type: 'ioc', 'campaign', 'asset'
            entity_id: Entity identifier

        Returns:
            Enriched entity dict with memory and pattern data
        """
        if entity_type == "ioc":
            return self.agent.correlate_ioc_with_history(entity_id)
        elif entity_type == "campaign":
            return self.agent.correlate_campaign_with_history(entity_id)
        elif entity_type == "asset":
            return self.agent.correlate_asset_with_history(entity_id)
        else:
            return {"status": "unknown", "entity_type": entity_type}

    def enrich_state_with_memory(self, agent_state: Dict[str, Any]) -> Dict[str, Any]:
        """Augment agent state with memory enrichment.

        Adds memory context to existing agent state:
        - IOC correlations
        - Campaign correlations
        - Threat predictions
        - Risk assessments

        Args:
            agent_state: Current agent state dict

        Returns:
            Enhanced state with memory_context added
        """
        memory_context = {}

        # Enrich IOCs if present
        if "collected_indicators" in agent_state:
            memory_context["indicator_correlations"] = []
            for indicator in agent_state["collected_indicators"]:
                ioc_id = indicator.get("id", "")
                if ioc_id:
                    corr = self.agent.correlate_ioc_with_history(ioc_id)
                    related = self.agent.find_related_threats(ioc_id)
                    memory_context["indicator_correlations"].append({
                        "indicator": indicator,
                        "correlation": corr,
                        "related_threats": related,
                    })

        # Enrich CVEs if present
        if "collected_cves" in agent_state:
            memory_context["cve_enrichment"] = []
            for cve in agent_state["collected_cves"]:
                cve_id = cve.get("id", "")
                # Treat CVE as entity for memory correlation
                if cve_id:
                    risk = self.agent.context.build_risk_context(cve_id)
                    memory_context["cve_enrichment"].append({
                        "cve_id": cve_id,
                        "risk_context": risk.__dict__ if risk else {},
                    })

        # Add threat predictions
        memory_context["threat_predictions"] = self.agent.predict_next_threat_activity()

        # Add overall summary
        memory_context["enrichment_summary"] = self.agent.get_memory_enrichment_summary()

        agent_state["memory_context"] = memory_context
        return agent_state
