"""
core/decision_support.py - Decision Support System

Strategic decision support for threat response:
- Risk-based prioritization of threats
- Mitigation strategy recommendations
- Threat hunting guidance and priorities
- Resource allocation recommendations
- Defensive capability recommendations
- Timeline-based action plans
"""

from typing import Dict, List, Set, Optional, Any, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import math

from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine
from core.community_detection import CommunityDetectionEngine
from core.actor_profiling import ActorProfilingEngine
from core.trend_analysis import TrendAnalyzer
from core.anomaly_detection import AnomalyDetector
from core.threat_intelligence_reasoner import ThreatIntelligenceReasoner


class PrioritizedThreat:
    """Threat with priority scoring."""

    def __init__(self, threat_id: str, threat_type: str):
        """Initialize prioritized threat.

        Args:
            threat_id: Unique threat identifier
            threat_type: Type (campaign, actor, ioc)
        """
        self.threat_id = threat_id
        self.threat_type = threat_type
        self.priority_score = 0.0
        self.risk_level = "unknown"
        self.urgency = "low"
        self.impact_potential = 0.0
        self.likelihood = 0.0
        self.affected_assets = []
        self.recommended_actions = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "threat_id": self.threat_id,
            "threat_type": self.threat_type,
            "priority_score": self.priority_score,
            "risk_level": self.risk_level,
            "urgency": self.urgency,
            "impact_potential": self.impact_potential,
            "likelihood": self.likelihood,
            "affected_assets": self.affected_assets,
            "recommended_actions": self.recommended_actions,
        }


class MitigationStrategy:
    """Recommended mitigation strategy."""

    def __init__(self, strategy_id: str, threat_id: str):
        """Initialize mitigation strategy.

        Args:
            strategy_id: Unique strategy identifier
            threat_id: Target threat ID
        """
        self.strategy_id = strategy_id
        self.threat_id = threat_id
        self.title = ""
        self.description = ""
        self.short_term_actions = []
        self.long_term_actions = []
        self.required_resources = []
        self.estimated_effort = "medium"
        self.effectiveness_score = 0.0
        self.implementation_timeline_days = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "strategy_id": self.strategy_id,
            "threat_id": self.threat_id,
            "title": self.title,
            "description": self.description,
            "short_term_actions": self.short_term_actions,
            "long_term_actions": self.long_term_actions,
            "required_resources": self.required_resources,
            "estimated_effort": self.estimated_effort,
            "effectiveness_score": self.effectiveness_score,
            "implementation_timeline_days": self.implementation_timeline_days,
        }


class DecisionSupportSystem:
    """Strategic decision support system."""

    def __init__(
        self,
        memory_engine: ThreatMemoryEngine,
        pattern_engine: PatternDetectionEngine,
        context_engine: HistoricalContextEngine,
        community_engine: CommunityDetectionEngine,
        profiling_engine: ActorProfilingEngine,
        trend_analyzer: TrendAnalyzer,
        anomaly_detector: AnomalyDetector,
        reasoner: ThreatIntelligenceReasoner,
    ):
        """Initialize decision support system.

        Args:
            memory_engine: Threat memory engine
            pattern_engine: Pattern detection engine
            context_engine: Historical context engine
            community_engine: Community detection engine
            profiling_engine: Actor profiling engine
            trend_analyzer: Trend analysis engine
            anomaly_detector: Anomaly detection engine
            reasoner: Threat intelligence reasoner
        """
        self.memory = memory_engine
        self.patterns = pattern_engine
        self.context = context_engine
        self.communities = community_engine
        self.profiling = profiling_engine
        self.trends = trend_analyzer
        self.anomalies = anomaly_detector
        self.reasoner = reasoner

    def prioritize_threats(self, limit: int = 10) -> List[PrioritizedThreat]:
        """Prioritize threats by risk, urgency, and impact.

        Args:
            limit: Maximum threats to return

        Returns:
            List of prioritized threats
        """
        threats = []

        # Score campaigns
        for campaign_id, camp_mem in self.memory.campaign_memory.items():
            threat = PrioritizedThreat(campaign_id, "campaign")

            # Risk factors
            activity_risk = min(camp_mem.activity_count / 20.0, 1.0)
            active_risk = 1.0 if camp_mem.is_active else 0.3
            target_risk = min(len(camp_mem.current_targets) / 5.0, 1.0)

            threat.impact_potential = (activity_risk * 0.3 + target_risk * 0.4 + active_risk * 0.3)

            # Likelihood
            recent_activity = sum(
                1 for a in camp_mem.activities
                if a.date > datetime.utcnow() - timedelta(days=30)
            )
            threat.likelihood = min(recent_activity / 5.0, 1.0)

            # Priority score
            threat.priority_score = (threat.impact_potential * 0.6 + threat.likelihood * 0.4)

            # Urgency
            if threat.priority_score > 0.8:
                threat.urgency = "critical"
                threat.risk_level = "critical"
            elif threat.priority_score > 0.6:
                threat.urgency = "high"
                threat.risk_level = "high"
            elif threat.priority_score > 0.4:
                threat.urgency = "medium"
                threat.risk_level = "medium"
            else:
                threat.urgency = "low"
                threat.risk_level = "low"

            threat.affected_assets = camp_mem.current_targets

            threats.append(threat)

        # Score actors
        actor_rankings = self.profiling.rank_actors_by_threat()
        for actor_rank in actor_rankings:
            threat = PrioritizedThreat(actor_rank["actor_id"], "actor")

            threat.impact_potential = actor_rank["threat_score"]
            threat.likelihood = 0.7 if actor_rank["is_active"] else 0.3
            threat.priority_score = (threat.impact_potential * 0.6 + threat.likelihood * 0.4)

            if threat.priority_score > 0.8:
                threat.urgency = "critical"
                threat.risk_level = "critical"
            elif threat.priority_score > 0.6:
                threat.urgency = "high"
                threat.risk_level = "high"
            elif threat.priority_score > 0.4:
                threat.urgency = "medium"
                threat.risk_level = "medium"
            else:
                threat.urgency = "low"
                threat.risk_level = "low"

            threats.append(threat)

        # Sort by priority and return top N
        threats.sort(key=lambda x: x.priority_score, reverse=True)
        return threats[:limit]

    def generate_mitigation_strategies(self, threat_id: str, threat_type: str) -> List[MitigationStrategy]:
        """Generate mitigation strategies for threat.

        Args:
            threat_id: Threat identifier
            threat_type: Type of threat

        Returns:
            List of mitigation strategies
        """
        strategies = []

        if threat_type == "campaign":
            camp_mem = self.memory.get_campaign_memory(threat_id)
            if not camp_mem:
                return strategies

            # Strategy 1: IOC Blocking
            strategy1 = MitigationStrategy(f"{threat_id}-block-iocs", threat_id)
            strategy1.title = "IOC Blocking & Network Defense"
            strategy1.description = "Block all known IOCs associated with this campaign"
            strategy1.short_term_actions = [
                "Extract all IOCs from campaign memory",
                "Block IPs/domains at network edge",
                "Implement DNS sinkhole",
                "Update intrusion detection rules",
            ]
            strategy1.long_term_actions = [
                "Monitor for IOC reuse",
                "Track infrastructure evolution",
                "Implement threat intelligence feed",
            ]
            strategy1.required_resources = ["Firewall admin", "IDS/IPS engineer", "TI analyst"]
            strategy1.estimated_effort = "low"
            strategy1.effectiveness_score = 0.8
            strategy1.implementation_timeline_days = 1
            strategies.append(strategy1)

            # Strategy 2: Threat Hunting
            strategy2 = MitigationStrategy(f"{threat_id}-hunt", threat_id)
            strategy2.title = "Proactive Threat Hunting"
            strategy2.description = "Hunt for campaign indicators in enterprise infrastructure"
            strategy2.short_term_actions = [
                f"Hunt for {len(camp_mem.techniques_evolution)} known techniques",
                "Search logs for indicators of compromise",
                "Check for lateral movement patterns",
                "Review network flow data",
            ]
            strategy2.long_term_actions = [
                "Establish continuous hunting program",
                "Build behavioral baselines",
                "Implement behavioral analytics",
            ]
            strategy2.required_resources = ["Threat hunters", "SOC analysts", "Forensics team"]
            strategy2.estimated_effort = "medium"
            strategy2.effectiveness_score = 0.75
            strategy2.implementation_timeline_days = 3
            strategies.append(strategy2)

            # Strategy 3: Defensive Hardening
            strategy3 = MitigationStrategy(f"{threat_id}-harden", threat_id)
            strategy3.title = "Defensive Capability Enhancement"
            strategy3.description = "Harden systems against campaign techniques"
            strategy3.short_term_actions = [
                "Disable/restrict campaign techniques",
                "Implement EDR on critical systems",
                "Enable MFA for sensitive accounts",
                "Update security patches",
            ]
            strategy3.long_term_actions = [
                "Architecture security review",
                "Zero-trust implementation",
                "Continuous vulnerability management",
            ]
            strategy3.required_resources = ["Infrastructure team", "Security architects", "Patch management"]
            strategy3.estimated_effort = "high"
            strategy3.effectiveness_score = 0.85
            strategy3.implementation_timeline_days = 14
            strategies.append(strategy3)

        elif threat_type == "actor":
            profile = self.profiling.profile_actor(threat_id)

            # Strategy 1: Campaign Monitoring
            strategy1 = MitigationStrategy(f"{threat_id}-monitor", threat_id)
            strategy1.title = "Campaign Monitoring & Early Warning"
            strategy1.description = f"Monitor {profile.total_campaigns} known campaigns for resumption"
            strategy1.short_term_actions = [
                "Establish baseline for actor behavior",
                "Monitor dormant campaigns for reactivation",
                "Track infrastructure reuse",
                "Monitor dark web for planning signals",
            ]
            strategy1.long_term_actions = [
                "Establish 24/7 monitoring program",
                "Implement behavioral deviation alerting",
            ]
            strategy1.required_resources = ["SOC analysts", "TI analysts"]
            strategy1.estimated_effort = "medium"
            strategy1.effectiveness_score = 0.7
            strategy1.implementation_timeline_days = 2
            strategies.append(strategy1)

            # Strategy 2: Victim Community Collaboration
            strategy2 = MitigationStrategy(f"{threat_id}-collab", threat_id)
            strategy2.title = "Victim Community Collaboration"
            strategy2.description = "Share intelligence with other targeted organizations"
            strategy2.short_term_actions = [
                f"Share {len(profile.target_sectors)} target sectors insights",
                "Coordinate defense strategies",
                "Share defensive measures",
            ]
            strategy2.long_term_actions = [
                "Establish industry information sharing",
                "Participate in threat intelligence community",
            ]
            strategy2.required_resources = ["TI team", "Legal/compliance"]
            strategy2.estimated_effort = "low"
            strategy2.effectiveness_score = 0.65
            strategy2.implementation_timeline_days = 1
            strategies.append(strategy2)

        return strategies

    def get_hunting_priorities(self, max_count: int = 5) -> List[Dict[str, Any]]:
        """Get threat hunting priorities.

        Args:
            max_count: Maximum hunting priorities

        Returns:
            List of hunting priorities with guidance
        """
        priorities = []

        # Get emerging techniques
        technique_trends = self.trends.analyze_technique_adoption_trends(days_window=90)
        emerging_techniques = [t for t in technique_trends if t["trend"] == "emerging"]

        for tech in emerging_techniques[:max_count]:
            priorities.append({
                "hunt_type": "technique",
                "indicator": tech["technique"],
                "priority": "high",
                "guidance": f"Hunt for {tech['technique']} - newly adopted by {tech['total_usage']} actors",
                "search_locations": ["endpoint logs", "network IDS", "DNS records"],
                "expected_signals": ["process creation", "network connection", "DNS query"],
            })

        # Get rising IOCs
        ioc_trends = self.trends.analyze_ioc_trends(days_window=90)
        rising_iocs = [t for t in ioc_trends if t["trend"] == "rising"]

        for ioc in rising_iocs[:max_count]:
            priorities.append({
                "hunt_type": "ioc",
                "indicator": ioc["ioc_value"],
                "priority": "critical",
                "guidance": f"Hunt for {ioc['ioc_value']} - rising activity ({ioc['activity_change_percent']:.0f}%)",
                "search_locations": ["proxy logs", "firewall logs", "DNS records"],
                "expected_signals": ["connection attempt", "DNS resolution", "network flow"],
            })

        return priorities[:max_count]

    def get_resource_allocation(self) -> Dict[str, Any]:
        """Get resource allocation recommendations.

        Returns:
            Dict with resource allocation guidance
        """
        allocation = {
            "monitoring": {"hours_per_week": 0, "priority": "low", "rationale": ""},
            "hunting": {"hours_per_week": 0, "priority": "low", "rationale": ""},
            "hardening": {"hours_per_week": 0, "priority": "low", "rationale": ""},
            "detection": {"hours_per_week": 0, "priority": "low", "rationale": ""},
            "analysis": {"hours_per_week": 0, "priority": "low", "rationale": ""},
        }

        # Assess threat level
        threat_assessment = self.reasoner.assess_threat_level()

        if threat_assessment.threat_level == "critical":
            allocation["monitoring"]["hours_per_week"] = 168  # Full-time
            allocation["monitoring"]["priority"] = "critical"
            allocation["hunting"]["hours_per_week"] = 120
            allocation["hunting"]["priority"] = "critical"
            allocation["hardening"]["hours_per_week"] = 80
            allocation["hardening"]["priority"] = "high"
        elif threat_assessment.threat_level == "high":
            allocation["monitoring"]["hours_per_week"] = 80
            allocation["monitoring"]["priority"] = "high"
            allocation["hunting"]["hours_per_week"] = 60
            allocation["hunting"]["priority"] = "high"
            allocation["hardening"]["hours_per_week"] = 40
            allocation["hardening"]["priority"] = "medium"
        elif threat_assessment.threat_level == "medium":
            allocation["monitoring"]["hours_per_week"] = 40
            allocation["monitoring"]["priority"] = "medium"
            allocation["hunting"]["hours_per_week"] = 30
            allocation["hunting"]["priority"] = "medium"
            allocation["hardening"]["hours_per_week"] = 20
            allocation["hardening"]["priority"] = "medium"
        else:
            allocation["monitoring"]["hours_per_week"] = 10
            allocation["monitoring"]["priority"] = "low"
            allocation["hunting"]["hours_per_week"] = 5
            allocation["hunting"]["priority"] = "low"
            allocation["hardening"]["hours_per_week"] = 5
            allocation["hardening"]["priority"] = "low"

        # Add rationale
        allocation["monitoring"]["rationale"] = "Continuous threat monitoring based on active campaigns"
        allocation["hunting"]["rationale"] = "Proactive hunting for emerging indicators"
        allocation["hardening"]["rationale"] = "Defensive capability improvement"

        return allocation

    def get_action_timeline(self, days: int = 30) -> List[Dict[str, Any]]:
        """Generate action timeline for next N days.

        Args:
            days: Number of days to plan

        Returns:
            List of actions with timeline
        """
        timeline = []

        # Immediate actions (0-24 hours)
        timeline.append({
            "phase": "Immediate (0-24 hours)",
            "actions": [
                "Activate incident response team",
                "Block known IOCs",
                "Implement real-time alerting",
                "Begin threat hunting operations",
            ],
        })

        # Short-term (1-7 days)
        timeline.append({
            "phase": "Short-term (1-7 days)",
            "actions": [
                "Complete initial threat hunting",
                "Identify compromised systems",
                "Implement detection rules",
                "Begin remediation of affected systems",
            ],
        })

        # Medium-term (1-4 weeks)
        timeline.append({
            "phase": "Medium-term (1-4 weeks)",
            "actions": [
                "Complete system hardening",
                "Deploy advanced detection capabilities",
                "Conduct security awareness training",
                "Update incident response procedures",
            ],
        })

        # Long-term (1-3 months)
        timeline.append({
            "phase": "Long-term (1-3 months)",
            "actions": [
                "Implement zero-trust architecture",
                "Deploy behavioral analytics",
                "Establish threat intelligence program",
                "Continuous monitoring and optimization",
            ],
        })

        return timeline

    def get_decision_summary(self) -> Dict[str, Any]:
        """Get comprehensive decision support summary.

        Returns:
            Dict with all decision support outputs
        """
        return {
            "timestamp": datetime.utcnow(),
            "prioritized_threats": [t.to_dict() for t in self.prioritize_threats(limit=5)],
            "hunting_priorities": self.get_hunting_priorities(max_count=3),
            "resource_allocation": self.get_resource_allocation(),
            "action_timeline": self.get_action_timeline(days=30),
            "summary": self._generate_decision_summary(),
        }

    def _generate_decision_summary(self) -> str:
        """Generate natural language decision summary.

        Returns:
            Human-readable summary
        """
        threats = self.prioritize_threats(limit=3)
        allocation = self.get_resource_allocation()

        summary = (
            f"DECISION SUPPORT SUMMARY\n"
            f"Generated: {datetime.utcnow().isoformat()}\n\n"
            f"TOP PRIORITIES\n"
        )

        for i, threat in enumerate(threats, 1):
            summary += f"{i}. {threat.threat_type.upper()}: {threat.threat_id}\n"
            summary += f"   Risk Level: {threat.risk_level}\n"
            summary += f"   Priority Score: {threat.priority_score:.2f}\n"

        summary += f"\nRECOMMENDED RESOURCE ALLOCATION\n"
        for resource, details in allocation.items():
            if details["priority"] != "low":
                summary += f"- {resource.replace('_', ' ').title()}: {details['hours_per_week']} hrs/week ({details['priority'].upper()})\n"

        return summary
