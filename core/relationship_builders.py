"""
core/relationship_builders.py - Relationship Intelligence Builders

Transforms threat intelligence entities into rich relationships.
Foundation for graph-native threat reasoning.

14 relationship builders:
1. CVEToMalwareBuilder - CVE → Malware
2. CVEToCampaignBuilder - CVE → Campaign
3. CVEToThreatActorBuilder - CVE → ThreatActor (inferred)
4. CVEToATTACKBuilder - CVE → ATT&CK
5. MalwareToCampaignBuilder - Malware → Campaign
6. ThreatActorToCampaignBuilder - ThreatActor → Campaign
7. ThreatActorToInfraBuilder - ThreatActor → Infrastructure
8. InfraToC2Builder - Infrastructure → C2
9. CampaignToVictimologyBuilder - Campaign → Victimology
10. CampaignToSectorBuilder - Campaign → Sector
11. AssetToAttackPathBuilder - Asset → AttackPath
12. AssetToReachabilityBuilder - Asset → Reachability
13. IOCToMalwareBuilder - IOC → Malware
14. IOCToCampaignBuilder - IOC → Campaign
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from datetime import datetime
from core.threat_schema import (
    Relationship, RelationshipType, RelationshipMetadata, EntityType,
    Vulnerability, IOC, Asset, Campaign, ThreatActor, Infrastructure
)


# ============================================================
# BASE RELATIONSHIP BUILDER
# ============================================================

class RelationshipBuilder(ABC):
    """
    Abstract base class cho tất cả relationship builders.

    Pattern: Builder tạo mối quan hệ từ entities.
    Trả về Relationship object với confidence + evidence.
    """

    @abstractmethod
    async def build(
        self,
        source_entity: Any,
        target_entity: Any,
    ) -> Optional[Relationship]:
        """
        Build relationship từ source → target entities.

        Returns:
            Relationship if confidence > threshold, else None
        """
        pass

    def create_relationship(
        self,
        source_id: str,
        source_type: EntityType,
        target_id: str,
        target_type: EntityType,
        rel_type: RelationshipType,
        confidence: float,
        evidence: List[str],
        reasoning: Optional[str] = None,
        source_provider: str = "builder",
        metadata: Optional[RelationshipMetadata] = None,
    ) -> Relationship:
        """
        Factory method để tạo Relationship object.

        Args:
            source_id: Source entity ID
            source_type: Source entity type
            target_id: Target entity ID
            target_type: Target entity type
            rel_type: Relationship type
            confidence: Confidence score (0.0-1.0)
            evidence: List of evidence sources
            reasoning: Optional reasoning explanation
            source_provider: Where relationship originated
            metadata: Optional rich metadata

        Returns:
            Relationship object
        """
        if metadata is None:
            metadata = RelationshipMetadata(
                confidence=confidence,
                evidence=evidence,
                first_observed=datetime.utcnow(),
                last_observed=datetime.utcnow(),
                active=True,
                source=source_provider,
                reasoning=reasoning
            )

        return Relationship(
            source_id=source_id,
            source_type=source_type,
            target_id=target_id,
            target_type=target_type,
            relationship_type=rel_type,
            confidence=confidence,
            strength="strong" if confidence >= 0.8 else "medium" if confidence >= 0.5 else "weak",
            evidence_sources=evidence,
            metadata=metadata,
            context={
                "builder": self.__class__.__name__,
                "created_at": datetime.utcnow().isoformat()
            }
        )


# ============================================================
# RELATIONSHIP BUILDERS (14 total)
# ============================================================

class CVEToMalwareBuilder(RelationshipBuilder):
    """Build CVE → Malware relationships from OpenCTI/correlation data."""

    async def build(
        self,
        cve: Vulnerability,
        malware: Dict[str, Any],
    ) -> Optional[Relationship]:
        """
        Build CVE → Malware relationship.

        Malware dict format:
        {
            "id": "malware-uuid",
            "name": "Poison Ivy",
            "exploits_cves": ["CVE-2024-1086"],
            "confidence": 0.8,
            "source": "opencti"
        }
        """
        if not malware or not cve:
            return None

        # Confidence from OpenCTI or correlation
        confidence = malware.get("confidence", 0.7)

        # Must have minimum confidence
        if confidence < 0.5:
            return None

        return self.create_relationship(
            source_id=cve.id,
            source_type=EntityType.VULNERABILITY,
            target_id=malware.get("id", malware.get("name")),
            target_type=EntityType.MALWARE,
            rel_type=RelationshipType.EXPLOITS,
            confidence=confidence,
            evidence=["malware_analysis", "opencti_source"],
            reasoning=f"Malware {malware.get('name')} exploits {cve.id}",
            source_provider="opencti"
        )


class CVEToCampaignBuilder(RelationshipBuilder):
    """Build CVE → Campaign relationships from OpenCTI/correlation data."""

    async def build(
        self,
        cve: Vulnerability,
        campaign: Campaign,
    ) -> Optional[Relationship]:
        """Build CVE → Campaign relationship."""
        if not campaign or not cve:
            return None

        # Check if campaign actually exploits this CVE
        confidence = 0.8 if cve.id in getattr(campaign, "techniques", []) else 0.6

        if confidence < 0.5:
            return None

        return self.create_relationship(
            source_id=cve.id,
            source_type=EntityType.VULNERABILITY,
            target_id=campaign.id,
            target_type=EntityType.CAMPAIGN,
            rel_type=RelationshipType.OBSERVED_IN,
            confidence=confidence,
            evidence=["campaign_link", "temporal_correlation"],
            reasoning=f"Campaign {campaign.name} exploits {cve.id}",
            source_provider="opencti"
        )


class CVEToThreatActorBuilder(RelationshipBuilder):
    """Infer CVE → ThreatActor relationships via campaigns."""

    async def build(
        self,
        cve: Vulnerability,
        threat_actor: ThreatActor,
    ) -> Optional[Relationship]:
        """
        Build CVE → ThreatActor relationship (inferred).

        Inferred through: CVE → Campaign → ThreatActor
        """
        if not threat_actor or not cve:
            return None

        # Inferred relationships have lower confidence
        confidence = 0.6

        return self.create_relationship(
            source_id=cve.id,
            source_type=EntityType.VULNERABILITY,
            target_id=threat_actor.id,
            target_type=EntityType.THREAT_ACTOR,
            rel_type=RelationshipType.EXPLOITS,
            confidence=confidence,
            evidence=["graph_inference", "temporal_correlation"],
            reasoning=f"ThreatActor {threat_actor.name} exploits {cve.id} via campaigns",
            source_provider="correlator"
        )


class CVEToATTACKBuilder(RelationshipBuilder):
    """Build CVE → ATT&CK relationships from CWE mappings."""

    async def build(
        self,
        cve: Vulnerability,
        attack_technique: Dict[str, Any],
    ) -> Optional[Relationship]:
        """
        Build CVE → ATT&CK relationship.

        Attack technique dict:
        {
            "id": "T1234",
            "name": "Exploit for Privilege Escalation",
            "confidence": 0.85
        }
        """
        if not attack_technique or not cve:
            return None

        confidence = attack_technique.get("confidence", 0.7)

        if confidence < 0.5:
            return None

        return self.create_relationship(
            source_id=cve.id,
            source_type=EntityType.VULNERABILITY,
            target_id=attack_technique.get("id"),
            target_type=EntityType.ATTACK_PATTERN,
            rel_type=RelationshipType.MAPPED_TO,
            confidence=confidence,
            evidence=["cwe_mapping", "mitre_analysis"],
            reasoning=f"CVE {cve.id} maps to ATT&CK {attack_technique.get('name')}",
            source_provider="enrichment_pipeline"
        )


class MalwareToCampaignBuilder(RelationshipBuilder):
    """Build Malware → Campaign relationships from OpenCTI."""

    async def build(
        self,
        malware: Dict[str, Any],
        campaign: Campaign,
    ) -> Optional[Relationship]:
        """Build Malware → Campaign relationship."""
        if not malware or not campaign:
            return None

        # Check if campaign uses this malware
        if malware.get("id") not in campaign.malware:
            return None

        confidence = 0.85

        return self.create_relationship(
            source_id=campaign.id,
            source_type=EntityType.CAMPAIGN,
            target_id=malware.get("id"),
            target_type=EntityType.MALWARE,
            rel_type=RelationshipType.USES_MALWARE,
            confidence=confidence,
            evidence=["opencti_source", "campaign_analysis"],
            reasoning=f"Campaign {campaign.name} uses malware {malware.get('name')}",
            source_provider="opencti"
        )


class ThreatActorToCampaignBuilder(RelationshipBuilder):
    """Build ThreatActor → Campaign relationships from OpenCTI."""

    async def build(
        self,
        threat_actor: ThreatActor,
        campaign: Campaign,
    ) -> Optional[Relationship]:
        """Build ThreatActor → Campaign relationship."""
        if not threat_actor or not campaign:
            return None

        # Check if threat actor leads this campaign
        if campaign.id not in threat_actor.campaigns:
            return None

        confidence = 0.9

        return self.create_relationship(
            source_id=threat_actor.id,
            source_type=EntityType.THREAT_ACTOR,
            target_id=campaign.id,
            target_type=EntityType.CAMPAIGN,
            rel_type=RelationshipType.LEADS_CAMPAIGN,
            confidence=confidence,
            evidence=["opencti_source", "attribution_data"],
            reasoning=f"ThreatActor {threat_actor.name} leads campaign {campaign.name}",
            source_provider="opencti"
        )


class ThreatActorToInfraBuilder(RelationshipBuilder):
    """Build ThreatActor → Infrastructure relationships."""

    async def build(
        self,
        threat_actor: ThreatActor,
        infrastructure: Infrastructure,
    ) -> Optional[Relationship]:
        """Build ThreatActor → Infrastructure relationship."""
        if not threat_actor or not infrastructure:
            return None

        # Check if threat actor operates this infrastructure
        if infrastructure.id not in threat_actor.infrastructure:
            return None

        confidence = 0.85

        return self.create_relationship(
            source_id=threat_actor.id,
            source_type=EntityType.THREAT_ACTOR,
            target_id=infrastructure.id,
            target_type=EntityType.INFRASTRUCTURE,
            rel_type=RelationshipType.OPERATES_INFRASTRUCTURE,
            confidence=confidence,
            evidence=["infrastructure_control", "whois_analysis"],
            reasoning=f"ThreatActor {threat_actor.name} operates infrastructure {infrastructure.value}",
            source_provider="opencti"
        )


class InfraToC2Builder(RelationshipBuilder):
    """Build Infrastructure → C2 relationships."""

    async def build(
        self,
        infrastructure: Infrastructure,
        c2_infrastructure: Infrastructure,
    ) -> Optional[Relationship]:
        """Build Infrastructure → C2 relationship (connection)."""
        if not infrastructure or not c2_infrastructure:
            return None

        # Check if connected
        if c2_infrastructure.id not in infrastructure.c2_connections:
            return None

        confidence = 0.75

        return self.create_relationship(
            source_id=infrastructure.id,
            source_type=EntityType.INFRASTRUCTURE,
            target_id=c2_infrastructure.id,
            target_type=EntityType.INFRASTRUCTURE,
            rel_type=RelationshipType.COMMUNICATES_WITH,
            confidence=confidence,
            evidence=["network_traffic", "dns_analysis"],
            reasoning=f"Infrastructure {infrastructure.value} communicates with C2 {c2_infrastructure.value}",
            source_provider="enrichment_pipeline"
        )


class CampaignToVictimologyBuilder(RelationshipBuilder):
    """Build Campaign → Victimology relationships."""

    async def build(
        self,
        campaign: Campaign,
        victim_type: str,  # "Government", "Financial", etc
    ) -> Optional[Relationship]:
        """Build Campaign → Victimology relationship."""
        if not campaign or not victim_type:
            return None

        # Check if campaign targets this victim type
        if victim_type not in campaign.victimology:
            return None

        confidence = 0.85

        return self.create_relationship(
            source_id=campaign.id,
            source_type=EntityType.CAMPAIGN,
            target_id=victim_type,  # Simple string ID
            target_type=EntityType.CAMPAIGN,  # Victim type (simplified)
            rel_type=RelationshipType.TARGETS_VICTIMOLOGY,
            confidence=confidence,
            evidence=["victimology_analysis", "campaign_targeting"],
            reasoning=f"Campaign {campaign.name} targets {victim_type} victimology",
            source_provider="enrichment_pipeline"
        )


class CampaignToSectorBuilder(RelationshipBuilder):
    """Build Campaign → Sector relationships."""

    async def build(
        self,
        campaign: Campaign,
        sector: str,  # "Government", "Finance", etc
    ) -> Optional[Relationship]:
        """Build Campaign → Sector relationship."""
        if not campaign or not sector:
            return None

        # Check if campaign targets this sector
        if sector not in campaign.sectors:
            return None

        confidence = 0.85

        return self.create_relationship(
            source_id=campaign.id,
            source_type=EntityType.CAMPAIGN,
            target_id=sector,  # Simple string ID
            target_type=EntityType.CAMPAIGN,  # Sector (simplified)
            rel_type=RelationshipType.TARGETS_SECTOR,
            confidence=confidence,
            evidence=["sectoral_pattern", "campaign_targeting"],
            reasoning=f"Campaign {campaign.name} targets {sector} sector",
            source_provider="enrichment_pipeline"
        )


class AssetToAttackPathBuilder(RelationshipBuilder):
    """Build Asset → AttackPath relationships from graph analysis."""

    async def build(
        self,
        asset: Asset,
        attack_path_data: Dict[str, Any],
    ) -> Optional[Relationship]:
        """
        Build Asset → AttackPath relationship.

        Attack path data:
        {
            "path_id": "path-1",
            "length": 3,
            "risk": 0.95
        }
        """
        if not asset or not attack_path_data:
            return None

        confidence = attack_path_data.get("risk", 0.7)

        if confidence < 0.5:
            return None

        return self.create_relationship(
            source_id=asset.id,
            source_type=EntityType.ASSET,
            target_id=attack_path_data.get("path_id", "attack-path"),
            target_type=EntityType.VULNERABILITY,  # Simplified
            rel_type=RelationshipType.VULNERABLE_TO,
            confidence=confidence,
            evidence=["graph_analysis", "attack_simulation"],
            reasoning=f"Asset {asset.hostname} has attack path (length: {attack_path_data.get('length')})",
            source_provider="graph_analyzer"
        )


class AssetToReachabilityBuilder(RelationshipBuilder):
    """Build Asset → Reachability relationships."""

    async def build(
        self,
        source_asset: Asset,
        target_asset: Asset,
    ) -> Optional[Relationship]:
        """Build Asset → Asset reachability relationship."""
        if not source_asset or not target_asset:
            return None

        # Check if reachable
        if target_asset.id not in source_asset.reachable_assets:
            return None

        confidence = 0.8

        return self.create_relationship(
            source_id=source_asset.id,
            source_type=EntityType.ASSET,
            target_id=target_asset.id,
            target_type=EntityType.ASSET,
            rel_type=RelationshipType.REACHABLE_TO,
            confidence=confidence,
            evidence=["network_analysis", "reachability_test"],
            reasoning=f"Asset {source_asset.hostname} can reach {target_asset.hostname}",
            source_provider="enrichment_pipeline"
        )


class IOCToMalwareBuilder(RelationshipBuilder):
    """Build IOC → Malware relationships from correlation."""

    async def build(
        self,
        ioc: IOC,
        malware: Dict[str, Any],
    ) -> Optional[Relationship]:
        """Build IOC → Malware relationship."""
        if not ioc or not malware:
            return None

        # Check if IOC is associated with malware
        confidence = malware.get("confidence", 0.7)

        if confidence < 0.5:
            return None

        return self.create_relationship(
            source_id=ioc.id,
            source_type=EntityType.IOC,
            target_id=malware.get("id"),
            target_type=EntityType.MALWARE,
            rel_type=RelationshipType.LINKED_TO,
            confidence=confidence,
            evidence=["malware_analysis", "ioc_correlation"],
            reasoning=f"IOC {ioc.value} linked to malware {malware.get('name')}",
            source_provider="correlator"
        )


class IOCToCampaignBuilder(RelationshipBuilder):
    """Build IOC → Campaign relationships."""

    async def build(
        self,
        ioc: IOC,
        campaign: Campaign,
    ) -> Optional[Relationship]:
        """Build IOC → Campaign relationship."""
        if not ioc or not campaign:
            return None

        # IOC observed in campaign
        confidence = 0.8

        return self.create_relationship(
            source_id=ioc.id,
            source_type=EntityType.IOC,
            target_id=campaign.id,
            target_type=EntityType.CAMPAIGN,
            rel_type=RelationshipType.OBSERVED_IN,
            confidence=confidence,
            evidence=["campaign_link", "ioc_tracking"],
            reasoning=f"IOC {ioc.value} observed in campaign {campaign.name}",
            source_provider="enrichment_pipeline"
        )
