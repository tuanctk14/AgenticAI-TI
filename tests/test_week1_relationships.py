"""
tests/test_week1_relationships.py - Week 1 Relationship Tests

Comprehensive tests for:
- 16 relationship types
- RelationshipMetadata
- Relationship builders
- Temporal fields
- Backward compatibility
"""

import pytest
import asyncio
from datetime import datetime
from core.threat_schema import (
    Vulnerability, IOC, Asset, Campaign, ThreatActor, Infrastructure,
    Relationship, RelationshipMetadata, RelationshipType, EntityType, IOCType,
    RiskContext
)
from core.relationship_builders import (
    CVEToMalwareBuilder, CVEToCampaignBuilder, CVEToThreatActorBuilder,
    CVEToATTACKBuilder, MalwareToCampaignBuilder, ThreatActorToCampaignBuilder,
    ThreatActorToInfraBuilder, InfraToC2Builder, CampaignToVictimologyBuilder,
    CampaignToSectorBuilder, AssetToAttackPathBuilder, AssetToReachabilityBuilder,
    IOCToMalwareBuilder, IOCToCampaignBuilder
)


# ============================================================
# TEST: 16 RELATIONSHIP TYPES
# ============================================================

def test_all_16_relationship_types_exist():
    """Verify all 16 relationship types are defined."""
    expected_types = {
        "VULNERABLE_TO", "LINKED_TO", "EXPLOITS", "COMMUNICATES_WITH",
        "MAPPED_TO", "DETECTED_ON", "REACHABLE_TO", "EXPOSED_TO",
        "USES", "OBSERVED_IN",
        "USES_MALWARE", "LEADS_CAMPAIGN", "OPERATES_INFRASTRUCTURE",
        "TARGETS_SECTOR", "TARGETS_VICTIMOLOGY", "FACES_EXPOSURE"
    }

    actual_types = {e.name for e in RelationshipType}
    assert actual_types == expected_types, f"Mismatch: {actual_types ^ expected_types}"


def test_relationship_type_values():
    """Verify relationship type values are correct."""
    assert RelationshipType.VULNERABLE_TO.value == "vulnerable_to"
    assert RelationshipType.USES_MALWARE.value == "uses_malware"
    assert RelationshipType.LEADS_CAMPAIGN.value == "leads_campaign"
    assert RelationshipType.OPERATES_INFRASTRUCTURE.value == "operates_infrastructure"
    assert RelationshipType.TARGETS_SECTOR.value == "targets_sector"
    assert RelationshipType.TARGETS_VICTIMOLOGY.value == "targets_victimology"
    assert RelationshipType.FACES_EXPOSURE.value == "faces_exposure"


# ============================================================
# TEST: RELATIONSHIP METADATA
# ============================================================

def test_relationship_metadata_creation():
    """Test RelationshipMetadata model."""
    metadata = RelationshipMetadata(
        confidence=0.85,
        evidence=["opencti_source", "temporal_correlation"],
        active=True,
        source="opencti",
        reasoning="Campaign exploits CVE"
    )

    assert metadata.confidence == 0.85
    assert "opencti_source" in metadata.evidence
    assert metadata.active is True
    assert metadata.source == "opencti"


def test_relationship_metadata_defaults():
    """Test RelationshipMetadata with defaults."""
    metadata = RelationshipMetadata(
        confidence=0.7,
        source="builder"
    )

    assert metadata.confidence == 0.7
    assert metadata.evidence == []
    assert metadata.active is True
    assert metadata.source == "builder"
    assert metadata.reasoning is None


def test_relationship_with_metadata():
    """Test Relationship with metadata."""
    metadata = RelationshipMetadata(
        confidence=0.9,
        evidence=["opencti_source"],
        source="opencti"
    )

    rel = Relationship(
        source_id="campaign-1",
        source_type=EntityType.CAMPAIGN,
        target_id="CVE-2024-1086",
        target_type=EntityType.VULNERABILITY,
        relationship_type=RelationshipType.EXPLOITS,
        confidence=0.9,
        metadata=metadata
    )

    assert rel.metadata is not None
    assert rel.metadata.confidence == 0.9
    assert rel.metadata.source == "opencti"


# ============================================================
# TEST: TEMPORAL FIELDS
# ============================================================

def test_vulnerability_temporal_fields():
    """Test Vulnerability temporal fields."""
    vuln = Vulnerability(
        id="CVE-2024-1086",
        description="Linux kernel vulnerability",
        kev_added_date=datetime(2024, 2, 1),
        poc_published_date=datetime(2024, 2, 2),
        first_seen_in_wild=datetime(2024, 2, 5),
        last_exploited=datetime(2026, 5, 10),
        exploit_evolution={
            "2024-02-01": "Initial PoC",
            "2024-02-15": "Metasploit module"
        }
    )

    assert vuln.kev_added_date == datetime(2024, 2, 1)
    assert vuln.poc_published_date == datetime(2024, 2, 2)
    assert vuln.first_seen_in_wild == datetime(2024, 2, 5)
    assert len(vuln.exploit_evolution) == 2


def test_ioc_temporal_fields():
    """Test IOC temporal fields."""
    ioc = IOC(
        id="192.168.1.100",
        ioc_type=IOCType.IP,
        value="192.168.1.100",
        active_window="2024-01 to 2026-05",
        recurrence_count=3,
        recurrence_history=[
            {"date": "2024-01-01", "campaign": "campaign-1"},
            {"date": "2024-06-01", "campaign": "campaign-2"},
            {"date": "2025-12-01", "campaign": "campaign-3"}
        ]
    )

    assert ioc.active_window == "2024-01 to 2026-05"
    assert ioc.recurrence_count == 3
    assert len(ioc.recurrence_history) == 3


def test_temporal_fields_optional():
    """Test temporal fields are optional."""
    vuln = Vulnerability(
        id="CVE-2026-2652",
        description="Test CVE"
    )

    assert vuln.kev_added_date is None
    assert vuln.poc_published_date is None
    assert vuln.first_seen_in_wild is None
    assert vuln.exploit_evolution is None

    ioc = IOC(
        id="example.com",
        ioc_type=IOCType.DOMAIN,
        value="example.com"
    )

    assert ioc.active_window is None
    assert ioc.recurrence_count == 0
    assert ioc.recurrence_history == []


# ============================================================
# TEST: CONTEXTUAL RISK FIELDS
# ============================================================

def test_risk_context_contextual_fields():
    """Test RiskContext contextual fields."""
    risk = RiskContext(
        cvss_score=9.8,
        epss_score=0.97,
        attack_path_length=3,
        campaign_active=True,
        campaign_name="APT1 Campaign",
        malware_family="Poison Ivy",
        threat_actor="APT1",
        historical_recurrence=0.75,
        exploitation_confidence=0.92
    )

    assert risk.attack_path_length == 3
    assert risk.campaign_active is True
    assert risk.campaign_name == "APT1 Campaign"
    assert risk.malware_family == "Poison Ivy"
    assert risk.threat_actor == "APT1"
    assert risk.historical_recurrence == 0.75
    assert risk.exploitation_confidence == 0.92


def test_risk_context_defaults():
    """Test RiskContext with defaults."""
    risk = RiskContext(
        cvss_score=7.5,
        epss_score=0.5
    )

    assert risk.attack_path_length is None
    assert risk.campaign_active is False
    assert risk.campaign_name is None
    assert risk.historical_recurrence == 0.0
    assert risk.exploitation_confidence == 0.0


# ============================================================
# TEST: LIGHTWEIGHT ENTITIES
# ============================================================

def test_campaign_entity():
    """Test Campaign lightweight entity."""
    campaign = Campaign(
        id="campaign-1",
        name="APT1 Campaign",
        aliases=["Campaign X"],
        threat_actors=["apt1"],
        sectors=["Government", "Finance"],
        victimology=["Government Officials"],
        malware=["malware-1", "malware-2"],
        techniques=["T1234", "T5678"],
        active=True,
        severity="CRITICAL",
        confidence=0.9
    )

    assert campaign.id == "campaign-1"
    assert campaign.name == "APT1 Campaign"
    assert len(campaign.sectors) == 2
    assert campaign.active is True
    assert campaign.confidence == 0.9


def test_threat_actor_entity():
    """Test ThreatActor lightweight entity."""
    actor = ThreatActor(
        id="actor-1",
        name="APT1",
        aliases=["Comment Crew"],
        campaigns=["campaign-1"],
        malware_used=["malware-1"],
        infrastructure=["infra-1"],
        techniques=["T1234"],
        target_sectors=["Government"],
        activity_level="high",
        active=True
    )

    assert actor.id == "actor-1"
    assert actor.name == "APT1"
    assert actor.activity_level == "high"
    assert actor.campaigns[0] == "campaign-1"


def test_infrastructure_entity():
    """Test Infrastructure lightweight entity."""
    infra = Infrastructure(
        id="infra-1",
        node_type="c2",
        value="192.168.1.1",
        c2_connections=["192.168.1.2"],
        malware=["malware-1"],
        campaigns=["campaign-1"],
        threat_actors=["actor-1"],
        active=True,
        severity="HIGH",
        confidence=0.85
    )

    assert infra.id == "infra-1"
    assert infra.node_type == "c2"
    assert infra.value == "192.168.1.1"
    assert len(infra.c2_connections) == 1


# ============================================================
# TEST: RELATIONSHIP BUILDERS
# ============================================================

@pytest.mark.asyncio
async def test_cve_to_campaign_builder():
    """Test CVEToCampaignBuilder."""
    cve = Vulnerability(
        id="CVE-2024-1086",
        description="Test CVE"
    )

    campaign = Campaign(
        id="campaign-1",
        name="Test Campaign",
        active=True
    )

    builder = CVEToCampaignBuilder()
    rel = await builder.build(cve, campaign)

    assert rel is not None
    assert rel.source_id == "CVE-2024-1086"
    assert rel.target_id == "campaign-1"
    assert rel.relationship_type == RelationshipType.OBSERVED_IN
    assert rel.confidence >= 0.5


@pytest.mark.asyncio
async def test_threat_actor_to_campaign_builder():
    """Test ThreatActorToCampaignBuilder."""
    actor = ThreatActor(
        id="actor-1",
        name="APT1",
        campaigns=["campaign-1"]
    )

    campaign = Campaign(
        id="campaign-1",
        name="Test Campaign"
    )

    builder = ThreatActorToCampaignBuilder()
    rel = await builder.build(actor, campaign)

    assert rel is not None
    assert rel.source_id == "actor-1"
    assert rel.target_id == "campaign-1"
    assert rel.relationship_type == RelationshipType.LEADS_CAMPAIGN
    assert rel.confidence >= 0.8


@pytest.mark.asyncio
async def test_ioc_to_campaign_builder():
    """Test IOCToCampaignBuilder."""
    ioc = IOC(
        id="192.168.1.100",
        ioc_type=IOCType.IP,
        value="192.168.1.100"
    )

    campaign = Campaign(
        id="campaign-1",
        name="Test Campaign"
    )

    builder = IOCToCampaignBuilder()
    rel = await builder.build(ioc, campaign)

    assert rel is not None
    assert rel.source_id == "192.168.1.100"
    assert rel.target_id == "campaign-1"
    assert rel.relationship_type == RelationshipType.OBSERVED_IN


@pytest.mark.asyncio
async def test_builder_with_metadata():
    """Test builder generates metadata correctly."""
    cve = Vulnerability(
        id="CVE-2024-1086",
        description="Test"
    )

    campaign = Campaign(
        id="campaign-1",
        name="Test"
    )

    builder = CVEToCampaignBuilder()
    rel = await builder.build(cve, campaign)

    assert rel.metadata is not None
    assert rel.metadata.confidence == rel.confidence
    assert rel.metadata.source == "opencti"
    assert rel.metadata.active is True
    assert rel.metadata.reasoning is not None


# ============================================================
# TEST: BACKWARD COMPATIBILITY
# ============================================================

def test_backward_compatibility_vulnerability():
    """Test old Vulnerability code still works."""
    # Old code - no temporal fields
    vuln = Vulnerability(
        id="CVE-2026-2652",
        description="Test CVE",
        published_date="2026-05-15"
    )

    assert vuln.id == "CVE-2026-2652"
    assert vuln.kev_added_date is None
    assert vuln.first_seen_in_wild is None


def test_backward_compatibility_relationship():
    """Test old Relationship code still works."""
    # Old code - no metadata
    rel = Relationship(
        source_id="asset-1",
        source_type=EntityType.ASSET,
        target_id="CVE-2024-1086",
        target_type=EntityType.VULNERABILITY,
        relationship_type=RelationshipType.VULNERABLE_TO,
        confidence=0.9
    )

    assert rel.confidence == 0.9
    assert rel.metadata is None


def test_backward_compatibility_risk_context():
    """Test old RiskContext code still works."""
    # Old code - no contextual fields
    risk = RiskContext(
        cvss_score=8.6,
        epss_score=0.5,
        kev_listed=False
    )

    assert risk.cvss_score == 8.6
    assert risk.campaign_active is False
    assert risk.attack_path_length is None


# ============================================================
# TEST: CONFIDENCE SCORING
# ============================================================

def test_relationship_strength_custom():
    """Test custom strength assignment."""
    rel = Relationship(
        source_id="s1",
        source_type=EntityType.VULNERABILITY,
        target_id="t1",
        target_type=EntityType.CAMPAIGN,
        relationship_type=RelationshipType.OBSERVED_IN,
        confidence=0.95,
        strength="strong"
    )

    assert rel.strength == "strong"
    assert rel.confidence == 0.95


def test_relationship_strength_default():
    """Test default strength is medium."""
    rel = Relationship(
        source_id="s1",
        source_type=EntityType.VULNERABILITY,
        target_id="t1",
        target_type=EntityType.CAMPAIGN,
        relationship_type=RelationshipType.OBSERVED_IN,
        confidence=0.65
    )

    assert rel.strength == "medium"  # Default


def test_relationship_strength_weak_custom():
    """Test weak strength assignment."""
    rel = Relationship(
        source_id="s1",
        source_type=EntityType.VULNERABILITY,
        target_id="t1",
        target_type=EntityType.CAMPAIGN,
        relationship_type=RelationshipType.OBSERVED_IN,
        confidence=0.3,
        strength="weak"
    )

    assert rel.strength == "weak"


# ============================================================
# TEST: ENTITY TYPES
# ============================================================

def test_entity_types_complete():
    """Test all entity types defined."""
    expected = {
        "VULNERABILITY", "IOC", "ASSET", "RELATIONSHIP",
        "MALWARE", "CAMPAIGN", "THREAT_ACTOR", "ATTACK_PATTERN",
        "INFRASTRUCTURE"
    }

    actual = {e.name for e in EntityType}
    assert actual == expected


# ============================================================
# INTEGRATION TESTS
# ============================================================

def test_full_relationship_chain():
    """Test complete relationship chain."""
    # Create entities
    vuln = Vulnerability(
        id="CVE-2024-1086",
        description="Test"
    )

    campaign = Campaign(
        id="campaign-1",
        name="APT1",
        active=True
    )

    actor = ThreatActor(
        id="actor-1",
        name="APT1",
        campaigns=["campaign-1"]
    )

    # Create relationships
    rel1 = Relationship(
        source_id=vuln.id,
        source_type=EntityType.VULNERABILITY,
        target_id=campaign.id,
        target_type=EntityType.CAMPAIGN,
        relationship_type=RelationshipType.OBSERVED_IN,
        confidence=0.8
    )

    rel2 = Relationship(
        source_id=actor.id,
        source_type=EntityType.THREAT_ACTOR,
        target_id=campaign.id,
        target_type=EntityType.CAMPAIGN,
        relationship_type=RelationshipType.LEADS_CAMPAIGN,
        confidence=0.9
    )

    # Verify chain
    assert rel1.target_id == rel2.target_id  # Both point to same campaign
    assert rel1.relationship_type != rel2.relationship_type


@pytest.mark.asyncio
async def test_multiple_builders():
    """Test multiple builders on same entities."""
    cve = Vulnerability(id="CVE-2024-1086", description="Test")
    campaign = Campaign(id="campaign-1", name="Test")

    builder1 = CVEToCampaignBuilder()
    builder2 = IOCToCampaignBuilder()

    rel1 = await builder1.build(cve, campaign)

    ioc = IOC(id="192.168.1.1", ioc_type=IOCType.IP, value="192.168.1.1")
    rel2 = await builder2.build(ioc, campaign)

    assert rel1 is not None
    assert rel2 is not None
    assert rel1.source_type != rel2.source_type


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
