"""
tests/test_week2_memory.py - Week 2 Persistent Threat Memory Tests

Tests for:
- 5 memory features (IOC, Campaign, Asset, Infrastructure, Pattern)
- Memory record & retrieval operations
- Memory persistence (database integration)
- Memory queries & analysis
- Backward compatibility with Week 1
"""

import pytest
import sqlite3
import tempfile
import os
import json
from datetime import datetime, timedelta

from core.threat_memory import (
    ThreatMemoryEngine,
    RecurringIOCMemory,
    CampaignPersistenceMemory,
    AssetExposureHistoryMemory,
    InfrastructureReuseMemory,
    ExploitationPatternMemory,
)
from core.sqlite_repository import SQLiteRepository


class TestIOCRecurringMemory:
    """Test recurring IOC memory operations."""

    def test_record_ioc_occurrence(self):
        """Test recording single IOC occurrence."""
        engine = ThreatMemoryEngine()

        memory = engine.record_ioc_occurrence(
            ioc_id="ip-192.168.1.1",
            ioc_value="192.168.1.1",
            context="network_scan",
            campaign_id="APT28",
            severity="high",
            confidence=0.85,
        )

        assert memory.ioc_id == "ip-192.168.1.1"
        assert memory.ioc_value == "192.168.1.1"
        assert memory.occurrence_count == 1
        assert "APT28" in memory.associated_campaigns

    def test_track_recurring_ioc(self):
        """Test tracking IOC across multiple occurrences."""
        engine = ThreatMemoryEngine()

        # Record 3 occurrences
        for i in range(3):
            engine.record_ioc_occurrence(
                ioc_id="ip-10.0.0.1",
                ioc_value="10.0.0.1",
                context=f"detection_{i}",
                campaign_id=f"campaign_{i}",
            )

        memory = engine.get_ioc_memory("ip-10.0.0.1")
        assert memory.occurrence_count == 3
        assert len(memory.occurrences) == 3
        assert len(memory.associated_campaigns) == 3

    def test_get_recurring_iocs(self):
        """Test querying recurring IOCs."""
        engine = ThreatMemoryEngine()

        # Record IOCs with different frequencies
        for j in range(3):
            engine.record_ioc_occurrence(
                ioc_id=f"ip-recurring-{j}",
                ioc_value=f"10.0.0.{j}",
                context="test",
            )

        # Record single-occurrence IOC
        engine.record_ioc_occurrence(
            ioc_id="ip-single",
            ioc_value="10.0.1.1",
            context="test",
        )

        # Add second occurrence to first IOC
        engine.record_ioc_occurrence(
            ioc_id="ip-recurring-0",
            ioc_value="10.0.0.0",
            context="test2",
        )

        recurring = engine.get_recurring_iocs(min_occurrences=2)
        assert len(recurring) == 1
        assert recurring[0].ioc_id == "ip-recurring-0"

    def test_ioc_memory_fields(self):
        """Test all fields in IOC memory."""
        engine = ThreatMemoryEngine()

        memory = engine.record_ioc_occurrence(
            ioc_id="ip-test",
            ioc_value="192.168.1.100",
            context="infrastructure_scan",
            campaign_id="FIN7",
            asset_id="asset-001",
            severity="critical",
            confidence=0.95,
        )

        assert memory.ioc_id == "ip-test"
        assert memory.ioc_value == "192.168.1.100"
        assert memory.is_active == True
        assert memory.reuse_frequency >= 0.0
        assert memory.next_reuse_likelihood >= 0.0


class TestCampaignPersistenceMemory:
    """Test campaign persistence memory operations."""

    def test_record_campaign_activity(self):
        """Test recording campaign activity."""
        engine = ThreatMemoryEngine()

        memory = engine.record_campaign_activity(
            campaign_id="APT28-2026",
            campaign_name="APT28 Q2 Campaign",
            activity_type="exploit",
            targets_count=25,
            techniques_used=["T1566", "T1199"],
            severity="critical",
            confidence=0.9,
        )

        assert memory.campaign_id == "APT28-2026"
        assert memory.campaign_name == "APT28 Q2 Campaign"
        assert memory.activity_count == 1
        assert len(memory.activities) == 1
        assert len(memory.techniques_evolution) == 2

    def test_track_campaign_evolution(self):
        """Test tracking campaign evolution."""
        engine = ThreatMemoryEngine()

        # Record activities with evolving techniques
        techniques_list = [
            ["T1566", "T1199"],
            ["T1566", "T1566_002"],
            ["T1566_002", "T1199", "T1047"],
        ]

        for i, techniques in enumerate(techniques_list):
            engine.record_campaign_activity(
                campaign_id="APT-EVOLVE",
                campaign_name="Evolving APT",
                activity_type="exploitation" if i % 2 else "reconnaissance",
                targets_count=10 + i*5,
                techniques_used=techniques,
            )

        memory = engine.get_campaign_memory("APT-EVOLVE")
        assert memory.activity_count == 3
        assert memory.technique_changes > 0
        assert len(memory.techniques_evolution) > 2

    def test_get_active_campaigns(self):
        """Test querying active campaigns."""
        engine = ThreatMemoryEngine()

        # Create active campaign
        engine.record_campaign_activity(
            campaign_id="ACTIVE-1",
            campaign_name="Active Campaign 1",
            activity_type="exploit",
        )

        # Create inactive campaign
        memory = engine.record_campaign_activity(
            campaign_id="INACTIVE-1",
            campaign_name="Inactive Campaign 1",
            activity_type="reconnaissance",
        )
        memory.is_active = False

        active = engine.get_active_campaigns()
        assert len(active) >= 1
        active_ids = [c.campaign_id for c in active]
        assert "ACTIVE-1" in active_ids
        assert "INACTIVE-1" not in active_ids

    def test_campaign_memory_fields(self):
        """Test all fields in campaign memory."""
        engine = ThreatMemoryEngine()

        memory = engine.record_campaign_activity(
            campaign_id="complete-test",
            campaign_name="Complete Test Campaign",
            activity_type="targeted_attack",
            targets_count=50,
            techniques_used=["T1566", "T1059"],
            severity="critical",
            confidence=0.85,
        )

        assert memory.campaign_id == "complete-test"
        assert memory.is_active == True
        assert memory.activity_pattern == "unknown"
        assert memory.next_activity_likelihood >= 0.0
        assert memory.confidence >= 0.0


class TestAssetExposureHistoryMemory:
    """Test asset exposure history memory operations."""

    def test_record_asset_exposure(self):
        """Test recording asset exposure."""
        engine = ThreatMemoryEngine()

        memory = engine.record_asset_exposure(
            asset_id="asset-db-001",
            asset_name="Production Database",
            exposure_type="cve",
            cve_id="CVE-2026-1234",
            severity="critical",
        )

        assert memory.asset_id == "asset-db-001"
        assert memory.asset_name == "Production Database"
        assert memory.exposure_count == 1
        assert memory.is_currently_exposed == True
        assert len(memory.exposures) == 1

    def test_record_asset_remediation(self):
        """Test recording remediation action."""
        engine = ThreatMemoryEngine()

        # Create exposure
        engine.record_asset_exposure(
            asset_id="asset-web-001",
            asset_name="Web Server",
            exposure_type="ioc_detected",
            ioc_id="ip-malicious",
        )

        # Record remediation
        memory = engine.record_asset_remediation(
            asset_id="asset-web-001",
            exposure_duration_days=3,
            action="patched_and_isolated",
        )

        assert memory.is_currently_exposed == False
        assert memory.exposures[0].remediation_action == "patched_and_isolated"
        assert memory.exposures[0].exposure_duration_days == 3

    def test_track_exposure_patterns(self):
        """Test tracking asset exposure patterns."""
        engine = ThreatMemoryEngine()

        # Record multiple exposures
        for i in range(3):
            engine.record_asset_exposure(
                asset_id="asset-recurring",
                asset_name="Recurring Exposure Asset",
                exposure_type="vulnerability" if i % 2 else "ioc",
                cve_id=f"CVE-2026-{1000+i}" if i % 2 else None,
            )

        memory = engine.get_asset_memory("asset-recurring")
        assert memory.exposure_count == 3
        assert memory.exposure_frequency > 0.0
        assert memory.is_currently_exposed == True

    def test_get_exposed_assets(self):
        """Test querying currently exposed assets."""
        engine = ThreatMemoryEngine()

        # Create exposed asset
        engine.record_asset_exposure(
            asset_id="exposed-1",
            asset_name="Exposed Asset 1",
            exposure_type="cve",
        )

        # Create remediated asset
        engine.record_asset_exposure(
            asset_id="remediated-1",
            asset_name="Remediated Asset 1",
            exposure_type="cve",
        )
        engine.record_asset_remediation(
            asset_id="remediated-1",
            exposure_duration_days=1,
            action="fixed",
        )

        exposed = engine.get_exposed_assets()
        exposed_ids = [a.asset_id for a in exposed]
        assert "exposed-1" in exposed_ids
        assert "remediated-1" not in exposed_ids

    def test_asset_memory_fields(self):
        """Test all fields in asset memory."""
        engine = ThreatMemoryEngine()

        memory = engine.record_asset_exposure(
            asset_id="asset-complete",
            asset_name="Complete Test Asset",
            exposure_type="malware_detected",
        )

        assert memory.asset_id == "asset-complete"
        assert memory.exposure_frequency >= 0.0
        assert memory.remediation_success_rate >= 0.0
        assert memory.next_exposure_likelihood >= 0.0
        assert memory.exposure_trend == "unknown"


class TestInfrastructureReuseMemory:
    """Test infrastructure reuse memory operations."""

    def test_record_infrastructure_use(self):
        """Test recording infrastructure use."""
        engine = ThreatMemoryEngine()

        memory = engine.record_infrastructure_use(
            infrastructure_id="c2-network-001",
            node_type="c2_server",
            node_value="evil.com",
            campaign_id="APT28-2026",
            malware_family="Zebrocy",
        )

        assert memory.infrastructure_id == "c2-network-001"
        assert memory.reuse_count == 1
        assert len(memory.nodes) == 1
        assert "APT28-2026" in memory.associated_campaigns

    def test_track_infrastructure_pivot_chains(self):
        """Test tracking infrastructure pivot chains."""
        engine = ThreatMemoryEngine()

        # Record multiple nodes in infrastructure family
        nodes = [
            ("c2-001", "proxy", "proxy.evil.com"),
            ("c2-001", "c2_server", "c2.evil.com"),
            ("c2-001", "exfil_server", "data.evil.com"),
        ]

        for infra_id, node_type, node_value in nodes:
            engine.record_infrastructure_use(
                infrastructure_id=infra_id,
                node_type=node_type,
                node_value=node_value,
                campaign_id="APT-INFRA",
            )

        memory = engine.get_infrastructure_memory("c2-001")
        assert memory.reuse_count == 3
        assert len(memory.nodes) == 3

    def test_get_reused_infrastructure(self):
        """Test querying reused infrastructure."""
        engine = ThreatMemoryEngine()

        # Create heavily reused infra
        for i in range(3):
            engine.record_infrastructure_use(
                infrastructure_id="reused-infra",
                node_type="c2",
                node_value="persistent.evil.com",
                campaign_id=f"campaign_{i}",
            )

        # Create single-use infra
        engine.record_infrastructure_use(
            infrastructure_id="single-use-infra",
            node_type="c2",
            node_value="temp.evil.com",
            campaign_id="campaign_x",
        )

        reused = engine.get_reused_infrastructure(min_reuses=2)
        reused_ids = [i.infrastructure_id for i in reused]
        assert "reused-infra" in reused_ids
        assert "single-use-infra" not in reused_ids

    def test_infrastructure_memory_fields(self):
        """Test all fields in infrastructure memory."""
        engine = ThreatMemoryEngine()

        memory = engine.record_infrastructure_use(
            infrastructure_id="infra-complete",
            node_type="c2_server",
            node_value="c2.evil.com",
            campaign_id="APT-TEST",
            malware_family="BackdoorA",
        )

        assert memory.infrastructure_id == "infra-complete"
        assert memory.is_active == True
        assert memory.reuse_frequency >= 0.0
        assert memory.next_reuse_likelihood >= 0.0


class TestExploitationPatternMemory:
    """Test exploitation pattern memory operations."""

    def test_record_exploitation_pattern(self):
        """Test recording exploitation pattern."""
        engine = ThreatMemoryEngine()

        memory = engine.record_exploitation_pattern(
            pattern_id="pattern-phishing-001",
            pattern_name="Spear Phishing with Macro",
            technique_id="T1566",
            technique_name="Phishing",
            campaign_id="APT28-2026",
            success=True,
            target_count=5,
        )

        assert memory.pattern_id == "pattern-phishing-001"
        assert memory.pattern_name == "Spear Phishing with Macro"
        assert memory.occurrence_count == 1
        assert memory.success_rate == 1.0

    def test_track_pattern_success_rate(self):
        """Test tracking exploitation pattern success rates."""
        engine = ThreatMemoryEngine()

        # Record 3 successful, 2 failed pattern uses
        for i in range(5):
            engine.record_exploitation_pattern(
                pattern_id="pattern-exploit-001",
                pattern_name="SQL Injection Attack",
                technique_id="T1190",
                technique_name="Exploit Public-Facing Application",
                campaign_id="campaign_exploit",
                success=(i < 3),
                target_count=10,
            )

        memory = engine.get_pattern_memory("pattern-exploit-001")
        assert memory.occurrence_count == 5
        assert memory.success_rate == 0.6  # 3/5

    def test_track_pattern_adoption(self):
        """Test tracking technique adoption across campaigns."""
        engine = ThreatMemoryEngine()

        # Record pattern adoption by different campaigns
        campaigns = ["APT28", "APT29", "Lazarus"]
        for campaign_id in campaigns:
            engine.record_exploitation_pattern(
                pattern_id="pattern-wormable",
                pattern_name="Wormable Vulnerability Exploitation",
                technique_id="T1072",
                technique_name="Software Deployment Tools",
                campaign_id=campaign_id,
                success=True,
            )

        memory = engine.get_pattern_memory("pattern-wormable")
        assert len(memory.adopting_campaigns) >= 3

    def test_get_effective_patterns(self):
        """Test querying effective patterns."""
        engine = ThreatMemoryEngine()

        # Highly effective pattern (90% success)
        for i in range(10):
            engine.record_exploitation_pattern(
                pattern_id="effective-pattern",
                pattern_name="Effective Attack",
                technique_id="T1055",
                technique_name="Process Injection",
                success=(i < 9),
            )

        # Low effectiveness pattern (20% success)
        for i in range(10):
            engine.record_exploitation_pattern(
                pattern_id="weak-pattern",
                pattern_name="Weak Attack",
                technique_id="T1566",
                technique_name="Phishing",
                success=(i < 2),
            )

        effective = engine.get_effective_patterns(min_success_rate=0.5)
        effective_ids = [p.pattern_id for p in effective]
        assert "effective-pattern" in effective_ids
        assert "weak-pattern" not in effective_ids

    def test_pattern_memory_fields(self):
        """Test all fields in pattern memory."""
        engine = ThreatMemoryEngine()

        memory = engine.record_exploitation_pattern(
            pattern_id="pattern-complete",
            pattern_name="Complete Test Pattern",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            success=True,
            target_count=20,
        )

        assert memory.pattern_id == "pattern-complete"
        assert memory.adoption_trend == "unknown"
        assert memory.is_active == True
        assert memory.predicted_effectiveness >= 0.0


class TestMemoryQueries:
    """Test memory query operations."""

    def test_get_memory_summary(self):
        """Test memory summary query."""
        engine = ThreatMemoryEngine()

        # Populate all memory types
        engine.record_ioc_occurrence("ioc-1", "10.0.0.1", "test")
        engine.record_campaign_activity("camp-1", "Campaign 1", "exploit")
        engine.record_asset_exposure("asset-1", "Asset 1", "cve")
        engine.record_infrastructure_use("infra-1", "c2", "c2.evil.com")
        engine.record_exploitation_pattern("pattern-1", "Pattern 1", "T1566", "Phishing")

        summary = engine.get_memory_summary()

        assert summary["ioc_memory_count"] >= 1
        assert summary["campaign_memory_count"] >= 1
        assert summary["asset_memory_count"] >= 1
        assert summary["infrastructure_memory_count"] >= 1
        assert summary["pattern_memory_count"] >= 1

    def test_get_threat_timeline(self):
        """Test threat timeline query."""
        engine = ThreatMemoryEngine()

        # Create events across time
        engine.record_ioc_occurrence("ioc-1", "10.0.0.1", "scan")
        engine.record_campaign_activity("camp-1", "Campaign 1", "exploit")
        engine.record_asset_exposure("asset-1", "Asset 1", "cve")

        timeline = engine.get_threat_timeline(days_back=30)

        assert len(timeline) >= 3
        # Timeline should have mixed event types
        event_types = {e["type"] for e in timeline}
        assert "ioc_observation" in event_types
        assert "campaign_activity" in event_types
        assert "asset_exposure" in event_types


class TestMemoryPersistence:
    """Test memory persistence with SQLiteRepository."""

    def test_repository_initializes_memory(self):
        """Test that SQLiteRepository initializes ThreatMemoryEngine."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        repo = SQLiteRepository(db_path=temp_db)

        assert repo.memory_engine is not None
        assert isinstance(repo.memory_engine, ThreatMemoryEngine)

        os.unlink(temp_db)

    def test_persist_and_load_ioc_memory(self):
        """Test persisting and loading IOC memory."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        # Create repo and record memory
        repo1 = SQLiteRepository(db_path=temp_db)
        repo1.memory_engine.record_ioc_occurrence(
            "ioc-persist-1",
            "192.168.1.1",
            "network_scan",
            campaign_id="APT-PERSIST",
        )
        repo1._save_memory_to_db()

        # Create new repo and verify memory is loaded
        repo2 = SQLiteRepository(db_path=temp_db)
        memory = repo2.memory_engine.get_ioc_memory("ioc-persist-1")

        assert memory is not None
        assert memory.ioc_value == "192.168.1.1"
        assert "APT-PERSIST" in memory.associated_campaigns

        os.unlink(temp_db)

    def test_persist_and_load_campaign_memory(self):
        """Test persisting and loading campaign memory."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        # Create repo and record memory
        repo1 = SQLiteRepository(db_path=temp_db)
        repo1.memory_engine.record_campaign_activity(
            "campaign-persist",
            "Persistent Campaign",
            "exploitation",
            targets_count=50,
        )
        repo1._save_memory_to_db()

        # Create new repo and verify memory is loaded
        repo2 = SQLiteRepository(db_path=temp_db)
        memory = repo2.memory_engine.get_campaign_memory("campaign-persist")

        assert memory is not None
        assert memory.campaign_name == "Persistent Campaign"
        assert memory.activity_count >= 1

        os.unlink(temp_db)

    def test_persist_and_load_asset_memory(self):
        """Test persisting and loading asset memory."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        # Create repo and record memory
        repo1 = SQLiteRepository(db_path=temp_db)
        repo1.memory_engine.record_asset_exposure(
            "asset-persist",
            "Persistent Asset",
            "vulnerability",
            cve_id="CVE-2026-9999",
        )
        repo1._save_memory_to_db()

        # Create new repo and verify memory is loaded
        repo2 = SQLiteRepository(db_path=temp_db)
        memory = repo2.memory_engine.get_asset_memory("asset-persist")

        assert memory is not None
        assert memory.asset_name == "Persistent Asset"
        assert memory.is_currently_exposed == True

        os.unlink(temp_db)

    def test_memory_tables_created(self):
        """Test that memory tables are created in database."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        repo = SQLiteRepository(db_path=temp_db)

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table'
            AND name IN ('ioc_memory', 'campaign_memory', 'asset_memory',
                         'infrastructure_memory', 'pattern_memory')
        """)
        tables = {row[0] for row in cursor.fetchall()}

        expected = {
            'ioc_memory', 'campaign_memory', 'asset_memory',
            'infrastructure_memory', 'pattern_memory'
        }

        assert tables == expected

        conn.close()
        os.unlink(temp_db)


class TestBackwardCompatibility:
    """Test backward compatibility with Week 1 systems."""

    def test_memory_independent_of_week1(self):
        """Test that memory system doesn't break Week 1 functionality."""
        engine = ThreatMemoryEngine()

        # Week 1 relationship should still work
        from core.threat_schema import Relationship, RelationshipType, EntityType

        rel = Relationship(
            source_id="cve-001",
            source_type=EntityType.VULNERABILITY,
            target_id="malware-001",
            target_type=EntityType.MALWARE,
            relationship_type=RelationshipType.LINKED_TO,
            strength="strong",
        )

        assert rel.relationship_type == RelationshipType.LINKED_TO
        # Memory engine shouldn't affect relationship creation
        assert engine.get_memory_summary() is not None

    def test_repository_with_week1_operations(self):
        """Test that Week 1 repository operations still work with memory."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        repo = SQLiteRepository(db_path=temp_db)

        # Week 1 vulnerability should persist
        from core.threat_schema import Vulnerability

        vuln = Vulnerability(
            id="CVE-2026-test",
            description="Test CVE",
            published_date="2026-05-15",
        )

        # Memory engine should coexist peacefully
        assert repo.memory_engine is not None
        assert len(repo.memory_engine.ioc_memory) == 0

        os.unlink(temp_db)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
