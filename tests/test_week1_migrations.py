"""
tests/test_week1_migrations.py - Week 1 Migration Tests

Tests for:
- Migration system
- Schema creation
- Backward compatibility
- SQLiteRepository integration
"""

import pytest
import sqlite3
import tempfile
import os
from core.sqlite_repository import SQLiteRepository
from core.migrations.manager import MigrationManager
from core.threat_schema import Vulnerability, IOC, Campaign, ThreatActor, Infrastructure


class TestMigrationManager:
    """Test migration manager functionality."""

    def test_migration_manager_creation(self):
        """Test MigrationManager can be instantiated."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        manager = MigrationManager(temp_db)
        assert manager.db_path == temp_db

        os.unlink(temp_db)

    def test_pending_migrations_found(self):
        """Test pending migrations are discovered."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        manager = MigrationManager(temp_db)
        pending = manager.get_pending_migrations()

        assert len(pending) > 0
        assert "001" in pending

        os.unlink(temp_db)

    def test_migration_001_in_pending(self):
        """Test migration 001 is detected as pending."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        manager = MigrationManager(temp_db)
        pending = manager.get_pending_migrations()

        assert "001" in pending

        os.unlink(temp_db)


class TestSQLiteRepositoryMigrations:
    """Test SQLiteRepository with migrations."""

    def test_repository_auto_applies_migrations(self):
        """Test SQLiteRepository auto-applies migrations on init."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        # Initialize repo (should apply migrations)
        repo = SQLiteRepository(db_path=temp_db)

        # Verify tables exist
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table'
            ORDER BY name
        """)
        tables = {row[0] for row in cursor.fetchall()}

        expected_tables = {
            'assets', 'campaigns', 'iocs', 'intelligence_objects',
            'infrastructure', 'relationships', 'threat_actors',
            'threat_observations', 'vulnerabilities', '_migrations',
            # Week 2 memory tables
            'ioc_memory', 'campaign_memory', 'asset_memory',
            'infrastructure_memory', 'pattern_memory'
        }

        assert tables == expected_tables

        conn.close()
        os.unlink(temp_db)

    def test_temporal_columns_exist(self):
        """Test temporal columns are created in vulnerabilities."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        repo = SQLiteRepository(db_path=temp_db)

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(vulnerabilities)")
        columns = {row[1] for row in cursor.fetchall()}

        # Check temporal columns exist
        temporal_columns = {
            'kev_added_date', 'poc_published_date', 'exploit_evolution',
            'first_seen_in_wild', 'last_exploited'
        }

        assert temporal_columns.issubset(columns)

        conn.close()
        os.unlink(temp_db)

    def test_ioc_recurrence_columns_exist(self):
        """Test IOC recurrence columns exist."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        repo = SQLiteRepository(db_path=temp_db)

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(iocs)")
        columns = {row[1] for row in cursor.fetchall()}

        recurrence_columns = {
            'active_window', 'recurrence_count', 'recurrence_history'
        }

        assert recurrence_columns.issubset(columns)

        conn.close()
        os.unlink(temp_db)

    def test_new_entity_tables_exist(self):
        """Test new entity tables are created."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        repo = SQLiteRepository(db_path=temp_db)

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table'
            AND name IN ('campaigns', 'threat_actors', 'infrastructure')
        """)
        tables = {row[0] for row in cursor.fetchall()}

        assert tables == {'campaigns', 'threat_actors', 'infrastructure'}

        conn.close()
        os.unlink(temp_db)

    def test_performance_indexes_created(self):
        """Test performance indexes are created."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        repo = SQLiteRepository(db_path=temp_db)

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='index'
            AND name LIKE 'idx_%'
        """)
        indexes = {row[0] for row in cursor.fetchall()}

        # Check key indexes exist
        expected_indexes = {
            'idx_vuln_kev_added', 'idx_vuln_first_seen',
            'idx_ioc_recurrence', 'idx_campaign_active',
            'idx_actor_active', 'idx_infra_active',
            'idx_rel_source', 'idx_rel_target', 'idx_rel_confidence'
        }

        assert expected_indexes.issubset(indexes)

        conn.close()
        os.unlink(temp_db)

    def test_relationship_metadata_columns_exist(self):
        """Test relationship metadata columns exist."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        repo = SQLiteRepository(db_path=temp_db)

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(relationships)")
        columns = {row[1] for row in cursor.fetchall()}

        # Check metadata columns
        metadata_columns = {'metadata', 'reasoning'}
        assert metadata_columns.issubset(columns)

        conn.close()
        os.unlink(temp_db)


class TestBackwardCompatibility:
    """Test backward compatibility with existing code."""

    def test_vulnerability_without_temporal_fields(self):
        """Test Vulnerability works without temporal fields in DB."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        repo = SQLiteRepository(db_path=temp_db)

        # Old-style Vulnerability (no temporal)
        vuln = Vulnerability(
            id="CVE-2026-2652",
            description="Test CVE",
            published_date="2026-05-15"
        )

        assert vuln.kev_added_date is None
        assert vuln.first_seen_in_wild is None

        os.unlink(temp_db)

    def test_ioc_without_recurrence_fields(self):
        """Test IOC works without recurrence fields in DB."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        repo = SQLiteRepository(db_path=temp_db)

        # Old-style IOC (no recurrence)
        ioc = IOC(
            id="192.168.1.1",
            ioc_type="ip",
            value="192.168.1.1",
            first_seen="2024-01-01"
        )

        assert ioc.recurrence_count == 0
        assert ioc.recurrence_history == []

        os.unlink(temp_db)

    def test_multiple_repository_initializations(self):
        """Test multiple repo inits don't duplicate migrations."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        # First init
        repo1 = SQLiteRepository(db_path=temp_db)

        # Second init (should not fail)
        repo2 = SQLiteRepository(db_path=temp_db)

        # Verify tables still exist
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM _migrations WHERE status='applied'")
        count = cursor.fetchone()[0]

        # Should have exactly 1 version applied (001)
        assert count == 1

        conn.close()
        os.unlink(temp_db)


class TestSchemaIntegrity:
    """Test schema integrity after migrations."""

    def test_campaign_table_schema(self):
        """Test campaigns table has correct schema."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        repo = SQLiteRepository(db_path=temp_db)

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(campaigns)")
        columns = {row[1] for row in cursor.fetchall()}

        expected = {
            'id', 'name', 'aliases', 'description', 'threat_actors',
            'start_date', 'end_date', 'active', 'victimology', 'sectors',
            'techniques', 'malware', 'severity', 'confidence',
            'created_at', 'updated_at'
        }

        assert columns == expected

        conn.close()
        os.unlink(temp_db)

    def test_threat_actors_table_schema(self):
        """Test threat_actors table has correct schema."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        repo = SQLiteRepository(db_path=temp_db)

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(threat_actors)")
        columns = {row[1] for row in cursor.fetchall()}

        expected = {
            'id', 'name', 'aliases', 'description', 'campaigns',
            'malware_used', 'infrastructure', 'techniques', 'target_sectors',
            'active', 'last_seen', 'activity_level',
            'created_at', 'updated_at'
        }

        assert columns == expected

        conn.close()
        os.unlink(temp_db)

    def test_infrastructure_table_schema(self):
        """Test infrastructure table has correct schema."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        repo = SQLiteRepository(db_path=temp_db)

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(infrastructure)")
        columns = {row[1] for row in cursor.fetchall()}

        expected = {
            'id', 'node_type', 'value', 'c2_connections',
            'malware', 'campaigns', 'threat_actors',
            'first_seen', 'last_seen', 'active',
            'severity', 'confidence',
            'created_at', 'updated_at'
        }

        assert columns == expected

        conn.close()
        os.unlink(temp_db)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
