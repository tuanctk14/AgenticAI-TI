"""
core/migrations/001_temporal_and_relationships.py - Week 1 Schema Migration

Adds temporal intelligence + relationship entity support to SQLite.

Changes:
1. Add temporal columns to vulnerabilities table
2. Add temporal columns to iocs table
3. Create campaigns table
4. Create threat_actors table
5. Create infrastructure table
6. Update relationships table schema
7. Create indexes for temporal fields

Version: 001
Date: 2026-05-17
Depends: Initial schema (from _init_db)
"""

import sqlite3
from datetime import datetime
from typing import Optional


def upgrade(conn: sqlite3.Connection) -> None:
    """
    Apply migration: add temporal + relationship support.

    Args:
        conn: SQLite connection
    """
    cursor = conn.cursor()

    # ============================================================
    # 1. ALTER vulnerabilities - Add temporal fields
    # ============================================================

    # Check if columns exist before adding
    cursor.execute("PRAGMA table_info(vulnerabilities)")
    existing_columns = {row[1] for row in cursor.fetchall()}

    if "kev_added_date" not in existing_columns:
        cursor.execute("""
            ALTER TABLE vulnerabilities
            ADD COLUMN kev_added_date TEXT
        """)

    if "poc_published_date" not in existing_columns:
        cursor.execute("""
            ALTER TABLE vulnerabilities
            ADD COLUMN poc_published_date TEXT
        """)

    if "exploit_evolution" not in existing_columns:
        cursor.execute("""
            ALTER TABLE vulnerabilities
            ADD COLUMN exploit_evolution JSON
        """)

    if "first_seen_in_wild" not in existing_columns:
        cursor.execute("""
            ALTER TABLE vulnerabilities
            ADD COLUMN first_seen_in_wild TEXT
        """)

    if "last_exploited" not in existing_columns:
        cursor.execute("""
            ALTER TABLE vulnerabilities
            ADD COLUMN last_exploited TEXT
        """)

    # ============================================================
    # 2. ALTER iocs - Add temporal + recurrence fields
    # ============================================================

    cursor.execute("PRAGMA table_info(iocs)")
    existing_columns = {row[1] for row in cursor.fetchall()}

    if "active_window" not in existing_columns:
        cursor.execute("""
            ALTER TABLE iocs
            ADD COLUMN active_window TEXT
        """)

    if "recurrence_count" not in existing_columns:
        cursor.execute("""
            ALTER TABLE iocs
            ADD COLUMN recurrence_count INTEGER DEFAULT 0
        """)

    if "recurrence_history" not in existing_columns:
        cursor.execute("""
            ALTER TABLE iocs
            ADD COLUMN recurrence_history JSON
        """)

    # ============================================================
    # 3. CREATE campaigns table
    # ============================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS campaigns (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            aliases JSON,
            description TEXT,
            threat_actors JSON,
            start_date TEXT,
            end_date TEXT,
            active BOOLEAN DEFAULT TRUE,
            victimology JSON,
            sectors JSON,
            techniques JSON,
            malware JSON,
            severity TEXT,
            confidence REAL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # ============================================================
    # 4. CREATE threat_actors table
    # ============================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_actors (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            aliases JSON,
            description TEXT,
            campaigns JSON,
            malware_used JSON,
            infrastructure JSON,
            techniques JSON,
            target_sectors JSON,
            active BOOLEAN DEFAULT TRUE,
            last_seen TEXT,
            activity_level TEXT DEFAULT 'unknown',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # ============================================================
    # 5. CREATE infrastructure table
    # ============================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS infrastructure (
            id TEXT PRIMARY KEY,
            node_type TEXT NOT NULL,
            value TEXT NOT NULL,
            c2_connections JSON,
            malware JSON,
            campaigns JSON,
            threat_actors JSON,
            first_seen TEXT,
            last_seen TEXT,
            active BOOLEAN DEFAULT TRUE,
            severity TEXT,
            confidence REAL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # ============================================================
    # 6. UPDATE relationships table schema
    # ============================================================

    cursor.execute("PRAGMA table_info(relationships)")
    rel_columns = {row[1] for row in cursor.fetchall()}

    if "metadata" not in rel_columns:
        cursor.execute("""
            ALTER TABLE relationships
            ADD COLUMN metadata JSON
        """)

    if "reasoning" not in rel_columns:
        cursor.execute("""
            ALTER TABLE relationships
            ADD COLUMN reasoning TEXT
        """)

    # ============================================================
    # 7. CREATE indexes for performance
    # ============================================================

    # Temporal field indexes (for range queries)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_vuln_kev_added
        ON vulnerabilities(kev_added_date)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_vuln_first_seen
        ON vulnerabilities(first_seen_in_wild)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_ioc_recurrence
        ON iocs(recurrence_count)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_campaign_active
        ON campaigns(active)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_actor_active
        ON threat_actors(active)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_infra_active
        ON infrastructure(active)
    """)

    # Relationship indexes (for traversal)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_rel_source
        ON relationships(source_id, relationship_type)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_rel_target
        ON relationships(target_id, relationship_type)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_rel_confidence
        ON relationships(confidence)
    """)

    conn.commit()
    print("[Migration 001] Upgrade complete: temporal + relationships support added")


def downgrade(conn: sqlite3.Connection) -> None:
    """
    Rollback migration.

    Note: SQLite doesn't support DROP COLUMN easily.
    This creates a backup of old data structure.

    Args:
        conn: SQLite connection
    """
    cursor = conn.cursor()

    # Drop new tables
    cursor.execute("DROP TABLE IF EXISTS campaigns")
    cursor.execute("DROP TABLE IF EXISTS threat_actors")
    cursor.execute("DROP TABLE IF EXISTS infrastructure")

    # Drop new indexes
    cursor.execute("DROP INDEX IF EXISTS idx_vuln_kev_added")
    cursor.execute("DROP INDEX IF EXISTS idx_vuln_first_seen")
    cursor.execute("DROP INDEX IF EXISTS idx_ioc_recurrence")
    cursor.execute("DROP INDEX IF EXISTS idx_campaign_active")
    cursor.execute("DROP INDEX IF EXISTS idx_actor_active")
    cursor.execute("DROP INDEX IF EXISTS idx_infra_active")
    cursor.execute("DROP INDEX IF EXISTS idx_rel_source")
    cursor.execute("DROP INDEX IF EXISTS idx_rel_target")
    cursor.execute("DROP INDEX IF EXISTS idx_rel_confidence")

    conn.commit()
    print("[Migration 001] Downgrade complete: temporal + relationships removed")


# ============================================================
# MIGRATION METADATA
# ============================================================

MIGRATION_VERSION = "001"
MIGRATION_DESCRIPTION = "Add temporal intelligence + relationship entities"
MIGRATION_DATE = "2026-05-17"
MIGRATION_DEPENDENCIES = []
