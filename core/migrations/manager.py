"""
core/migrations/manager.py - Migration Manager

Handles database schema versioning and migration execution.
"""

import sqlite3
from typing import List, Dict, Any
from pathlib import Path
import importlib


class MigrationManager:
    """Manage database migrations."""

    def __init__(self, db_path: str):
        """Initialize migration manager."""
        self.db_path = db_path

    def init_migrations_table(self, conn: sqlite3.Connection) -> None:
        """Create migrations tracking table if not exists."""
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS _migrations (
                version TEXT PRIMARY KEY,
                description TEXT,
                applied_at TEXT,
                status TEXT
            )
        """)
        conn.commit()

    def get_applied_migrations(self, conn: sqlite3.Connection) -> List[str]:
        """Get list of applied migrations."""
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT version FROM _migrations WHERE status='applied' ORDER BY version")
            return [row[0] for row in cursor.fetchall()]
        except sqlite3.OperationalError:
            # Table doesn't exist yet
            return []

    def apply_migration(self, conn: sqlite3.Connection, version: str) -> bool:
        """
        Apply a migration.

        Args:
            conn: Database connection
            version: Migration version (e.g., "001")

        Returns:
            True if successful
        """
        try:
            # Import migration module
            module = importlib.import_module(f"core.migrations.migration_{version}")

            # Run upgrade
            module.upgrade(conn)

            # Record migration
            cursor = conn.cursor()
            from datetime import datetime
            cursor.execute("""
                INSERT OR REPLACE INTO _migrations
                (version, description, applied_at, status)
                VALUES (?, ?, ?, ?)
            """, (
                version,
                getattr(module, "MIGRATION_DESCRIPTION", ""),
                datetime.utcnow().isoformat(),
                "applied"
            ))
            conn.commit()

            return True
        except Exception as e:
            print(f"[Migration] Error applying {version}: {e}")
            return False

    def rollback_migration(self, conn: sqlite3.Connection, version: str) -> bool:
        """
        Rollback a migration.

        Args:
            conn: Database connection
            version: Migration version

        Returns:
            True if successful
        """
        try:
            # Import migration module
            module = importlib.import_module(f"core.migrations.migration_{version}")

            # Run downgrade
            module.downgrade(conn)

            # Remove migration record
            cursor = conn.cursor()
            cursor.execute("DELETE FROM _migrations WHERE version=?", (version,))
            conn.commit()

            return True
        except Exception as e:
            print(f"[Migration] Error rolling back {version}: {e}")
            return False

    def get_pending_migrations(self) -> List[str]:
        """
        Get list of pending migrations to apply.

        Returns:
            List of migration versions
        """
        # Check migrations directory
        migrations_dir = Path(__file__).parent
        migration_files = sorted([
            f.stem.replace("migration_", "")
            for f in migrations_dir.glob("migration_*.py")
        ])
        return migration_files

    def migrate_to_latest(self, conn: sqlite3.Connection) -> bool:
        """
        Apply all pending migrations in order.

        Args:
            conn: Database connection

        Returns:
            True if all successful
        """
        self.init_migrations_table(conn)

        applied = self.get_applied_migrations(conn)
        pending = self.get_pending_migrations()

        success = True
        for version in pending:
            if version not in applied:
                print(f"[Migration] Applying {version}...")
                if self.apply_migration(conn, version):
                    print(f"[Migration] Applied {version}")
                else:
                    print(f"[Migration] Failed to apply {version}")
                    success = False
                    break

        return success
