"""
auth/db.py - Khởi tạo và migration dữ liệu auth.db.

Chạy lần đầu: init_db() → tạo bảng
"""

import sqlite3
import os
from pathlib import Path
from typing import Optional
from datetime import datetime
from .models import User, Role, Schedule, ScheduleRun, AuditEntry


class AuthDB:
    """Database adapter cho auth."""

    def __init__(self, db_path: str = "data/auth.db"):
        """Khởi tạo kết nối DB."""
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    def init_db(self):
        """Khởi tạo schema lần đầu."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash BLOB NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'viewer')),
                created_at TEXT NOT NULL,
                last_login TEXT,
                session_secret BLOB
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                time_of_day TEXT NOT NULL,
                severity_filter TEXT DEFAULT 'HIGH',
                enabled INTEGER DEFAULT 1,
                created_by INTEGER REFERENCES users(id),
                created_at TEXT NOT NULL,
                last_run TEXT,
                last_status TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schedule_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                schedule_id INTEGER REFERENCES schedules(id),
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT,
                report_path TEXT,
                cve_count INTEGER,
                error_message TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id),
                action TEXT NOT NULL,
                resource TEXT,
                timestamp TEXT NOT NULL
            )
        """)

        conn.commit()
        conn.close()

    def get_user_by_username(self, username: str) -> Optional[User]:
        """Lấy user theo username."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password_hash, role, created_at, last_login, session_secret FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return User(
            id=row[0],
            username=row[1],
            password_hash=row[2],
            role=Role(row[3]),
            created_at=datetime.fromisoformat(row[4]),
            last_login=datetime.fromisoformat(row[5]) if row[5] else None,
            session_secret=row[6]
        )

    def create_user(self, username: str, password_hash: bytes, role: Role) -> int:
        """Tạo user mới. Trả về user_id."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()

        cursor.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, role.value, now)
        )
        user_id = cursor.lastrowid

        conn.commit()
        conn.close()
        return user_id

    def user_exists(self, username: str) -> bool:
        """Kiểm tra user tồn tại."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0

    def admin_exists(self) -> bool:
        """Kiểm tra có admin nào trong hệ thống chưa."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0

    def update_last_login(self, user_id: int):
        """Cập nhật lần login cuối."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, user_id))
        conn.commit()
        conn.close()

    def get_all_users(self) -> list[User]:
        """Lấy danh sách tất cả user."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password_hash, role, created_at, last_login, session_secret FROM users ORDER BY created_at DESC"
        )
        rows = cursor.fetchall()
        conn.close()

        users = []
        for row in rows:
            users.append(User(
                id=row[0],
                username=row[1],
                password_hash=row[2],
                role=Role(row[3]),
                created_at=datetime.fromisoformat(row[4]),
                last_login=datetime.fromisoformat(row[5]) if row[5] else None,
                session_secret=row[6]
            ))
        return users

    def create_schedule(self, name: str, time_of_day: str, severity_filter: str, created_by: int) -> int:
        """Tạo schedule mới."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()

        cursor.execute(
            "INSERT INTO schedules (name, time_of_day, severity_filter, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
            (name, time_of_day, severity_filter, created_by, now)
        )
        schedule_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return schedule_id

    def get_schedule(self, schedule_id: int) -> Optional[Schedule]:
        """Lấy schedule theo ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, time_of_day, severity_filter, enabled, created_by, created_at, last_run, last_status FROM schedules WHERE id = ?",
            (schedule_id,)
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return Schedule(
            id=row[0],
            name=row[1],
            time_of_day=row[2],
            severity_filter=row[3],
            enabled=bool(row[4]),
            created_by=row[5],
            created_at=datetime.fromisoformat(row[6]),
            last_run=datetime.fromisoformat(row[7]) if row[7] else None,
            last_status=row[8]
        )

    def get_all_schedules(self, enabled_only: bool = False) -> list[Schedule]:
        """Lấy danh sách schedule."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if enabled_only:
            cursor.execute(
                "SELECT id, name, time_of_day, severity_filter, enabled, created_by, created_at, last_run, last_status FROM schedules WHERE enabled = 1 ORDER BY time_of_day"
            )
        else:
            cursor.execute(
                "SELECT id, name, time_of_day, severity_filter, enabled, created_by, created_at, last_run, last_status FROM schedules ORDER BY time_of_day"
            )

        rows = cursor.fetchall()
        conn.close()

        schedules = []
        for row in rows:
            schedules.append(Schedule(
                id=row[0],
                name=row[1],
                time_of_day=row[2],
                severity_filter=row[3],
                enabled=bool(row[4]),
                created_by=row[5],
                created_at=datetime.fromisoformat(row[6]),
                last_run=datetime.fromisoformat(row[7]) if row[7] else None,
                last_status=row[8]
            ))
        return schedules

    def update_schedule_status(self, schedule_id: int, last_run: datetime, last_status: str):
        """Cập nhật trạng thái sau khi chạy schedule."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE schedules SET last_run = ?, last_status = ? WHERE id = ?",
            (last_run.isoformat(), last_status, schedule_id)
        )
        conn.commit()
        conn.close()

    def toggle_schedule(self, schedule_id: int, enabled: bool):
        """Bật/tắt schedule."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE schedules SET enabled = ? WHERE id = ?",
            (int(enabled), schedule_id)
        )
        conn.commit()
        conn.close()

    def delete_schedule(self, schedule_id: int):
        """Xóa schedule."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
        conn.commit()
        conn.close()

    def create_schedule_run(self, schedule_id: int) -> int:
        """Tạo mục ghi schedule run, trả về run_id."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()

        cursor.execute(
            "INSERT INTO schedule_runs (schedule_id, started_at, status) VALUES (?, ?, ?)",
            (schedule_id, now, "running")
        )
        run_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return run_id

    def update_schedule_run(self, run_id: int, status: str, cve_count: Optional[int] = None,
                          report_path: Optional[str] = None, error_message: Optional[str] = None):
        """Cập nhật kết quả schedule run."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()

        cursor.execute(
            "UPDATE schedule_runs SET status = ?, cve_count = ?, report_path = ?, error_message = ?, finished_at = ? WHERE id = ?",
            (status, cve_count, report_path, error_message, now, run_id)
        )
        conn.commit()
        conn.close()

    def get_schedule_runs(self, schedule_id: int, limit: int = 10) -> list[ScheduleRun]:
        """Lấy lịch sử chạy schedule."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, schedule_id, started_at, finished_at, status, cve_count, report_path, error_message
               FROM schedule_runs WHERE schedule_id = ? ORDER BY started_at DESC LIMIT ?""",
            (schedule_id, limit)
        )
        rows = cursor.fetchall()
        conn.close()

        runs = []
        for row in rows:
            runs.append(ScheduleRun(
                id=row[0],
                schedule_id=row[1],
                started_at=datetime.fromisoformat(row[2]),
                finished_at=datetime.fromisoformat(row[3]) if row[3] else None,
                status=row[4],
                cve_count=row[5],
                report_path=row[6],
                error_message=row[7]
            ))
        return runs

    def add_audit_entry(self, user_id: int, action: str, resource: Optional[str] = None):
        """Thêm mục audit log."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()

        cursor.execute(
            "INSERT INTO audit_log (user_id, action, resource, timestamp) VALUES (?, ?, ?, ?)",
            (user_id, action, resource, now)
        )
        conn.commit()
        conn.close()

    def get_audit_log(self, limit: int = 100, user_id: Optional[int] = None) -> list[AuditEntry]:
        """Lấy audit log."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                "SELECT id, user_id, action, resource, timestamp FROM audit_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?",
                (user_id, limit)
            )
        else:
            cursor.execute(
                "SELECT id, user_id, action, resource, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )

        rows = cursor.fetchall()
        conn.close()

        entries = []
        for row in rows:
            entries.append(AuditEntry(
                id=row[0],
                user_id=row[1],
                action=row[2],
                resource=row[3],
                timestamp=datetime.fromisoformat(row[4])
            ))
        return entries
