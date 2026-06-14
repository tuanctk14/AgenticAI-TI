"""
auth/models.py - Mô hình dữ liệu cho xác thực và quản lý người dùng.

Định nghĩa: User, Role enum, Schedule, ScheduleRun, AuditEntry
"""

from enum import Enum
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


class Role(str, Enum):
    """Vai trò người dùng trong hệ thống."""
    ADMIN = "admin"
    VIEWER = "viewer"


@dataclass
class User:
    """Thông tin người dùng."""
    id: int
    username: str
    password_hash: bytes
    role: Role
    created_at: datetime
    last_login: Optional[datetime] = None
    session_secret: Optional[bytes] = None


@dataclass
class Schedule:
    """Lịch báo cáo tự động."""
    id: int
    name: str
    time_of_day: str  # HH:MM (24h)
    severity_filter: str  # HIGH/CRITICAL/MEDIUM/ALL
    enabled: bool
    created_by: int  # user_id
    created_at: datetime
    last_run: Optional[datetime] = None
    last_status: Optional[str] = None  # success/failed


@dataclass
class ScheduleRun:
    """Bản ghi một lần chạy schedule."""
    id: int
    schedule_id: int
    started_at: datetime
    status: str  # success/failed/running
    cve_count: Optional[int] = None
    report_path: Optional[str] = None
    error_message: Optional[str] = None
    finished_at: Optional[datetime] = None


@dataclass
class AuditEntry:
    """Mục nhập audit log."""
    id: int
    user_id: int
    action: str
    resource: Optional[str]
    timestamp: datetime


@dataclass
class SessionToken:
    """Token session đã parse."""
    user_id: int
    role: Role
    expires_at: datetime
    token: str
