"""
auth/service.py - Dịch vụ xác thực: hash/verify password, session management.
"""

import bcrypt
import json
import hmac
import hashlib
import secrets
import base64
import os
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Tuple
from .models import User, Role, SessionToken
from .db import AuthDB


class AuthService:
    """Dịch vụ xác thực."""

    def __init__(self, db: AuthDB, session_ttl_minutes: int = 15, activity_timeout_minutes: int = 15):
        """Khởi tạo auth service.

        Args:
            db: Kết nối AuthDB
            session_ttl_minutes: Thời hạn session (phút, mặc định 15)
            activity_timeout_minutes: Timeout không hoạt động (phút, mặc định 15)
        """
        self.db = db
        self.session_ttl = timedelta(minutes=session_ttl_minutes)
        self.activity_timeout = timedelta(minutes=activity_timeout_minutes)
        self.session_secret = os.getenv("SESSION_SECRET", "").encode()

        if not self.session_secret or len(self.session_secret) < 32:
            raise ValueError("SESSION_SECRET phải được set trong .env và dài >= 32 ký tự")

    def hash_password(self, password: str) -> bytes:
        """Hash password dùng bcrypt (cost=12)."""
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))

    def verify_password(self, password: str, password_hash: bytes) -> bool:
        """Kiểm tra password."""
        return bcrypt.checkpw(password.encode("utf-8"), password_hash)

    def login(self, username: str, password: str) -> Tuple[bool, Optional[SessionToken], str]:
        """Login: kiểm tra cred, sinh token, lưu session file.

        Returns:
            (success, token, message)
        """
        user = self.db.get_user_by_username(username)

        if not user:
            return False, None, f"User '{username}' không tồn tại"

        if not self.verify_password(password, user.password_hash):
            return False, None, "Mật khẩu sai"

        # Sinh token
        expires_at = datetime.utcnow() + self.session_ttl
        token = self._create_token(user.id, user.role, expires_at)

        # Lưu session file
        self._save_session_file(token)

        # Update last_login
        self.db.update_last_login(user.id)

        # Audit log
        self.db.add_audit_entry(user.id, "login")

        return True, token, "Đăng nhập thành công"

    def get_current_session(self) -> Optional[SessionToken]:
        """Đọc session từ file, verify, check expiry và activity timeout."""
        session_file = self._get_session_file_path()

        if not session_file.exists():
            return None

        try:
            with open(session_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            token_str = data.get("token")
            if not token_str:
                return None

            token = self._verify_token(token_str)
            if not token:
                return None

            # Check token expiry
            if datetime.fromisoformat(token.expires_at.isoformat()) < datetime.utcnow():
                self.logout()
                return None

            # Check activity timeout (from session file timestamp)
            last_activity_str = data.get("last_activity")
            if last_activity_str:
                last_activity = datetime.fromisoformat(last_activity_str)
                if datetime.utcnow() - last_activity > self.activity_timeout:
                    self.logout()
                    return None

            return token

        except Exception:
            return None

    def logout(self):
        """Xóa session file."""
        session_file = self._get_session_file_path()
        if session_file.exists():
            session_file.unlink()

    def update_activity_timestamp(self):
        """Cập nhật thời gian hoạt động cuối cùng."""
        session_file = self._get_session_file_path()

        if not session_file.exists():
            return

        try:
            with open(session_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            data["last_activity"] = datetime.utcnow().isoformat()

            with open(session_file, "w", encoding="utf-8") as f:
                json.dump(data, f)

        except Exception:
            pass

    def get_session_time_remaining(self) -> Optional[dict]:
        """Lấy thời gian còn lại của session.

        Returns: {
            "total_ttl_minutes": 15,
            "time_remaining_minutes": 10,
            "expires_at": "2026-06-15T12:25:00",
            "last_activity": "2026-06-15T12:10:00"
        }
        """
        session_file = self._get_session_file_path()

        if not session_file.exists():
            return None

        try:
            with open(session_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            token_str = data.get("token")
            if not token_str:
                return None

            token = self._verify_token(token_str)
            if not token:
                return None

            expires_at = datetime.fromisoformat(token.expires_at.isoformat())
            last_activity_str = data.get("last_activity")
            last_activity = datetime.fromisoformat(last_activity_str) if last_activity_str else None

            now = datetime.utcnow()
            time_remaining = expires_at - now

            return {
                "total_ttl_minutes": int(self.session_ttl.total_seconds() / 60),
                "time_remaining_minutes": max(0, int(time_remaining.total_seconds() / 60)),
                "expires_at": expires_at.isoformat(),
                "last_activity": last_activity.isoformat() if last_activity else None
            }

        except Exception:
            return None

    def _create_token(self, user_id: int, role: Role, expires_at: datetime) -> SessionToken:
        """Tạo token với HMAC signature."""
        payload = {
            "user_id": user_id,
            "role": role.value,
            "expires_at": expires_at.isoformat(),
            "last_activity": datetime.utcnow().isoformat()
        }
        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        payload_b64 = base64.b64encode(payload_json.encode()).decode()

        # HMAC signature
        signature = hmac.new(
            self.session_secret,
            payload_b64.encode(),
            hashlib.sha256
        ).hexdigest()

        token_str = f"{payload_b64}.{signature}"

        return SessionToken(
            user_id=user_id,
            role=role,
            expires_at=expires_at,
            token=token_str
        )

    def _verify_token(self, token_str: str) -> Optional[SessionToken]:
        """Verify token HMAC."""
        try:
            parts = token_str.split(".")
            if len(parts) != 2:
                return None

            payload_b64, signature = parts

            # Verify HMAC
            expected_signature = hmac.new(
                self.session_secret,
                payload_b64.encode(),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(signature, expected_signature):
                return None

            # Decode payload
            payload_json = base64.b64decode(payload_b64).decode()
            payload = json.loads(payload_json)

            expires_at = datetime.fromisoformat(payload["expires_at"])

            return SessionToken(
                user_id=payload["user_id"],
                role=Role(payload["role"]),
                expires_at=expires_at,
                token=token_str
            )

        except Exception:
            return None

    def _save_session_file(self, token: SessionToken):
        """Lưu token vào session file."""
        session_file = self._get_session_file_path()
        session_file.parent.mkdir(parents=True, exist_ok=True)

        data = {"token": token.token}
        with open(session_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        # Chỉ owner đọc được
        if os.name != "nt":  # Không phải Windows
            os.chmod(session_file, 0o600)

    @staticmethod
    def _get_session_file_path() -> Path:
        """Lấy đường dẫn session file."""
        if os.name == "nt":  # Windows
            session_dir = Path.home() / ".ati"
        else:
            session_dir = Path.home() / ".ati"

        return session_dir / "session.json"


# Singleton instance
_auth_service: Optional[AuthService] = None


def init_auth_service(db: AuthDB, session_ttl_minutes: int = 15, activity_timeout_minutes: int = 15) -> AuthService:
    """Khởi tạo global auth service."""
    global _auth_service
    _auth_service = AuthService(db, session_ttl_minutes, activity_timeout_minutes)
    return _auth_service


def get_auth_service() -> AuthService:
    """Lấy global auth service."""
    if _auth_service is None:
        raise RuntimeError("Auth service chưa được khởi tạo")
    return _auth_service
