"""
tests/test_phase_a_auth.py - Tests cho Phase A: Auth + phân quyền.
"""

import unittest
import tempfile
import os
from pathlib import Path
from auth import AuthDB, AuthService, Role, SessionToken, init_auth_service


class TestAuthDB(unittest.TestCase):
    """Tests cho AuthDB."""

    def setUp(self):
        """Khởi tạo temp DB cho mỗi test."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "auth_test.db")
        self.db = AuthDB(self.db_path)
        self.db.init_db()

    def tearDown(self):
        """Dọn dẹp."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_create_user(self):
        """Test tạo user."""
        password_hash = b"hashed_password"
        user_id = self.db.create_user("testuser", password_hash, Role.VIEWER)

        self.assertIsNotNone(user_id)
        self.assertTrue(self.db.user_exists("testuser"))

    def test_get_user_by_username(self):
        """Test lấy user theo username."""
        password_hash = b"hashed_password"
        self.db.create_user("alice", password_hash, Role.ADMIN)

        user = self.db.get_user_by_username("alice")

        self.assertIsNotNone(user)
        self.assertEqual(user.username, "alice")
        self.assertEqual(user.role, Role.ADMIN)

    def test_admin_exists(self):
        """Test kiểm tra admin tồn tại."""
        self.assertFalse(self.db.admin_exists())

        password_hash = b"hashed_password"
        self.db.create_user("admin_user", password_hash, Role.ADMIN)

        self.assertTrue(self.db.admin_exists())

    def test_create_schedule(self):
        """Test tạo schedule."""
        password_hash = b"hashed_password"
        user_id = self.db.create_user("admin", password_hash, Role.ADMIN)

        schedule_id = self.db.create_schedule(
            "daily-cve", "06:00", "HIGH", user_id
        )

        self.assertIsNotNone(schedule_id)

        schedule = self.db.get_schedule(schedule_id)
        self.assertIsNotNone(schedule)
        self.assertEqual(schedule.name, "daily-cve")
        self.assertEqual(schedule.time_of_day, "06:00")

    def test_audit_log(self):
        """Test audit log."""
        password_hash = b"hashed_password"
        user_id = self.db.create_user("testuser", password_hash, Role.VIEWER)

        self.db.add_audit_entry(user_id, "login")
        self.db.add_audit_entry(user_id, "search", "CVE-2024-1234")

        entries = self.db.get_audit_log(user_id=user_id)

        self.assertEqual(len(entries), 2)
        # Check both entries exist regardless of order
        actions = {entry.action for entry in entries}
        self.assertEqual(actions, {"login", "search"})
        # Check search entry has resource
        search_entries = [e for e in entries if e.action == "search"]
        self.assertEqual(len(search_entries), 1)
        self.assertEqual(search_entries[0].resource, "CVE-2024-1234")


class TestAuthService(unittest.TestCase):
    """Tests cho AuthService."""

    def setUp(self):
        """Khởi tạo temp DB + AuthService."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "auth_test.db")
        self.db = AuthDB(self.db_path)
        self.db.init_db()

        # Mock SESSION_SECRET
        os.environ["SESSION_SECRET"] = "a" * 32

        self.auth_service = AuthService(self.db)

    def tearDown(self):
        """Dọn dẹp."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
        # Xóa session file
        session_file = self.auth_service._get_session_file_path()
        if session_file.exists():
            session_file.unlink()

    def test_hash_and_verify_password(self):
        """Test hash + verify password."""
        password = "my_secure_password"
        password_hash = self.auth_service.hash_password(password)

        self.assertTrue(self.auth_service.verify_password(password, password_hash))
        self.assertFalse(self.auth_service.verify_password("wrong_password", password_hash))

    def test_login_success(self):
        """Test login thành công."""
        username = "testuser"
        password = "test123456"

        password_hash = self.auth_service.hash_password(password)
        self.db.create_user(username, password_hash, Role.VIEWER)

        success, token, msg = self.auth_service.login(username, password)

        self.assertTrue(success)
        self.assertIsNotNone(token)
        self.assertEqual(token.user_id, 1)
        self.assertEqual(token.role, Role.VIEWER)

    def test_login_wrong_password(self):
        """Test login với mật khẩu sai."""
        username = "testuser"
        password = "test123456"

        password_hash = self.auth_service.hash_password(password)
        self.db.create_user(username, password_hash, Role.VIEWER)

        success, token, msg = self.auth_service.login(username, "wrong_password")

        self.assertFalse(success)
        self.assertIsNone(token)

    def test_login_nonexistent_user(self):
        """Test login với user không tồn tại."""
        success, token, msg = self.auth_service.login("nonexistent", "password")

        self.assertFalse(success)
        self.assertIsNone(token)

    def test_session_token_creation_and_verification(self):
        """Test tạo và verify token."""
        from datetime import datetime, timedelta
        user_id = 42
        role = Role.ADMIN
        expires_at = datetime.utcnow() + timedelta(hours=8)

        token = self.auth_service._create_token(user_id, role, expires_at)

        self.assertIsNotNone(token.token)
        self.assertIn(".", token.token)

        # Verify token
        verified = self.auth_service._verify_token(token.token)

        self.assertIsNotNone(verified)
        self.assertEqual(verified.user_id, user_id)
        self.assertEqual(verified.role, role)

    def test_token_tamper_detection(self):
        """Test phát hiện token bị sửa."""
        from datetime import datetime, timedelta
        user_id = 42
        role = Role.ADMIN
        expires_at = datetime.utcnow() + timedelta(hours=8)

        token = self.auth_service._create_token(user_id, role, expires_at)

        # Sửa token (thay đổi user_id trong payload)
        parts = token.token.split(".")
        if len(parts) == 2:
            tampered_token = "X" + parts[0] + "." + parts[1]

            verified = self.auth_service._verify_token(tampered_token)

            self.assertIsNone(verified)

    def test_session_persistence(self):
        """Test lưu/đọc session file."""
        from datetime import datetime, timedelta

        token = self.auth_service._create_token(1, Role.VIEWER, datetime.utcnow() + timedelta(hours=8))
        self.auth_service._save_session_file(token)

        # Đọc lại
        session = self.auth_service.get_current_session()

        self.assertIsNotNone(session)
        self.assertEqual(session.user_id, 1)
        self.assertEqual(session.role, Role.VIEWER)

    def test_logout(self):
        """Test đăng xuất."""
        from datetime import datetime, timedelta

        token = self.auth_service._create_token(1, Role.VIEWER, datetime.utcnow() + timedelta(hours=8))
        self.auth_service._save_session_file(token)

        self.auth_service.logout()

        session = self.auth_service.get_current_session()
        self.assertIsNone(session)


def run_tests():
    """Chạy tất cả tests."""
    suite = unittest.TestLoader().loadTestsFromModule(__import__(__name__))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    import sys
    print("[PHASE A: AUTH + PHÂN QUYỀN TEST SUITE]")
    print("=" * 60)
    success = run_tests()
    print("\n" + "=" * 60)
    if success:
        print("[OK] Tất cả Phase A tests passed!")
    else:
        print("[FAILED] Một số tests failed")
    sys.exit(0 if success else 1)
