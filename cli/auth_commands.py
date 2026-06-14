"""
cli/auth_commands.py - CLI commands cho xác thực: init-admin, login, logout, whoami, etc.
"""

import sys
from getpass import getpass
from typing import Optional
from auth import AuthDB, AuthService, Role, get_auth_service
from .permission import require_role


def cmd_init_admin(db: AuthDB, auth_service: AuthService) -> bool:
    """Khởi tạo admin lần đầu. Chỉ chạy được 1 lần."""
    if db.admin_exists():
        print("[LỖI] Admin đã tồn tại. Bạn không thể tạo admin mới.")
        return False

    print("=== Khởi tạo Admin ===")
    username = input("Tên user admin: ").strip()

    if not username:
        print("[LỖI] Tên user không được trống")
        return False

    if db.user_exists(username):
        print(f"[LỖI] User '{username}' đã tồn tại")
        return False

    password = getpass("Mật khẩu: ")
    confirm = getpass("Xác nhận mật khẩu: ")

    if password != confirm:
        print("[LỖI] Mật khẩu không khớp")
        return False

    if len(password) < 6:
        print("[LỖI] Mật khẩu phải >= 6 ký tự")
        return False

    password_hash = auth_service.hash_password(password)
    user_id = db.create_user(username, password_hash, Role.ADMIN)

    print(f"[OK] Admin '{username}' (ID={user_id}) đã tạo")
    db.add_audit_entry(user_id, "init_admin")
    return True


def cmd_login(db: AuthDB, auth_service: AuthService) -> bool:
    """Đăng nhập."""
    session = auth_service.get_current_session()

    if session:
        print(f"[THÔNG BÁO] Bạn đã đăng nhập với user '{session.user_id}' (role: {session.role.value})")
        print("Chạy 'python main.py logout' để thoát")
        return True

    username = input("Tên user: ").strip()
    password = getpass("Mật khẩu: ")

    success, token, msg = auth_service.login(username, password)

    if success:
        print(f"[OK] {msg}")
        return True
    else:
        print(f"[LỖI] {msg}")
        return False


def cmd_logout(auth_service: AuthService) -> bool:
    """Đăng xuất."""
    session = auth_service.get_current_session()

    if not session:
        print("[THÔNG BÁO] Bạn chưa đăng nhập")
        return True

    auth_service.logout()
    print(f"[OK] Đã đăng xuất user {session.user_id}")
    return True


def cmd_whoami(auth_service: AuthService) -> bool:
    """In thông tin user hiện tại."""
    session = auth_service.get_current_session()

    if not session:
        print("[THÔNG BÁO] Chưa đăng nhập. Chạy: python main.py login")
        return False

    user = auth_service.db.get_user_by_username(
        next((u.username for u in auth_service.db.get_all_users() if u.id == session.user_id), "?")
    )

    if user:
        print(f"User: {user.username}")
        print(f"ID: {user.id}")
        print(f"Role: {user.role.value}")
        print(f"Tạo lúc: {user.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        if user.last_login:
            print(f"Login cuối: {user.last_login.strftime('%Y-%m-%d %H:%M:%S')}")

    return True


@require_role(Role.ADMIN)
def cmd_create_user(db: AuthDB, auth_service: AuthService) -> bool:
    """Tạo user mới (admin only)."""
    session = auth_service.get_current_session()
    if not session:
        return False

    print("=== Tạo User Mới ===")
    username = input("Tên user: ").strip()

    if not username:
        print("[LỖI] Tên user không được trống")
        return False

    if db.user_exists(username):
        print(f"[LỖI] User '{username}' đã tồn tại")
        return False

    role_input = input("Role (viewer/admin) [default: viewer]: ").strip().lower()
    role = Role.ADMIN if role_input == "admin" else Role.VIEWER

    password = getpass("Mật khẩu: ")
    confirm = getpass("Xác nhận mật khẩu: ")

    if password != confirm:
        print("[LỖI] Mật khẩu không khớp")
        return False

    if len(password) < 6:
        print("[LỖI] Mật khẩu phải >= 6 ký tự")
        return False

    password_hash = auth_service.hash_password(password)
    user_id = db.create_user(username, password_hash, role)

    print(f"[OK] User '{username}' (ID={user_id}, role={role.value}) đã tạo")
    db.add_audit_entry(session.user_id, "create_user", username)
    return True


@require_role(Role.ADMIN)
def cmd_list_users(db: AuthDB, auth_service: AuthService) -> bool:
    """Liệt kê users (admin only)."""
    session = auth_service.get_current_session()
    if not session:
        return False

    users = db.get_all_users()

    if not users:
        print("Không có user nào")
        return True

    print("\n=== Danh sách Users ===")
    print(f"{'ID':<5} {'Username':<20} {'Role':<10} {'Tạo lúc':<20} {'Login cuối':<20}")
    print("-" * 75)

    for user in users:
        last_login = user.last_login.strftime("%Y-%m-%d %H:%M:%S") if user.last_login else "-"
        print(f"{user.id:<5} {user.username:<20} {user.role.value:<10} "
              f"{user.created_at.strftime('%Y-%m-%d %H:%M:%S'):<20} {last_login:<20}")

    print()
    return True


@require_role(Role.ADMIN)
def cmd_delete_user(db: AuthDB, auth_service: AuthService) -> bool:
    """Xóa user (admin only)."""
    session = auth_service.get_current_session()
    if not session:
        return False

    print("=== Xóa User ===")
    username = input("Tên user để xóa: ").strip()

    user = db.get_user_by_username(username)
    if not user:
        print(f"[LỖI] User '{username}' không tồn tại")
        return False

    if user.id == session.user_id:
        print("[LỖI] Không thể xóa chính mình")
        return False

    confirm = input(f"Xác nhận xóa '{username}'? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Đã hủy")
        return False

    # SQLite: không có DELETE user, chỉ UPDATE disabled flag (nếu cần)
    # Tạm thời: chỉ warn
    print(f"[THÔNG BÁO] Hiện tại không hỗ trợ xóa user. Hãy xóa trực tiếp từ DB.")
    return False
