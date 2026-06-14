"""
cli/permission.py - Decorator @require_role để kiểm soát truy cập.
"""

from functools import wraps
from typing import Callable, Union, List
from auth import Role, get_auth_service


def require_role(required_roles: Union[Role, List[Role]]) -> Callable:
    """Decorator: chỉ cho phép role cụ thể chạy hàm.

    Args:
        required_roles: Role hoặc list[Role] được phép

    Returns:
        Hàm decorator
    """
    if isinstance(required_roles, Role):
        required_roles = [required_roles]

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            auth_service = get_auth_service()
            session = auth_service.get_current_session()

            if not session:
                print("[LỖI] Chưa đăng nhập. Chạy: python main.py login")
                return None

            if session.role not in required_roles:
                roles_str = ", ".join([r.value for r in required_roles])
                print(f"[LỖI] Quyền từ chối. Yêu cầu: {roles_str}, hiện có: {session.role.value}")
                auth_service.db.add_audit_entry(session.user_id, "permission_denied", func.__name__)
                return None

            return func(*args, **kwargs)

        return wrapper

    return decorator
