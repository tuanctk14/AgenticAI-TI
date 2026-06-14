"""
cli - Gói CLI commands.
"""

from . import auth_commands
from .permission import require_role

__all__ = ["auth_commands", "require_role"]
