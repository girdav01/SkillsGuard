"""Role-based access control (RBAC) for SkillGuard API.

Provides user authentication and authorization with configurable
roles and permissions for API endpoints.
"""

from __future__ import annotations

from enum import Enum
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class Role(str, Enum):
    """User roles with different permission levels."""

    ADMIN = "admin"
    ANALYST = "analyst"
    DEVELOPER = "developer"
    VIEWER = "viewer"


class Permission(str, Enum):
    """Granular permissions for API actions."""

    SCAN_SUBMIT = "scan:submit"
    SCAN_READ = "scan:read"
    RULES_READ = "rules:read"
    RULES_WRITE = "rules:write"
    POLICY_READ = "policy:read"
    POLICY_WRITE = "policy:write"
    MONITOR_READ = "monitor:read"
    MONITOR_WRITE = "monitor:write"
    SKILL_READ = "skill:read"
    AUDIT_READ = "audit:read"
    ADMIN_ALL = "admin:*"


# Default role-to-permission mappings
_ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.ADMIN: {p for p in Permission},
    Role.ANALYST: {
        Permission.SCAN_SUBMIT,
        Permission.SCAN_READ,
        Permission.RULES_READ,
        Permission.RULES_WRITE,
        Permission.POLICY_READ,
        Permission.MONITOR_READ,
        Permission.MONITOR_WRITE,
        Permission.SKILL_READ,
        Permission.AUDIT_READ,
    },
    Role.DEVELOPER: {
        Permission.SCAN_SUBMIT,
        Permission.SCAN_READ,
        Permission.RULES_READ,
        Permission.SKILL_READ,
        Permission.MONITOR_READ,
    },
    Role.VIEWER: {
        Permission.SCAN_READ,
        Permission.RULES_READ,
        Permission.SKILL_READ,
    },
}


class User(BaseModel):
    """A SkillGuard user."""

    id: str
    username: str
    role: Role
    api_key: str | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    active: bool = True


class RBACManager:
    """Manages users, roles, and permission checks.

    Provides a simple in-memory RBAC system for the API.
    Can be extended with database persistence.
    """

    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._api_keys: dict[str, str] = {}  # api_key -> user_id

    def add_user(self, user: User) -> None:
        """Register a new user."""
        self._users[user.id] = user
        if user.api_key:
            self._api_keys[user.api_key] = user.id

    def remove_user(self, user_id: str) -> bool:
        """Remove a user by ID."""
        user = self._users.pop(user_id, None)
        if user is None:
            return False
        if user.api_key:
            self._api_keys.pop(user.api_key, None)
        return True

    def get_user(self, user_id: str) -> User | None:
        """Get a user by ID."""
        return self._users.get(user_id)

    def get_user_by_api_key(self, api_key: str) -> User | None:
        """Authenticate a user by API key."""
        user_id = self._api_keys.get(api_key)
        if user_id is None:
            return None
        user = self._users.get(user_id)
        if user and user.active:
            return user
        return None

    def check_permission(self, user_id: str, permission: Permission) -> bool:
        """Check if a user has a specific permission."""
        user = self._users.get(user_id)
        if user is None or not user.active:
            return False

        user_permissions = _ROLE_PERMISSIONS.get(user.role, set())

        # Admin has all permissions
        if Permission.ADMIN_ALL in user_permissions:
            return True

        return permission in user_permissions

    def get_user_permissions(self, user_id: str) -> set[Permission]:
        """Get all permissions for a user."""
        user = self._users.get(user_id)
        if user is None or not user.active:
            return set()
        return _ROLE_PERMISSIONS.get(user.role, set()).copy()

    def list_users(self) -> list[User]:
        """List all registered users."""
        return list(self._users.values())
