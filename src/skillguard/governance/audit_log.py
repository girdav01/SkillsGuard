"""Immutable audit trail for SkillGuard actions.

Records all significant actions (scans, policy decisions, user actions)
in an append-only log for compliance and forensics.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class AuditEntry(BaseModel):
    """A single audit log entry."""

    id: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    action: str  # scan_submitted, scan_completed, policy_evaluated, rule_changed, etc.
    actor: str = "system"  # user_id or "system"
    resource_type: str = ""  # scan, skill, rule, policy
    resource_id: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    result: str = ""  # success, failure, blocked
    integrity_hash: str = ""


class AuditLog:
    """Append-only audit log with integrity verification.

    Maintains an ordered, tamper-evident log of all significant
    actions in the system. Each entry includes an integrity hash
    that chains to the previous entry.
    """

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._last_hash: str = "genesis"

    async def log(
        self,
        action: str,
        actor: str = "system",
        resource_type: str = "",
        resource_id: str = "",
        details: dict[str, Any] | None = None,
        result: str = "success",
    ) -> AuditEntry:
        """Record an action in the audit log."""
        entry = AuditEntry(
            id=f"audit-{len(self._entries) + 1:06d}",
            action=action,
            actor=actor,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            result=result,
        )

        # Compute integrity hash (chained to previous entry)
        hash_input = f"{self._last_hash}|{entry.timestamp}|{entry.action}|{entry.actor}|{entry.resource_id}"
        entry.integrity_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:32]
        self._last_hash = entry.integrity_hash

        self._entries.append(entry)
        return entry

    async def query(
        self,
        action: str | None = None,
        actor: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Query the audit log with optional filters."""
        results = self._entries

        if action:
            results = [e for e in results if e.action == action]
        if actor:
            results = [e for e in results if e.actor == actor]
        if resource_type:
            results = [e for e in results if e.resource_type == resource_type]
        if resource_id:
            results = [e for e in results if e.resource_id == resource_id]

        # Return newest first
        results = list(reversed(results))
        return results[offset : offset + limit]

    async def verify_integrity(self) -> tuple[bool, int]:
        """Verify the integrity of the entire audit log.

        Returns:
            Tuple of (is_valid, last_valid_index).
        """
        if not self._entries:
            return True, 0

        prev_hash = "genesis"
        for i, entry in enumerate(self._entries):
            hash_input = f"{prev_hash}|{entry.timestamp}|{entry.action}|{entry.actor}|{entry.resource_id}"
            expected = hashlib.sha256(hash_input.encode()).hexdigest()[:32]
            if entry.integrity_hash != expected:
                return False, i
            prev_hash = entry.integrity_hash

        return True, len(self._entries)

    async def count(self) -> int:
        """Return the total number of audit entries."""
        return len(self._entries)

    async def export_json(self) -> str:
        """Export the full audit log as JSON."""
        return json.dumps(
            [entry.model_dump() for entry in self._entries],
            indent=2,
            default=str,
        )
