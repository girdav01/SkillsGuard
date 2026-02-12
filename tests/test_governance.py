"""Tests for governance layer: policy engine, RBAC, and audit log."""

from __future__ import annotations

from datetime import datetime

import pytest

from skillguard.core.models import (
    EngineResult,
    EngineVerdict,
    ScanResult,
    SkillPlatform,
    Verdict,
)
from skillguard.governance.policy_engine import PolicyEngine, PolicyRule
from skillguard.governance.rbac import Permission, RBACManager, Role, User
from skillguard.governance.audit_log import AuditLog


# ── Helper to build a minimal ScanResult ─────────────────────────────

def _make_result(
    verdict: str = "clean",
    score: int = 10,
    findings_by_severity: dict | None = None,
    owasp: list[str] | None = None,
) -> ScanResult:
    return ScanResult(
        scan_id="test-001",
        skill_name="test-skill",
        skill_sha256="abcdef1234567890",
        platform=SkillPlatform.GENERIC,
        scan_started=datetime(2025, 1, 1),
        scan_completed=datetime(2025, 1, 1),
        composite_score=score,
        verdict=Verdict(verdict),
        engine_results=[],
        total_findings=0,
        findings_by_severity=findings_by_severity or {},
        files_scanned=1,
        owasp_coverage=owasp or [],
    )


# ── PolicyEngine tests ──────────────────────────────────────────────

class TestPolicyEngine:
    @pytest.fixture
    def engine(self) -> PolicyEngine:
        return PolicyEngine()

    @pytest.mark.asyncio
    async def test_clean_skill_allowed(self, engine: PolicyEngine):
        result = _make_result(verdict="clean", score=5)
        policy_result = await engine.evaluate(result)
        assert policy_result.allowed is True
        assert len(policy_result.violations) == 0

    @pytest.mark.asyncio
    async def test_malicious_blocked(self, engine: PolicyEngine):
        result = _make_result(verdict="malicious", score=95)
        policy_result = await engine.evaluate(result)
        assert policy_result.allowed is False
        assert any(v.policy_id == "POL-001" for v in policy_result.violations)

    @pytest.mark.asyncio
    async def test_high_score_blocked(self, engine: PolicyEngine):
        result = _make_result(verdict="high_risk", score=85)
        policy_result = await engine.evaluate(result)
        assert policy_result.allowed is False
        assert any(v.policy_id == "POL-005" for v in policy_result.violations)

    @pytest.mark.asyncio
    async def test_suspicious_warning(self, engine: PolicyEngine):
        result = _make_result(verdict="suspicious", score=40)
        policy_result = await engine.evaluate(result)
        assert any(w.policy_id == "POL-004" for w in policy_result.warnings)

    @pytest.mark.asyncio
    async def test_critical_findings_blocked(self, engine: PolicyEngine):
        result = _make_result(
            verdict="high_risk",
            score=70,
            findings_by_severity={"critical": 2, "high": 1},
        )
        policy_result = await engine.evaluate(result)
        assert policy_result.allowed is False
        assert any(v.policy_id == "POL-002" for v in policy_result.violations)

    @pytest.mark.asyncio
    async def test_owasp_warning(self, engine: PolicyEngine):
        result = _make_result(verdict="low_risk", score=20, owasp=["LLM01"])
        policy_result = await engine.evaluate(result)
        assert any(w.policy_id == "POL-006" for w in policy_result.warnings)

    @pytest.mark.asyncio
    async def test_add_custom_policy(self, engine: PolicyEngine):
        custom = PolicyRule(
            id="CUSTOM-001",
            name="Block Low Risk",
            action="block",
            conditions={"verdict": "low_risk"},
        )
        engine.add_policy(custom)
        result = _make_result(verdict="low_risk", score=15)
        policy_result = await engine.evaluate(result)
        assert policy_result.allowed is False

    @pytest.mark.asyncio
    async def test_remove_policy(self, engine: PolicyEngine):
        assert engine.remove_policy("POL-001") is True
        assert engine.remove_policy("NONEXISTENT") is False

    @pytest.mark.asyncio
    async def test_disabled_policy_skipped(self, engine: PolicyEngine):
        # Disable the malicious blocker
        for p in engine.list_policies():
            if p.id == "POL-001":
                p.enabled = False

        result = _make_result(verdict="malicious", score=95)
        policy_result = await engine.evaluate(result)
        # POL-001 should not trigger (disabled), but POL-005 (score>=80) still blocks
        assert not any(v.policy_id == "POL-001" for v in policy_result.violations)

    @pytest.mark.asyncio
    async def test_load_yaml_policies(self, engine: PolicyEngine):
        yaml_content = """
policies:
  - id: YAML-001
    name: Test YAML Policy
    description: Loaded from YAML
    action: warn
    conditions:
      verdict: clean
    enabled: true
"""
        count = engine.load_policies_from_yaml(yaml_content)
        assert count == 1
        assert any(p.id == "YAML-001" for p in engine.list_policies())

    @pytest.mark.asyncio
    async def test_load_invalid_yaml(self, engine: PolicyEngine):
        count = engine.load_policies_from_yaml("not: valid: yaml: [}")
        assert count == 0

    @pytest.mark.asyncio
    async def test_load_yaml_missing_policies_key(self, engine: PolicyEngine):
        count = engine.load_policies_from_yaml("rules:\n  - id: foo")
        assert count == 0

    def test_list_policies(self, engine: PolicyEngine):
        policies = engine.list_policies()
        assert len(policies) == 6  # 6 default policies
        ids = {p.id for p in policies}
        assert "POL-001" in ids
        assert "POL-006" in ids


# ── RBACManager tests ───────────────────────────────────────────────

class TestRBACManager:
    @pytest.fixture
    def manager(self) -> RBACManager:
        m = RBACManager()
        m.add_user(User(id="admin1", username="admin", role=Role.ADMIN, api_key="key-admin"))
        m.add_user(User(id="analyst1", username="analyst", role=Role.ANALYST, api_key="key-analyst"))
        m.add_user(User(id="dev1", username="developer", role=Role.DEVELOPER, api_key="key-dev"))
        m.add_user(User(id="viewer1", username="viewer", role=Role.VIEWER, api_key="key-viewer"))
        return m

    def test_get_user(self, manager: RBACManager):
        user = manager.get_user("admin1")
        assert user is not None
        assert user.username == "admin"

    def test_get_user_by_api_key(self, manager: RBACManager):
        user = manager.get_user_by_api_key("key-analyst")
        assert user is not None
        assert user.id == "analyst1"

    def test_get_user_by_invalid_key(self, manager: RBACManager):
        assert manager.get_user_by_api_key("invalid-key") is None

    def test_admin_has_all_permissions(self, manager: RBACManager):
        assert manager.check_permission("admin1", Permission.SCAN_SUBMIT) is True
        assert manager.check_permission("admin1", Permission.POLICY_WRITE) is True
        assert manager.check_permission("admin1", Permission.ADMIN_ALL) is True

    def test_analyst_permissions(self, manager: RBACManager):
        assert manager.check_permission("analyst1", Permission.SCAN_SUBMIT) is True
        assert manager.check_permission("analyst1", Permission.RULES_WRITE) is True
        assert manager.check_permission("analyst1", Permission.ADMIN_ALL) is False

    def test_developer_permissions(self, manager: RBACManager):
        assert manager.check_permission("dev1", Permission.SCAN_SUBMIT) is True
        assert manager.check_permission("dev1", Permission.RULES_READ) is True
        assert manager.check_permission("dev1", Permission.RULES_WRITE) is False
        assert manager.check_permission("dev1", Permission.POLICY_WRITE) is False

    def test_viewer_permissions(self, manager: RBACManager):
        assert manager.check_permission("viewer1", Permission.SCAN_READ) is True
        assert manager.check_permission("viewer1", Permission.SCAN_SUBMIT) is False
        assert manager.check_permission("viewer1", Permission.MONITOR_WRITE) is False

    def test_unknown_user_no_permission(self, manager: RBACManager):
        assert manager.check_permission("unknown", Permission.SCAN_READ) is False

    def test_inactive_user_no_permission(self, manager: RBACManager):
        user = manager.get_user("dev1")
        user.active = False
        assert manager.check_permission("dev1", Permission.SCAN_READ) is False

    def test_remove_user(self, manager: RBACManager):
        assert manager.remove_user("viewer1") is True
        assert manager.get_user("viewer1") is None
        assert manager.get_user_by_api_key("key-viewer") is None
        assert manager.remove_user("nonexistent") is False

    def test_list_users(self, manager: RBACManager):
        users = manager.list_users()
        assert len(users) == 4

    def test_get_user_permissions(self, manager: RBACManager):
        perms = manager.get_user_permissions("dev1")
        assert Permission.SCAN_SUBMIT in perms
        assert Permission.SCAN_READ in perms
        assert Permission.RULES_READ in perms
        assert Permission.POLICY_WRITE not in perms

    def test_inactive_user_no_permissions(self, manager: RBACManager):
        user = manager.get_user("dev1")
        user.active = False
        perms = manager.get_user_permissions("dev1")
        assert len(perms) == 0


# ── AuditLog tests ──────────────────────────────────────────────────

class TestAuditLog:
    @pytest.fixture
    def audit(self) -> AuditLog:
        return AuditLog()

    @pytest.mark.asyncio
    async def test_log_entry(self, audit: AuditLog):
        entry = await audit.log(
            action="scan_completed",
            actor="user1",
            resource_type="scan",
            resource_id="scan-001",
            details={"verdict": "clean"},
        )
        assert entry.id == "audit-000001"
        assert entry.action == "scan_completed"
        assert entry.integrity_hash != ""

    @pytest.mark.asyncio
    async def test_integrity_chain(self, audit: AuditLog):
        await audit.log(action="scan_submitted", actor="user1")
        await audit.log(action="scan_completed", actor="user1")
        await audit.log(action="policy_evaluated", actor="system")

        is_valid, last_valid = await audit.verify_integrity()
        assert is_valid is True
        assert last_valid == 3

    @pytest.mark.asyncio
    async def test_tampered_log_detected(self, audit: AuditLog):
        await audit.log(action="action1")
        await audit.log(action="action2")
        await audit.log(action="action3")

        # Tamper with the second entry
        audit._entries[1].integrity_hash = "tampered_hash"

        is_valid, last_valid = await audit.verify_integrity()
        assert is_valid is False
        assert last_valid == 1  # First entry is valid, second is tampered

    @pytest.mark.asyncio
    async def test_query_by_action(self, audit: AuditLog):
        await audit.log(action="scan_submitted")
        await audit.log(action="scan_completed")
        await audit.log(action="scan_submitted")

        results = await audit.query(action="scan_submitted")
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_query_by_actor(self, audit: AuditLog):
        await audit.log(action="scan", actor="user1")
        await audit.log(action="scan", actor="user2")
        await audit.log(action="scan", actor="user1")

        results = await audit.query(actor="user1")
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_query_pagination(self, audit: AuditLog):
        for i in range(10):
            await audit.log(action=f"action_{i}")

        results = await audit.query(limit=3, offset=0)
        assert len(results) == 3

        results2 = await audit.query(limit=3, offset=3)
        assert len(results2) == 3

    @pytest.mark.asyncio
    async def test_count(self, audit: AuditLog):
        await audit.log(action="a")
        await audit.log(action="b")
        assert await audit.count() == 2

    @pytest.mark.asyncio
    async def test_empty_log_valid(self, audit: AuditLog):
        is_valid, last_valid = await audit.verify_integrity()
        assert is_valid is True
        assert last_valid == 0

    @pytest.mark.asyncio
    async def test_export_json(self, audit: AuditLog):
        import json

        await audit.log(action="test", actor="user1")
        exported = await audit.export_json()
        data = json.loads(exported)
        assert len(data) == 1
        assert data[0]["action"] == "test"
