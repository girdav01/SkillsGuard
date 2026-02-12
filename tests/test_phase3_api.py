"""Tests for Phase 3 API routes: policy, community, AI-BOM, audit."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from skillguard.api.app import create_app

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app)


def _submit_scan(client: TestClient) -> str:
    """Helper to submit a scan and return the scan_id."""
    resp = client.post(
        "/api/v1/scan",
        json={"skill_path": str(FIXTURES_DIR / "clean_skill")},
    )
    return resp.json()["scan_id"]


# ── Policy routes ────────────────────────────────────────────────────

class TestPolicyRoutes:
    def test_list_policies(self, client: TestClient):
        resp = client.get("/api/v1/policies")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert data["total"] >= 6  # 6 default policies

    def test_create_policy(self, client: TestClient):
        resp = client.post(
            "/api/v1/policies",
            json={
                "id": "TEST-POL-001",
                "name": "Test Policy",
                "description": "A test policy",
                "action": "warn",
                "conditions": {"verdict": "clean"},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "created"

    def test_delete_policy(self, client: TestClient):
        # Create first
        client.post(
            "/api/v1/policies",
            json={"id": "TO-DELETE", "name": "Delete Me", "action": "warn", "conditions": {}},
        )
        resp = client.delete("/api/v1/policies/TO-DELETE")
        assert resp.status_code == 200

    def test_delete_nonexistent_policy(self, client: TestClient):
        resp = client.delete("/api/v1/policies/NONEXISTENT")
        assert resp.status_code == 404

    def test_evaluate_policy(self, client: TestClient):
        scan_id = _submit_scan(client)
        resp = client.post(f"/api/v1/policies/evaluate/{scan_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert "allowed" in data

    def test_evaluate_nonexistent_scan(self, client: TestClient):
        resp = client.post("/api/v1/policies/evaluate/nonexistent")
        assert resp.status_code == 404

    def test_load_yaml_policies(self, client: TestClient):
        yaml_content = """
policies:
  - id: YAML-API-001
    name: YAML Test Policy
    action: audit
    conditions:
      verdict: clean
    enabled: true
"""
        resp = client.post(
            "/api/v1/policies/load-yaml",
            json={"yaml_content": yaml_content},
        )
        assert resp.status_code == 200
        assert resp.json()["policies_loaded"] == 1


# ── Community routes ─────────────────────────────────────────────────

class TestCommunityRoutes:
    def test_get_empty_reputation(self, client: TestClient):
        resp = client.get("/api/v1/community/unknown_hash")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_verdicts"] == 0

    def test_submit_verdict(self, client: TestClient):
        resp = client.post(
            "/api/v1/community/test_hash/verdict",
            json={
                "analyst_id": "analyst1",
                "verdict": "clean",
                "confidence": 0.9,
                "comment": "Looks fine",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "submitted"

    def test_submit_invalid_verdict(self, client: TestClient):
        resp = client.post(
            "/api/v1/community/test_hash/verdict",
            json={
                "analyst_id": "analyst1",
                "verdict": "invalid_verdict",
                "confidence": 0.5,
            },
        )
        assert resp.status_code == 400

    def test_submit_comment(self, client: TestClient):
        resp = client.post(
            "/api/v1/community/test_hash/comment",
            json={
                "author_id": "author1",
                "text": "This skill looks suspicious to me.",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "submitted"

    def test_reputation_after_verdicts(self, client: TestClient):
        sha = "reputation_test_hash"
        # Submit multiple verdicts
        for v in ["clean", "clean", "malicious"]:
            client.post(
                f"/api/v1/community/{sha}/verdict",
                json={"analyst_id": "a1", "verdict": v, "confidence": 0.8},
            )

        resp = client.get(f"/api/v1/community/{sha}")
        data = resp.json()
        assert data["total_verdicts"] == 3
        assert data["clean_count"] == 2
        assert data["malicious_count"] == 1


# ── AI-BOM routes ────────────────────────────────────────────────────

class TestAIBOMRoutes:
    def test_get_ai_bom(self, client: TestClient):
        scan_id = _submit_scan(client)
        resp = client.get(f"/api/v1/ai-bom/{scan_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["bomFormat"] == "CycloneDX"
        assert data["specVersion"] == "1.5"

    def test_get_ai_bom_nonexistent(self, client: TestClient):
        resp = client.get("/api/v1/ai-bom/nonexistent")
        assert resp.status_code == 404


# ── Audit routes ─────────────────────────────────────────────────────

class TestAuditRoutes:
    def test_query_empty_audit(self, client: TestClient):
        resp = client.get("/api/v1/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "entries" in data

    def test_verify_audit_integrity(self, client: TestClient):
        resp = client.get("/api/v1/audit/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_valid"] is True

    def test_export_audit(self, client: TestClient):
        resp = client.get("/api/v1/audit/export")
        assert resp.status_code == 200
