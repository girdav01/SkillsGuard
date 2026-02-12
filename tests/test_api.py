"""Tests for the FastAPI REST API."""

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


class TestHealthEndpoint:
    def test_health(self, client: TestClient):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["version"] in ("0.1.0", "0.2.0", "0.3.0")


class TestScanEndpoint:
    def test_submit_scan(self, client: TestClient):
        resp = client.post(
            "/api/v1/scan",
            json={
                "skill_path": str(FIXTURES_DIR / "clean_skill"),
                "platform": "generic",
                "scan_type": "full",
            },
        )
        assert resp.status_code == 202
        data = resp.json()
        assert "scan_id" in data
        assert data["status"] == "completed"

    def test_submit_scan_no_path(self, client: TestClient):
        resp = client.post("/api/v1/scan", json={})
        assert resp.status_code == 400

    def test_submit_scan_nonexistent_path(self, client: TestClient):
        resp = client.post(
            "/api/v1/scan",
            json={"skill_path": "/nonexistent/path"},
        )
        assert resp.status_code == 404

    def test_get_scan_result(self, client: TestClient):
        # Submit scan first
        submit_resp = client.post(
            "/api/v1/scan",
            json={"skill_path": str(FIXTURES_DIR / "clean_skill")},
        )
        scan_id = submit_resp.json()["scan_id"]

        # Retrieve result
        resp = client.get(f"/api/v1/scan/{scan_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == scan_id
        assert data["status"] == "completed"
        assert data["result"] is not None

    def test_get_nonexistent_scan(self, client: TestClient):
        resp = client.get("/api/v1/scan/nonexistent")
        assert resp.status_code == 404

    def test_scan_malicious_skill(self, client: TestClient):
        resp = client.post(
            "/api/v1/scan",
            json={"skill_path": str(FIXTURES_DIR / "malicious_skill")},
        )
        assert resp.status_code == 202
        scan_id = resp.json()["scan_id"]

        result_resp = client.get(f"/api/v1/scan/{scan_id}")
        result = result_resp.json()["result"]
        assert result["total_findings"] > 0
        assert result["composite_score"] > 0


class TestSkillEndpoint:
    def test_lookup_unknown_skill(self, client: TestClient):
        resp = client.get("/api/v1/skill/0000000000000000")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "not_seen"

    def test_lookup_scanned_skill(self, client: TestClient):
        # Scan first
        submit_resp = client.post(
            "/api/v1/scan",
            json={"skill_path": str(FIXTURES_DIR / "clean_skill")},
        )
        scan_id = submit_resp.json()["scan_id"]

        # Get the sha256 from scan results
        result_resp = client.get(f"/api/v1/scan/{scan_id}")
        sha256 = result_resp.json()["result"]["skill_sha256"]

        # Lookup by hash
        resp = client.get(f"/api/v1/skill/{sha256}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "known"


class TestRulesEndpoint:
    def test_list_rules(self, client: TestClient):
        resp = client.get("/api/v1/rules")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "rules" in data
