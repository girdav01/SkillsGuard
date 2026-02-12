"""Tests for AI-BOM (CycloneDX) generator."""

from __future__ import annotations

from datetime import datetime

import pytest

from skillguard.core.models import (
    EngineResult,
    EngineVerdict,
    Finding,
    ScanResult,
    Severity,
    SkillPlatform,
    Verdict,
)
from skillguard.core.ai_bom import generate_ai_bom, generate_ai_bom_json


def _make_result_with_findings() -> ScanResult:
    finding = Finding(
        rule_id="SG-TEST-001",
        rule_name="Test Finding",
        severity=Severity.HIGH,
        category="test",
        description="A test finding",
        file_path="test.py",
        confidence=0.85,
        owasp_llm=["LLM01"],
        mitre_attack=["T1059"],
        remediation="Fix it.",
    )
    engine_result = EngineResult(
        engine_name="test_engine",
        engine_version="1.0.0",
        verdict=EngineVerdict.SUSPICIOUS,
        confidence=0.85,
        findings=[finding],
        duration_ms=100,
    )
    return ScanResult(
        scan_id="bom-test-001",
        skill_name="test-skill",
        skill_sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        platform=SkillPlatform.GENERIC,
        scan_started=datetime(2025, 1, 1),
        scan_completed=datetime(2025, 1, 1),
        composite_score=55,
        verdict=Verdict.SUSPICIOUS,
        engine_results=[engine_result],
        total_findings=1,
        findings_by_severity={"high": 1},
        files_scanned=3,
        owasp_coverage=["LLM01"],
    )


class TestAIBOM:
    def test_bom_structure(self):
        result = _make_result_with_findings()
        bom = generate_ai_bom(result)

        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.5"
        assert bom["version"] == 1
        assert "metadata" in bom
        assert "components" in bom
        assert "vulnerabilities" in bom

    def test_bom_metadata(self):
        result = _make_result_with_findings()
        bom = generate_ai_bom(result)

        metadata = bom["metadata"]
        assert "timestamp" in metadata
        assert metadata["tools"]["components"][0]["name"] == "SkillGuard"

    def test_bom_component(self):
        result = _make_result_with_findings()
        bom = generate_ai_bom(result)

        components = bom["components"]
        assert len(components) == 1
        comp = components[0]
        assert comp["type"] == "application"
        assert comp["name"] == "test-skill"
        assert comp["hashes"][0]["alg"] == "SHA-256"

    def test_bom_properties(self):
        result = _make_result_with_findings()
        bom = generate_ai_bom(result)

        comp = bom["components"][0]
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["skillguard:verdict"] == "suspicious"
        assert props["skillguard:score"] == "55"
        assert props["skillguard:total_findings"] == "1"

    def test_bom_vulnerabilities(self):
        result = _make_result_with_findings()
        bom = generate_ai_bom(result)

        vulns = bom["vulnerabilities"]
        assert len(vulns) == 1
        vuln = vulns[0]
        assert vuln["id"] == "SG-TEST-001"
        assert vuln["description"] == "A test finding"
        assert vuln["recommendation"] == "Fix it."

        # Check OWASP and MITRE properties
        vuln_props = {p["name"]: p["value"] for p in vuln["properties"]}
        assert "owasp:llm" in vuln_props
        assert vuln_props["owasp:llm"] == "LLM01"

    def test_bom_no_findings(self):
        result = ScanResult(
            scan_id="bom-test-002",
            skill_name="clean-skill",
            skill_sha256="clean_hash",
            platform=SkillPlatform.GENERIC,
            scan_started=datetime(2025, 1, 1),
            scan_completed=datetime(2025, 1, 1),
            composite_score=0,
            verdict=Verdict.CLEAN,
            engine_results=[],
            total_findings=0,
            findings_by_severity={},
            files_scanned=1,
            owasp_coverage=[],
        )
        bom = generate_ai_bom(result)
        assert len(bom["vulnerabilities"]) == 0

    def test_bom_json_output(self):
        import json

        result = _make_result_with_findings()
        json_str = generate_ai_bom_json(result)
        data = json.loads(json_str)
        assert data["bomFormat"] == "CycloneDX"

    def test_bom_deduplicates_findings(self):
        """Findings with the same rule_id should only appear once."""
        finding1 = Finding(
            rule_id="SG-DUPE-001",
            rule_name="Duplicate",
            severity=Severity.MEDIUM,
            category="test",
            description="Dup finding",
            file_path="a.py",
            confidence=0.7,
        )
        finding2 = Finding(
            rule_id="SG-DUPE-001",
            rule_name="Duplicate",
            severity=Severity.MEDIUM,
            category="test",
            description="Dup finding",
            file_path="b.py",
            confidence=0.7,
        )
        engine_result = EngineResult(
            engine_name="test",
            engine_version="1.0",
            verdict=EngineVerdict.SUSPICIOUS,
            confidence=0.7,
            findings=[finding1, finding2],
            duration_ms=50,
        )
        result = ScanResult(
            scan_id="dedup-test",
            skill_name="test",
            skill_sha256="hash",
            platform=SkillPlatform.GENERIC,
            scan_started=datetime(2025, 1, 1),
            scan_completed=datetime(2025, 1, 1),
            composite_score=30,
            verdict=Verdict.SUSPICIOUS,
            engine_results=[engine_result],
            total_findings=2,
            findings_by_severity={"medium": 2},
            files_scanned=2,
            owasp_coverage=[],
        )
        bom = generate_ai_bom(result)
        assert len(bom["vulnerabilities"]) == 1
