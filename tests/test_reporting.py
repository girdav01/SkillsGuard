"""Tests for report generation."""

from __future__ import annotations

import json
from datetime import datetime, timezone

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
from skillguard.reporting.json_report import generate_json_report
from skillguard.reporting.sarif_report import generate_sarif_report


@pytest.fixture
def sample_result() -> ScanResult:
    finding = Finding(
        rule_id="SG-PI-001",
        rule_name="Instruction Override",
        severity=Severity.CRITICAL,
        category="prompt_injection",
        description="Detects instruction override patterns",
        file_path="SKILL.md",
        line_start=5,
        line_end=5,
        snippet="ignore previous instructions",
        owasp_llm=["LLM01"],
        mitre_attack=["T1059.006"],
        confidence=0.9,
        remediation="Remove override patterns.",
    )
    engine_result = EngineResult(
        engine_name="regex_scanner",
        engine_version="0.1.0",
        verdict=EngineVerdict.MALICIOUS,
        confidence=0.9,
        findings=[finding],
        duration_ms=15,
    )
    return ScanResult(
        scan_id="test123",
        skill_name="test-skill",
        skill_sha256="abcdef1234567890",
        platform=SkillPlatform.CLAUDE_CODE,
        scan_started=datetime(2026, 1, 1, tzinfo=timezone.utc),
        scan_completed=datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
        composite_score=40,
        verdict=Verdict.SUSPICIOUS,
        engine_results=[engine_result],
        total_findings=1,
        findings_by_severity={"critical": 1},
        files_scanned=3,
        owasp_coverage=["LLM01"],
    )


class TestJsonReport:
    def test_generates_valid_json(self, sample_result: ScanResult):
        report = generate_json_report(sample_result)
        data = json.loads(report)
        assert data["scan_id"] == "test123"
        assert data["skill_name"] == "test-skill"
        assert data["composite_score"] == 40

    def test_includes_findings(self, sample_result: ScanResult):
        report = generate_json_report(sample_result)
        data = json.loads(report)
        assert len(data["engine_results"]) == 1
        assert len(data["engine_results"][0]["findings"]) == 1
        finding = data["engine_results"][0]["findings"][0]
        assert finding["rule_id"] == "SG-PI-001"
        assert finding["severity"] == "critical"


class TestSarifReport:
    def test_generates_valid_sarif(self, sample_result: ScanResult):
        report = generate_sarif_report(sample_result)
        data = json.loads(report)
        assert data["version"] == "2.1.0"
        assert "$schema" in data

    def test_sarif_structure(self, sample_result: ScanResult):
        report = generate_sarif_report(sample_result)
        data = json.loads(report)
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "SkillGuard"
        assert len(run["results"]) == 1

    def test_sarif_result_details(self, sample_result: ScanResult):
        report = generate_sarif_report(sample_result)
        data = json.loads(report)
        result = data["runs"][0]["results"][0]
        assert result["ruleId"] == "SG-PI-001"
        assert result["level"] == "error"  # CRITICAL -> error
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "SKILL.md"

    def test_sarif_rules(self, sample_result: ScanResult):
        report = generate_sarif_report(sample_result)
        data = json.loads(report)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "SG-PI-001"

    def test_sarif_properties(self, sample_result: ScanResult):
        report = generate_sarif_report(sample_result)
        data = json.loads(report)
        props = data["runs"][0]["properties"]
        assert props["compositeScore"] == 40
        assert props["verdict"] == "suspicious"
