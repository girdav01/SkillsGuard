"""Tests for the HTML report generator."""

from __future__ import annotations

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
from skillguard.reporting.html_report import generate_html_report


@pytest.fixture
def clean_result():
    return ScanResult(
        scan_id="test-clean-001",
        skill_name="clean_skill",
        skill_sha256="abc123def456",
        platform=SkillPlatform.GENERIC,
        scan_started=datetime.now(timezone.utc),
        scan_completed=datetime.now(timezone.utc),
        composite_score=0,
        verdict=Verdict.CLEAN,
        engine_results=[],
        total_findings=0,
        findings_by_severity={},
        files_scanned=3,
    )


@pytest.fixture
def malicious_result():
    finding = Finding(
        rule_id="SG-PI-001",
        rule_name="Instruction Override",
        severity=Severity.CRITICAL,
        category="prompt_injection",
        description="Detects instruction override patterns",
        file_path="SKILL.md",
        line_start=5,
        snippet="ignore previous instructions",
        owasp_llm=["LLM01"],
        confidence=0.9,
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
        scan_id="test-mal-001",
        skill_name="malicious_skill",
        skill_sha256="xyz789",
        platform=SkillPlatform.CLAUDE_CODE,
        scan_started=datetime.now(timezone.utc),
        scan_completed=datetime.now(timezone.utc),
        composite_score=95,
        verdict=Verdict.MALICIOUS,
        engine_results=[engine_result],
        total_findings=1,
        findings_by_severity={"critical": 1},
        files_scanned=5,
        owasp_coverage=["LLM01"],
    )


class TestHTMLReport:
    def test_clean_report_generated(self, clean_result):
        html = generate_html_report(clean_result)
        assert "<!DOCTYPE html>" in html
        assert "SkillGuard" in html
        assert "clean_skill" in html
        assert "CLEAN" in html

    def test_malicious_report_generated(self, malicious_result):
        html = generate_html_report(malicious_result)
        assert "<!DOCTYPE html>" in html
        assert "MALICIOUS" in html
        assert "malicious_skill" in html
        assert "SG-PI-001" in html
        assert "95/100" in html

    def test_report_contains_findings(self, malicious_result):
        html = generate_html_report(malicious_result)
        assert "Instruction Override" in html or "SG-PI-001" in html
        assert "SKILL.md" in html

    def test_report_contains_owasp(self, malicious_result):
        html = generate_html_report(malicious_result)
        assert "LLM01" in html

    def test_report_is_self_contained(self, malicious_result):
        """HTML report should have inline styles (no external deps)."""
        html = generate_html_report(malicious_result)
        assert "<style>" in html
        # Should NOT reference external stylesheets
        assert 'rel="stylesheet"' not in html

    def test_empty_findings_no_crash(self, clean_result):
        html = generate_html_report(clean_result)
        assert "0/100" in html
