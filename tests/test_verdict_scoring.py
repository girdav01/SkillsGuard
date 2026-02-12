"""Tests for the verdict scoring algorithm."""

from __future__ import annotations

import pytest

from skillguard.core.models import (
    EngineResult,
    EngineVerdict,
    Finding,
    Severity,
    Verdict,
)
from skillguard.core.verdict import (
    aggregate_findings_by_severity,
    calculate_risk_score,
    collect_owasp_coverage,
)


def _make_finding(severity: Severity, **kwargs) -> Finding:
    return Finding(
        rule_id="TEST-001",
        rule_name="Test Finding",
        severity=severity,
        category="test",
        description="A test finding",
        file_path="test.md",
        confidence=0.9,
        **kwargs,
    )


def _make_engine_result(
    findings: list[Finding],
    verdict: EngineVerdict = EngineVerdict.CLEAN,
) -> EngineResult:
    return EngineResult(
        engine_name="test_engine",
        engine_version="1.0",
        verdict=verdict,
        confidence=0.9,
        findings=findings,
        duration_ms=100,
    )


class TestCalculateRiskScore:
    def test_no_findings_is_clean(self):
        result = _make_engine_result([])
        score, verdict = calculate_risk_score([result])
        assert score == 0
        assert verdict == Verdict.CLEAN

    def test_critical_finding_adds_40(self):
        result = _make_engine_result([_make_finding(Severity.CRITICAL)])
        score, verdict = calculate_risk_score([result])
        assert score == 40
        assert verdict == Verdict.LOW_RISK  # 40 is in 21-40 range

    def test_high_finding_adds_20(self):
        result = _make_engine_result([_make_finding(Severity.HIGH)])
        score, verdict = calculate_risk_score([result])
        assert score == 20
        assert verdict == Verdict.CLEAN  # 20 is in 0-20 range

    def test_medium_finding_adds_10(self):
        result = _make_engine_result([_make_finding(Severity.MEDIUM)])
        score, verdict = calculate_risk_score([result])
        assert score == 10
        assert verdict == Verdict.CLEAN

    def test_low_finding_adds_3(self):
        result = _make_engine_result([_make_finding(Severity.LOW)])
        score, verdict = calculate_risk_score([result])
        assert score == 3
        assert verdict == Verdict.CLEAN

    def test_multiple_findings_accumulate(self):
        findings = [
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.MEDIUM),
        ]
        result = _make_engine_result(findings)
        score, verdict = calculate_risk_score([result])
        assert score == 70  # 40 + 20 + 10
        assert verdict == Verdict.HIGH_RISK

    def test_score_capped_at_100(self):
        findings = [_make_finding(Severity.CRITICAL) for _ in range(5)]
        result = _make_engine_result(findings)
        score, verdict = calculate_risk_score([result])
        assert score == 100
        assert verdict == Verdict.MALICIOUS

    def test_threat_intel_match_instant_100(self):
        result = _make_engine_result([])
        score, verdict = calculate_risk_score([result], threat_intel_match=True)
        assert score == 100
        assert verdict == Verdict.MALICIOUS

    def test_engine_consensus_modifier(self):
        results = [
            _make_engine_result(
                [_make_finding(Severity.MEDIUM)],
                verdict=EngineVerdict.MALICIOUS,
            )
            for _ in range(3)
        ]
        score, verdict = calculate_risk_score(results)
        # 3 MALICIOUS engines -> min score 90
        assert score >= 90
        assert verdict == Verdict.MALICIOUS

    def test_trusted_publisher_reduces_score(self):
        result = _make_engine_result([_make_finding(Severity.HIGH)])
        score_normal, _ = calculate_risk_score([result])
        score_trusted, _ = calculate_risk_score([result], trusted_publisher=True)
        assert score_trusted == score_normal - 10

    def test_trusted_publisher_doesnt_go_negative(self):
        result = _make_engine_result([_make_finding(Severity.LOW)])
        score, verdict = calculate_risk_score([result], trusted_publisher=True)
        assert score >= 0

    def test_verdict_thresholds(self):
        # Test each verdict boundary
        test_cases = [
            (0, Verdict.CLEAN),
            (20, Verdict.CLEAN),
            (21, Verdict.LOW_RISK),
            (40, Verdict.LOW_RISK),
            (41, Verdict.SUSPICIOUS),
            (60, Verdict.SUSPICIOUS),
            (61, Verdict.HIGH_RISK),
            (80, Verdict.HIGH_RISK),
            (81, Verdict.MALICIOUS),
            (100, Verdict.MALICIOUS),
        ]
        for expected_score, expected_verdict in test_cases:
            # Create findings to hit the target score
            from skillguard.core.verdict import _score_to_verdict

            assert _score_to_verdict(expected_score) == expected_verdict


class TestAggregateFindingsBySeverity:
    def test_empty_results(self):
        result = _make_engine_result([])
        counts = aggregate_findings_by_severity([result])
        assert counts == {}

    def test_counts_by_severity(self):
        findings = [
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.LOW),
        ]
        result = _make_engine_result(findings)
        counts = aggregate_findings_by_severity([result])
        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["low"] == 1


class TestCollectOwaspCoverage:
    def test_collects_unique_refs(self):
        findings = [
            _make_finding(Severity.HIGH, owasp_llm=["LLM01", "LLM06"]),
            _make_finding(Severity.MEDIUM, owasp_llm=["LLM01", "LLM05"]),
        ]
        result = _make_engine_result(findings)
        coverage = collect_owasp_coverage([result])
        assert coverage == ["LLM01", "LLM05", "LLM06"]
