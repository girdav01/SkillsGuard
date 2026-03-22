"""Tests for OWASP AST coverage collection from verdict module."""

from __future__ import annotations

import pytest

from skillguard.core.models import (
    EngineResult,
    EngineVerdict,
    Finding,
    Severity,
)
from skillguard.core.verdict import collect_owasp_ast_coverage


def _make_finding(rule_id: str, owasp_ast: list[str]) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name="Test Rule",
        severity=Severity.MEDIUM,
        category="test",
        description="Test finding",
        file_path="test.md",
        owasp_ast=owasp_ast,
        confidence=0.80,
    )


def _make_engine_result(findings: list[Finding]) -> EngineResult:
    return EngineResult(
        engine_name="test_engine",
        engine_version="0.1.0",
        verdict=EngineVerdict.CLEAN,
        confidence=0.7,
        findings=findings,
        duration_ms=10,
    )


class TestOwaspAstCoverage:
    def test_collect_empty(self):
        result = collect_owasp_ast_coverage([])
        assert result == []

    def test_collect_single(self):
        finding = _make_finding("SG-TEST-001", owasp_ast=["AST01"])
        engine_result = _make_engine_result([finding])
        result = collect_owasp_ast_coverage([engine_result])
        assert result == ["AST01"]

    def test_collect_multiple_deduped(self):
        f1 = _make_finding("SG-TEST-001", owasp_ast=["AST01", "AST04"])
        f2 = _make_finding("SG-TEST-002", owasp_ast=["AST04", "AST06"])
        f3 = _make_finding("SG-TEST-003", owasp_ast=["AST01"])
        engine_result = _make_engine_result([f1, f2, f3])
        result = collect_owasp_ast_coverage([engine_result])
        assert result == ["AST01", "AST04", "AST06"]

    def test_collect_all_ast(self):
        findings = [
            _make_finding(f"SG-TEST-{i:03d}", owasp_ast=[f"AST{i:02d}"])
            for i in range(1, 11)
        ]
        engine_result = _make_engine_result(findings)
        result = collect_owasp_ast_coverage([engine_result])
        expected = [f"AST{i:02d}" for i in range(1, 11)]
        assert result == expected
        assert len(result) == 10
