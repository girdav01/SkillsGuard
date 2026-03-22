"""Tests for the dependency checker engine (OWASP AST07)."""

from __future__ import annotations

import pytest

from skillguard.core.models import (
    EngineVerdict,
    FileType,
    Severity,
    SkillFile,
)
from skillguard.engines.structural.dependency_checker import DependencyChecker


@pytest.fixture
def engine() -> DependencyChecker:
    return DependencyChecker()


def _make_skill_file(
    content: str,
    file_type: FileType = FileType.CONFIG,
    path: str = "requirements.txt",
) -> SkillFile:
    return SkillFile(
        path=path,
        file_type=file_type,
        sha256="abc123",
        size_bytes=len(content),
        content=content,
    )


class TestDependencyChecker:
    @pytest.mark.asyncio
    async def test_clean_pinned(self, engine: DependencyChecker):
        req = _make_skill_file("flask==2.0.1\nrequests==2.28.0\n")
        lock = _make_skill_file("", path="requirements.lock")
        result = await engine.scan([req, lock])
        assert result.verdict == EngineVerdict.CLEAN
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_unpinned_dependency(self, engine: DependencyChecker):
        sf = _make_skill_file("flask>=2.0\n")
        lock = _make_skill_file("", path="requirements.lock")
        result = await engine.scan([sf, lock])
        finding = next(f for f in result.findings if f.rule_id == "SG-DEP-001")
        assert finding.severity == Severity.MEDIUM
        assert "AST07" in finding.owasp_ast

    @pytest.mark.asyncio
    async def test_mutable_git_ref(self, engine: DependencyChecker):
        sf = _make_skill_file(
            "git+https://github.com/foo/bar@main\n",
        )
        lock = _make_skill_file("", path="requirements.lock")
        result = await engine.scan([sf, lock])
        finding = next(f for f in result.findings if f.rule_id == "SG-DEP-003")
        assert finding.severity == Severity.HIGH
        assert "AST07" in finding.owasp_ast

    @pytest.mark.asyncio
    async def test_health_check(self, engine: DependencyChecker):
        assert await engine.health_check() is True
