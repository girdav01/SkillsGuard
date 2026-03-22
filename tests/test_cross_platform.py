"""Tests for the cross-platform analyzer engine (OWASP AST10)."""

from __future__ import annotations

import pytest

from skillguard.core.models import (
    EngineVerdict,
    FileType,
    Severity,
    SkillFile,
)
from skillguard.engines.structural.cross_platform_analyzer import CrossPlatformAnalyzer


@pytest.fixture
def engine() -> CrossPlatformAnalyzer:
    return CrossPlatformAnalyzer()


def _make_skill_file(
    content: str,
    file_type: FileType = FileType.SKILL_MD,
    path: str = "SKILL.md",
) -> SkillFile:
    return SkillFile(
        path=path,
        file_type=file_type,
        sha256="abc123",
        size_bytes=len(content),
        content=content,
    )


class TestCrossPlatformAnalyzer:
    @pytest.mark.asyncio
    async def test_clean_portable(self, engine: CrossPlatformAnalyzer):
        sf = _make_skill_file(
            "# My Skill\n\n"
            "This skill provides helpful code review suggestions.\n"
            "It works on any platform.\n"
        )
        result = await engine.scan([sf])
        assert result.verdict == EngineVerdict.CLEAN
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_platform_specific_api(self, engine: CrossPlatformAnalyzer):
        sf = _make_skill_file(
            "# My Skill\n\n"
            "Use Bash() to execute commands on the host.\n",
            file_type=FileType.SCRIPT_PYTHON,
            path="run.py",
        )
        result = await engine.scan([sf])
        finding = next(f for f in result.findings if f.rule_id == "SG-XPLAT-001")
        assert finding.severity == Severity.MEDIUM
        assert "AST10" in finding.owasp_ast

    @pytest.mark.asyncio
    async def test_hardcoded_path(self, engine: CrossPlatformAnalyzer):
        sf = _make_skill_file(
            "# Config\n\n"
            "Read settings from ~/.cursor/settings.json\n"
        )
        result = await engine.scan([sf])
        finding = next(f for f in result.findings if f.rule_id == "SG-XPLAT-003")
        assert finding.severity == Severity.LOW
        assert "AST10" in finding.owasp_ast

    @pytest.mark.asyncio
    async def test_transport_mismatch(self, engine: CrossPlatformAnalyzer):
        sf = _make_skill_file(
            "# MCP Skill\n\n"
            "transport: stdio\n",
            file_type=FileType.CONFIG,
            path="config.yaml",
        )
        result = await engine.scan([sf])
        finding = next(f for f in result.findings if f.rule_id == "SG-XPLAT-004")
        assert finding.severity == Severity.MEDIUM
        assert "AST10" in finding.owasp_ast

    @pytest.mark.asyncio
    async def test_sandbox_escalation(self, engine: CrossPlatformAnalyzer):
        sf = _make_skill_file(
            "# My Skill\n\n"
            "sandbox: false\n",
            file_type=FileType.CONFIG,
            path="config.yaml",
        )
        result = await engine.scan([sf])
        finding = next(f for f in result.findings if f.rule_id == "SG-XPLAT-005")
        assert finding.severity == Severity.HIGH
        assert "AST10" in finding.owasp_ast

    @pytest.mark.asyncio
    async def test_health_check(self, engine: CrossPlatformAnalyzer):
        assert await engine.health_check() is True
