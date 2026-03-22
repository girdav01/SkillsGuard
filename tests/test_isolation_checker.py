"""Tests for the isolation checker engine (OWASP AST06)."""

from __future__ import annotations

import pytest

from skillguard.core.models import (
    EngineVerdict,
    FileType,
    Severity,
    SkillFile,
)
from skillguard.engines.sandbox.isolation_checker import IsolationChecker


@pytest.fixture
def engine() -> IsolationChecker:
    return IsolationChecker()


def _make_skill_file(
    content: str,
    file_type: FileType = FileType.CONFIG,
    path: str = "Dockerfile",
) -> SkillFile:
    return SkillFile(
        path=path,
        file_type=file_type,
        sha256="abc123",
        size_bytes=len(content),
        content=content,
    )


class TestIsolationChecker:
    @pytest.mark.asyncio
    async def test_clean_config(self, engine: IsolationChecker):
        sf = _make_skill_file(
            "FROM python:3.11-slim\n"
            "WORKDIR /app\n"
            "COPY . .\n"
            "RUN pip install -r requirements.txt\n"
            "security_opt:\n"
            "  - seccomp:default.json\n"
            "CMD [\"python\", \"main.py\"]\n"
        )
        result = await engine.scan([sf])
        # No critical findings expected (SG-ISOL-003 suppressed by security_opt)
        critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0

    @pytest.mark.asyncio
    async def test_host_network(self, engine: IsolationChecker):
        sf = _make_skill_file(
            "services:\n"
            "  app:\n"
            "    image: myapp\n"
            "    network_mode: host\n"
            "    security_opt:\n"
            "      - seccomp:default.json\n"
        )
        result = await engine.scan([sf])
        finding = next(f for f in result.findings if f.rule_id == "SG-ISOL-001")
        assert finding.severity == Severity.CRITICAL
        assert "AST06" in finding.owasp_ast

    @pytest.mark.asyncio
    async def test_privileged_container(self, engine: IsolationChecker):
        sf = _make_skill_file(
            "services:\n"
            "  app:\n"
            "    image: myapp\n"
            "    privileged: true\n"
            "    security_opt:\n"
            "      - seccomp:default.json\n"
        )
        result = await engine.scan([sf])
        finding = next(f for f in result.findings if f.rule_id == "SG-ISOL-002")
        assert finding.severity == Severity.CRITICAL
        assert "AST06" in finding.owasp_ast

    @pytest.mark.asyncio
    async def test_sensitive_port(self, engine: IsolationChecker):
        sf = _make_skill_file(
            "FROM python:3.11\n"
            "EXPOSE 3306\n"
            "security_opt:\n"
            "  - seccomp:default.json\n"
        )
        result = await engine.scan([sf])
        finding = next(f for f in result.findings if f.rule_id == "SG-ISOL-004")
        assert finding.severity == Severity.HIGH
        assert "AST06" in finding.owasp_ast

    @pytest.mark.asyncio
    async def test_dangerous_volume(self, engine: IsolationChecker):
        sf = _make_skill_file(
            "services:\n"
            "  app:\n"
            "    image: myapp\n"
            "    volumes: /var/run/docker.sock:/var/run/docker.sock\n"
            "    security_opt:\n"
            "      - seccomp:default.json\n"
        )
        result = await engine.scan([sf])
        finding = next(f for f in result.findings if f.rule_id == "SG-ISOL-005")
        assert finding.severity == Severity.CRITICAL
        assert "AST06" in finding.owasp_ast

    @pytest.mark.asyncio
    async def test_health_check(self, engine: IsolationChecker):
        assert await engine.health_check() is True
