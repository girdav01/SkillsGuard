"""Tests for the secret detector engine."""

from __future__ import annotations

import pytest

from skillguard.core.models import EngineVerdict, FileType, SkillFile
from skillguard.engines.sast.secret_detector import SecretDetector


@pytest.fixture
def detector() -> SecretDetector:
    return SecretDetector()


def _make_file(content: str) -> SkillFile:
    return SkillFile(
        path="test.py",
        file_type=FileType.SCRIPT_PYTHON,
        sha256="abc",
        size_bytes=len(content),
        content=content,
    )


class TestSecretDetector:
    @pytest.mark.asyncio
    async def test_clean_file(self, detector: SecretDetector):
        sf = _make_file("def hello():\n    return 'world'")
        result = await detector.scan([sf])
        assert result.verdict == EngineVerdict.CLEAN
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_detects_aws_access_key(self, detector: SecretDetector):
        sf = _make_file('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
        result = await detector.scan([sf])
        assert len(result.findings) >= 1
        assert any("AWS" in f.rule_name for f in result.findings)

    @pytest.mark.asyncio
    async def test_detects_github_token(self, detector: SecretDetector):
        sf = _make_file('token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"')
        result = await detector.scan([sf])
        assert len(result.findings) >= 1

    @pytest.mark.asyncio
    async def test_detects_private_key(self, detector: SecretDetector):
        sf = _make_file("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----")
        result = await detector.scan([sf])
        assert len(result.findings) >= 1
        assert result.verdict != EngineVerdict.CLEAN

    @pytest.mark.asyncio
    async def test_detects_generic_secret(self, detector: SecretDetector):
        sf = _make_file('password = "SuperSecretPassword123XYZ"')
        result = await detector.scan([sf])
        assert len(result.findings) >= 1

    @pytest.mark.asyncio
    async def test_detects_connection_string(self, detector: SecretDetector):
        sf = _make_file('db_url = "postgres://user:pass@localhost:5432/mydb"')
        result = await detector.scan([sf])
        assert len(result.findings) >= 1

    @pytest.mark.asyncio
    async def test_detects_jwt(self, detector: SecretDetector):
        sf = _make_file(
            'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"'
        )
        result = await detector.scan([sf])
        assert len(result.findings) >= 1

    @pytest.mark.asyncio
    async def test_engine_metadata(self, detector: SecretDetector):
        assert detector.name == "secret_detector"
        assert await detector.health_check() is True
