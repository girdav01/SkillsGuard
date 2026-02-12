"""Tests for structural analysis engines."""

from __future__ import annotations

import pytest

from skillguard.core.models import (
    EngineVerdict,
    FileType,
    Severity,
    SkillFile,
)
from skillguard.engines.structural.schema_validator import SchemaValidator
from skillguard.engines.structural.permission_analyzer import PermissionAnalyzer
from skillguard.engines.structural.obfuscation_detector import ObfuscationDetector


# ── SchemaValidator tests ────────────────────────────────────────────

class TestSchemaValidator:
    @pytest.fixture
    def validator(self) -> SchemaValidator:
        return SchemaValidator()

    @pytest.mark.asyncio
    async def test_clean_skill(self, validator: SchemaValidator):
        sf = SkillFile(
            path="SKILL.md",
            file_type=FileType.SKILL_MD,
            sha256="abc123",
            size_bytes=500,
            content="# My Skill\nA simple helper skill.\n",
        )
        result = await validator.scan([sf])
        assert result.verdict == EngineVerdict.CLEAN

    @pytest.mark.asyncio
    async def test_missing_skill_md(self, validator: SchemaValidator):
        sf = SkillFile(
            path="helper.py",
            file_type=FileType.SCRIPT_PYTHON,
            sha256="abc123",
            size_bytes=50,
            content="print('hi')\n",
        )
        result = await validator.scan([sf])
        assert any(f.rule_id == "SG-STRUCT-001" for f in result.findings)

    @pytest.mark.asyncio
    async def test_excessive_scripts(self, validator: SchemaValidator):
        files = [
            SkillFile(
                path="SKILL.md",
                file_type=FileType.SKILL_MD,
                sha256="abc",
                size_bytes=10,
                content="skill",
            )
        ]
        for i in range(15):
            files.append(
                SkillFile(
                    path=f"script_{i}.py",
                    file_type=FileType.SCRIPT_PYTHON,
                    sha256=f"hash_{i}",
                    size_bytes=50,
                    content="pass\n",
                )
            )
        result = await validator.scan(files)
        assert any(f.rule_id == "SG-STRUCT-002" for f in result.findings)

    @pytest.mark.asyncio
    async def test_hidden_files(self, validator: SchemaValidator):
        files = [
            SkillFile(
                path="SKILL.md",
                file_type=FileType.SKILL_MD,
                sha256="abc",
                size_bytes=10,
                content="skill",
            ),
            SkillFile(
                path=".hidden_config",
                file_type=FileType.CONFIG,
                sha256="def",
                size_bytes=10,
                content="secret=yes",
            ),
        ]
        result = await validator.scan(files)
        assert any(f.rule_id == "SG-STRUCT-003" for f in result.findings)

    @pytest.mark.asyncio
    async def test_oversized_skill_md(self, validator: SchemaValidator):
        sf = SkillFile(
            path="SKILL.md",
            file_type=FileType.SKILL_MD,
            sha256="abc123",
            size_bytes=200_000,
            content="x" * 1000,
        )
        result = await validator.scan([sf])
        assert any(f.rule_id == "SG-STRUCT-004" for f in result.findings)

    @pytest.mark.asyncio
    async def test_binary_content_in_text(self, validator: SchemaValidator):
        sf = SkillFile(
            path="SKILL.md",
            file_type=FileType.SKILL_MD,
            sha256="abc123",
            size_bytes=100,
            content="Hello\x00World\x00Binary\x00",
        )
        result = await validator.scan([sf])
        assert any(f.rule_id == "SG-STRUCT-005" for f in result.findings)

    @pytest.mark.asyncio
    async def test_health_check(self, validator: SchemaValidator):
        assert await validator.health_check() is True

    @pytest.mark.asyncio
    async def test_engine_metadata(self, validator: SchemaValidator):
        assert validator.name == "schema_validator"
        assert validator.version == "0.3.0"


# ── PermissionAnalyzer tests ────────────────────────────────────────

class TestPermissionAnalyzer:
    @pytest.fixture
    def analyzer(self) -> PermissionAnalyzer:
        return PermissionAnalyzer()

    @pytest.mark.asyncio
    async def test_clean_skill(self, analyzer: PermissionAnalyzer):
        sf = SkillFile(
            path="SKILL.md",
            file_type=FileType.SKILL_MD,
            sha256="abc123",
            size_bytes=100,
            content="# Hello\nA simple greeting skill.\n",
        )
        result = await analyzer.scan([sf])
        assert result.verdict == EngineVerdict.CLEAN

    @pytest.mark.asyncio
    async def test_dangerous_shell_plus_network(self, analyzer: PermissionAnalyzer):
        sf = SkillFile(
            path="SKILL.md",
            file_type=FileType.SKILL_MD,
            sha256="abc123",
            size_bytes=200,
            content=(
                "This skill can execute shell commands and "
                "fetch data from HTTP API endpoints.\n"
            ),
        )
        result = await analyzer.scan([sf])
        assert any(f.rule_id == "SG-PERM-001" for f in result.findings)

    @pytest.mark.asyncio
    async def test_env_plus_network(self, analyzer: PermissionAnalyzer):
        sf = SkillFile(
            path="SKILL.md",
            file_type=FileType.SKILL_MD,
            sha256="abc123",
            size_bytes=200,
            content=(
                "Access environment variables like os.environ and "
                "send HTTP requests to external APIs.\n"
            ),
        )
        result = await analyzer.scan([sf])
        assert any(f.rule_id == "SG-PERM-003" for f in result.findings)

    @pytest.mark.asyncio
    async def test_excessive_permissions(self, analyzer: PermissionAnalyzer):
        sf = SkillFile(
            path="SKILL.md",
            file_type=FileType.SKILL_MD,
            sha256="abc123",
            size_bytes=300,
            content=(
                "This skill needs to execute shell commands, "
                "delete files, access environment variables, "
                "and fetch data via HTTP requests.\n"
            ),
        )
        result = await analyzer.scan([sf])
        assert any(f.rule_id == "SG-PERM-004" for f in result.findings)

    @pytest.mark.asyncio
    async def test_skip_non_relevant_files(self, analyzer: PermissionAnalyzer):
        sf = SkillFile(
            path="script.py",
            file_type=FileType.SCRIPT_PYTHON,
            sha256="abc123",
            size_bytes=200,
            content="import subprocess; subprocess.run(['ls'])\n",
        )
        result = await analyzer.scan([sf])
        assert result.verdict == EngineVerdict.CLEAN

    @pytest.mark.asyncio
    async def test_health_check(self, analyzer: PermissionAnalyzer):
        assert await analyzer.health_check() is True


# ── ObfuscationDetector tests ───────────────────────────────────────

class TestObfuscationDetector:
    @pytest.fixture
    def detector(self) -> ObfuscationDetector:
        return ObfuscationDetector()

    @pytest.mark.asyncio
    async def test_clean_code(self, detector: ObfuscationDetector):
        sf = SkillFile(
            path="clean.py",
            file_type=FileType.SCRIPT_PYTHON,
            sha256="abc123",
            size_bytes=50,
            content="def greet(name):\n    return f'Hello {name}'\n",
        )
        result = await detector.scan([sf])
        assert result.verdict == EngineVerdict.CLEAN

    @pytest.mark.asyncio
    async def test_detect_base64_function(self, detector: ObfuscationDetector):
        sf = SkillFile(
            path="b64.py",
            file_type=FileType.SCRIPT_PYTHON,
            sha256="abc123",
            size_bytes=100,
            content='import base64\ndata = base64.b64decode("SGVsbG8gV29ybGQ=")\n',
        )
        result = await detector.scan([sf])
        assert any(f.rule_id == "SG-OBFUSC-001" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_hex_encoding(self, detector: ObfuscationDetector):
        sf = SkillFile(
            path="hex.py",
            file_type=FileType.SCRIPT_PYTHON,
            sha256="abc123",
            size_bytes=100,
            content='payload = "\\x68\\x65\\x6c\\x6c\\x6f\\x20\\x77\\x6f\\x72\\x6c\\x64\\x0a"\n',
        )
        result = await detector.scan([sf])
        assert any(f.rule_id == "SG-OBFUSC-003" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_chr_concatenation(self, detector: ObfuscationDetector):
        sf = SkillFile(
            path="chr.py",
            file_type=FileType.SCRIPT_PYTHON,
            sha256="abc123",
            size_bytes=100,
            content="payload = chr(104) + chr(101) + chr(108) + chr(108) + chr(111)\n",
        )
        result = await detector.scan([sf])
        assert any(f.rule_id == "SG-OBFUSC-004" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_eval_with_decode(self, detector: ObfuscationDetector):
        sf = SkillFile(
            path="evil.py",
            file_type=FileType.SCRIPT_PYTHON,
            sha256="abc123",
            size_bytes=100,
            content='eval(base64.b64decode("cHJpbnQoJ2hpJyk="))\n',
        )
        result = await detector.scan([sf])
        # Should detect both the b64decode and eval patterns
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_detect_rot13(self, detector: ObfuscationDetector):
        sf = SkillFile(
            path="rot.py",
            file_type=FileType.SCRIPT_PYTHON,
            sha256="abc123",
            size_bytes=100,
            content='import codecs\nresult = codecs.decode("uryyb", "rot_13")\n',
        )
        result = await detector.scan([sf])
        assert any(f.rule_id == "SG-OBFUSC-007" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_compression(self, detector: ObfuscationDetector):
        sf = SkillFile(
            path="packed.py",
            file_type=FileType.SCRIPT_PYTHON,
            sha256="abc123",
            size_bytes=100,
            content='import zlib\ncode = zlib.decompress(packed_data)\nexec(code)\n',
        )
        result = await detector.scan([sf])
        assert any(f.rule_id == "SG-OBFUSC-008" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_dynamic_import(self, detector: ObfuscationDetector):
        sf = SkillFile(
            path="dyn.py",
            file_type=FileType.SCRIPT_PYTHON,
            sha256="abc123",
            size_bytes=100,
            content='mod = __import__("os")\nmod.system("ls")\n',
        )
        result = await detector.scan([sf])
        assert any(f.rule_id == "SG-OBFUSC-009" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_string_reversal(self, detector: ObfuscationDetector):
        sf = SkillFile(
            path="rev.py",
            file_type=FileType.SCRIPT_PYTHON,
            sha256="abc123",
            size_bytes=100,
            content='cmd = "tac/nib/"[::-1]\n',
        )
        result = await detector.scan([sf])
        assert any(f.rule_id == "SG-OBFUSC-010" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_base64_payload(self, detector: ObfuscationDetector):
        """Test that actual base64-encoded suspicious content is detected."""
        import base64
        payload = base64.b64encode(b"import os; os.system('/bin/bash')").decode()
        sf = SkillFile(
            path="payload.py",
            file_type=FileType.SCRIPT_PYTHON,
            sha256="abc123",
            size_bytes=200,
            content=f'encoded = "{payload}"\n',
        )
        result = await detector.scan([sf])
        assert any(f.rule_id == "SG-OBFUSC-B64" for f in result.findings)

    @pytest.mark.asyncio
    async def test_health_check(self, detector: ObfuscationDetector):
        assert await detector.health_check() is True

    @pytest.mark.asyncio
    async def test_engine_metadata(self, detector: ObfuscationDetector):
        assert detector.name == "obfuscation_detector"
        assert detector.version == "0.3.0"
