"""Integration tests for the full scan pipeline."""

from __future__ import annotations

from pathlib import Path

import pytest

from skillguard.core.models import ScanRequest, SkillPlatform, Verdict
from skillguard.core.scanner import ScanOrchestrator
from skillguard.engines.prompt_injection.regex_scanner import RegexScanner
from skillguard.engines.sast.secret_detector import SecretDetector


@pytest.fixture
def orchestrator() -> ScanOrchestrator:
    engines = [
        RegexScanner(),
        SecretDetector(),
    ]
    return ScanOrchestrator(engines=engines)


class TestScanOrchestrator:
    @pytest.mark.asyncio
    async def test_scan_clean_skill(
        self, orchestrator: ScanOrchestrator, clean_skill_path: Path
    ):
        request = ScanRequest(
            skill_path=str(clean_skill_path),
            platform=SkillPlatform.CLAUDE_CODE,
        )
        result = await orchestrator.scan(request)

        assert result.scan_id != ""
        assert result.skill_name == "clean_skill"
        assert result.skill_sha256 != ""
        assert result.files_scanned >= 2
        assert result.composite_score < 41  # Should not be suspicious

    @pytest.mark.asyncio
    async def test_scan_malicious_skill(
        self, orchestrator: ScanOrchestrator, malicious_skill_path: Path
    ):
        request = ScanRequest(
            skill_path=str(malicious_skill_path),
            platform=SkillPlatform.GENERIC,
        )
        result = await orchestrator.scan(request)

        assert result.scan_id != ""
        assert result.total_findings > 0
        assert result.composite_score > 0
        # Should detect at least some threats
        assert len(result.engine_results) >= 2

    @pytest.mark.asyncio
    async def test_scan_nonexistent_path(self, orchestrator: ScanOrchestrator):
        request = ScanRequest(skill_path="/nonexistent/path")
        with pytest.raises(FileNotFoundError):
            await orchestrator.scan(request)

    @pytest.mark.asyncio
    async def test_scan_result_has_timestamps(
        self, orchestrator: ScanOrchestrator, clean_skill_path: Path
    ):
        request = ScanRequest(skill_path=str(clean_skill_path))
        result = await orchestrator.scan(request)
        assert result.scan_started is not None
        assert result.scan_completed is not None
        assert result.scan_completed >= result.scan_started

    @pytest.mark.asyncio
    async def test_health_check(self, orchestrator: ScanOrchestrator):
        health = await orchestrator.health_check()
        assert "regex_scanner" in health
        assert "secret_detector" in health
        assert health["regex_scanner"] is True
        assert health["secret_detector"] is True
