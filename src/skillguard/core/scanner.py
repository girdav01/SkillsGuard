"""Main scan orchestrator.

Coordinates parallel execution of all scanning engines and produces
the final ScanResult.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from skillguard.core.hasher import hash_skill
from skillguard.core.models import (
    EngineResult,
    ScanRequest,
    ScanResult,
    SkillFile,
    SkillPlatform,
)
from skillguard.core.skill_parser import parse_skill_directory
from skillguard.core.verdict import (
    aggregate_findings_by_severity,
    calculate_risk_score,
    collect_owasp_coverage,
)
from skillguard.engines.base import ScanEngine


class ScanOrchestrator:
    """Coordinates parallel execution of all scanning engines."""

    def __init__(
        self,
        engines: list[ScanEngine],
    ) -> None:
        self.engines = engines

    async def scan(self, request: ScanRequest) -> ScanResult:
        """Execute full scan pipeline.

        1. Parse & normalize skill structure
        2. Hash all components
        3. Run all engines in parallel
        4. Aggregate verdicts into composite score
        5. Return result
        """
        scan_id = uuid.uuid4().hex[:16]
        scan_started = datetime.now(timezone.utc)

        # Parse skill files
        if request.skill_path:
            skill_files = parse_skill_directory(request.skill_path)
        else:
            raise ValueError("skill_path is required (git_url not yet supported)")

        if not skill_files:
            scan_completed = datetime.now(timezone.utc)
            return ScanResult(
                scan_id=scan_id,
                skill_name=_infer_skill_name(request),
                skill_sha256="",
                platform=request.platform,
                scan_started=scan_started,
                scan_completed=scan_completed,
                composite_score=0,
                verdict="clean",
                engine_results=[],
                total_findings=0,
                findings_by_severity={},
                files_scanned=0,
            )

        # Compute composite hash
        skill_sha256 = hash_skill([(sf.path, sf.sha256) for sf in skill_files])

        # Run all engines in parallel
        engine_results = await self._run_engines(skill_files)

        # Calculate risk score
        score, verdict = calculate_risk_score(engine_results)

        scan_completed = datetime.now(timezone.utc)

        total_findings = sum(len(r.findings) for r in engine_results)
        findings_by_severity = aggregate_findings_by_severity(engine_results)
        owasp_coverage = collect_owasp_coverage(engine_results)

        return ScanResult(
            scan_id=scan_id,
            skill_name=_infer_skill_name(request),
            skill_sha256=skill_sha256,
            platform=request.platform,
            scan_started=scan_started,
            scan_completed=scan_completed,
            composite_score=score,
            verdict=verdict,
            engine_results=engine_results,
            total_findings=total_findings,
            findings_by_severity=findings_by_severity,
            files_scanned=len(skill_files),
            owasp_coverage=owasp_coverage,
        )

    async def _run_engines(self, skill_files: list[SkillFile]) -> list[EngineResult]:
        """Run all engines in parallel and collect results."""
        tasks = []
        for engine in self.engines:
            tasks.append(self._run_single_engine(engine, skill_files))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        engine_results: list[EngineResult] = []
        for result in results:
            if isinstance(result, EngineResult):
                engine_results.append(result)
            # Exceptions from individual engines are silently skipped
            # to allow other engines to complete

        return engine_results

    async def _run_single_engine(
        self, engine: ScanEngine, skill_files: list[SkillFile]
    ) -> EngineResult:
        """Run a single engine with error handling."""
        return await engine.scan(skill_files)

    async def health_check(self) -> dict[str, bool]:
        """Check health of all engines."""
        results: dict[str, bool] = {}
        for engine in self.engines:
            try:
                results[engine.name] = await engine.health_check()
            except Exception:
                results[engine.name] = False
        return results


def _infer_skill_name(request: ScanRequest) -> str:
    """Infer skill name from the request."""
    if request.skill_path:
        from pathlib import Path

        return Path(request.skill_path).name
    if request.git_url:
        return request.git_url.rstrip("/").split("/")[-1]
    return "unknown"
