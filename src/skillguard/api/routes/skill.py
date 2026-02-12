"""Skill reputation lookup routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from skillguard.api.models import SkillReputationResponse

router = APIRouter()

# In-memory reputation store for MVP
_reputation_db: dict[str, dict] = {}


@router.get("/skill/{sha256}", response_model=SkillReputationResponse)
async def lookup_skill(sha256: str) -> SkillReputationResponse:
    """Instant reputation lookup by skill hash."""
    # Check in-memory store first
    if sha256 in _reputation_db:
        entry = _reputation_db[sha256]
        return SkillReputationResponse(
            sha256=sha256,
            status="known",
            verdict=entry.get("verdict"),
            composite_score=entry.get("composite_score"),
            last_scanned=entry.get("last_scanned"),
        )

    # Also check recent scan results
    from skillguard.api.routes.scan import _scan_results

    for result in _scan_results.values():
        if result.skill_sha256 == sha256:
            verdict_val = (
                result.verdict
                if isinstance(result.verdict, str)
                else result.verdict.value
            )
            return SkillReputationResponse(
                sha256=sha256,
                status="known",
                verdict=verdict_val,
                composite_score=result.composite_score,
                last_scanned=result.scan_completed.isoformat(),
            )

    return SkillReputationResponse(sha256=sha256, status="not_seen")
