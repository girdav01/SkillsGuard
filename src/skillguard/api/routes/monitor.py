"""Monitoring API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from skillguard.api.routes.scan import _sanitize_path
from skillguard.monitoring.drift_detector import DriftDetector, DriftResult, SkillBaseline

router = APIRouter()

# Shared drift detector instance
_drift_detector = DriftDetector()


class MonitorRequest(BaseModel):
    """Request to register a skill for monitoring."""

    skill_path: str
    verdict: str = "unknown"
    score: int = 0


class MonitorResponse(BaseModel):
    """Response after registering for monitoring."""

    skill_path: str
    status: str
    baseline_hash: str


class MonitorListResponse(BaseModel):
    """Response listing all monitored skills."""

    monitored_paths: list[str]
    count: int


@router.post("/monitor", response_model=MonitorResponse)
async def register_monitor(request: MonitorRequest) -> MonitorResponse:
    """Register a skill directory for continuous monitoring."""
    # Validate and sanitize path to prevent traversal
    safe_path = _sanitize_path(request.skill_path)

    try:
        baseline = await _drift_detector.capture_baseline(
            safe_path,
            verdict=request.verdict,
            score=request.score,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="skill path not found")
    except Exception:
        raise HTTPException(status_code=400, detail="failed to capture baseline")

    return MonitorResponse(
        skill_path=baseline.skill_path,
        status="monitoring",
        baseline_hash=baseline.skill_sha256,
    )


@router.get("/monitor", response_model=MonitorListResponse)
async def list_monitored() -> MonitorListResponse:
    """List all monitored skill directories."""
    paths = await _drift_detector.list_monitored()
    return MonitorListResponse(
        monitored_paths=paths,
        count=len(paths),
    )


@router.get("/monitor/check")
async def check_drift(skill_path: str) -> dict:
    """Check a monitored skill for drift."""
    # Validate and sanitize path to prevent traversal
    safe_path = _sanitize_path(skill_path)

    baseline = await _drift_detector.get_baseline(safe_path)
    if baseline is None:
        raise HTTPException(status_code=404, detail="Skill not being monitored")

    drift = await _drift_detector.check_drift(safe_path)
    return drift.model_dump()


@router.delete("/monitor")
async def unregister_monitor(skill_path: str) -> dict:
    """Stop monitoring a skill directory."""
    # Validate and sanitize path to prevent traversal
    safe_path = _sanitize_path(skill_path)

    removed = await _drift_detector.remove_baseline(safe_path)
    if not removed:
        raise HTTPException(status_code=404, detail="Skill not being monitored")
    return {"status": "removed", "skill_path": safe_path}
