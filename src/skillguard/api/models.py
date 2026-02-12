"""Pydantic models for API request/response schemas."""

from __future__ import annotations

from pydantic import BaseModel

from skillguard.core.models import ScanResult, SkillPlatform


class ScanSubmitRequest(BaseModel):
    """Request body for submitting a scan."""

    skill_path: str | None = None
    git_url: str | None = None
    scan_type: str = "full"
    platform: SkillPlatform = SkillPlatform.GENERIC


class ScanSubmitResponse(BaseModel):
    """Response after submitting a scan."""

    scan_id: str
    status: str


class ScanStatusResponse(BaseModel):
    """Response for scan status check."""

    scan_id: str
    status: str
    result: ScanResult | None = None


class SkillReputationResponse(BaseModel):
    """Response for skill reputation lookup."""

    sha256: str
    status: str  # "known" | "not_seen"
    verdict: str | None = None
    composite_score: int | None = None
    last_scanned: str | None = None


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str
    detail: str | None = None
