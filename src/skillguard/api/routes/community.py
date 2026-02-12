"""Community verdicts API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from skillguard.intelligence.community import (
    CommunityComment,
    CommunityVerdict,
    CommunityVerdicts,
    SkillReputation,
)

router = APIRouter()

# Shared community verdicts instance
_community = CommunityVerdicts()


class VerdictSubmitRequest(BaseModel):
    """Request to submit a community verdict."""

    analyst_id: str
    verdict: str  # clean, suspicious, malicious
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    comment: str = ""


class CommentSubmitRequest(BaseModel):
    """Request to submit a comment on a skill."""

    author_id: str
    text: str


@router.get("/community/{sha256}", response_model=SkillReputation)
async def get_reputation(sha256: str) -> SkillReputation:
    """Get the community reputation for a skill by its SHA256 hash."""
    return await _community.get_reputation(sha256)


@router.post("/community/{sha256}/verdict")
async def submit_verdict(sha256: str, request: VerdictSubmitRequest) -> dict:
    """Submit a community verdict for a skill."""
    if request.verdict not in ("clean", "suspicious", "malicious"):
        raise HTTPException(
            status_code=400,
            detail="Verdict must be one of: clean, suspicious, malicious",
        )

    verdict = CommunityVerdict(
        analyst_id=request.analyst_id,
        verdict=request.verdict,
        confidence=request.confidence,
        comment=request.comment,
    )
    await _community.add_verdict(sha256, verdict)

    count = await _community.get_verdict_count(sha256)
    return {"status": "submitted", "total_verdicts": count}


@router.post("/community/{sha256}/comment")
async def submit_comment(sha256: str, request: CommentSubmitRequest) -> dict:
    """Submit a comment on a skill."""
    comment = CommunityComment(
        author_id=request.author_id,
        text=request.text,
    )
    await _community.add_comment(sha256, comment)
    return {"status": "submitted"}
