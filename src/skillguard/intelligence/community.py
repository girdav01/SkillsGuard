"""Community verdicts and reputation system.

Provides a community-driven reputation layer where analysts can
submit verdicts and comments on scanned skills.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class CommunityVerdict(BaseModel):
    """A single community verdict on a skill."""

    analyst_id: str
    verdict: str  # clean, suspicious, malicious
    confidence: float = Field(ge=0.0, le=1.0)
    comment: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CommunityComment(BaseModel):
    """A comment on a scanned skill."""

    author_id: str
    text: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SkillReputation(BaseModel):
    """Aggregated community reputation for a skill."""

    sha256: str
    total_verdicts: int = 0
    malicious_count: int = 0
    suspicious_count: int = 0
    clean_count: int = 0
    consensus_verdict: str | None = None
    consensus_confidence: float = 0.0
    comments: list[CommunityComment] = Field(default_factory=list)
    first_seen: str | None = None
    last_updated: str | None = None


class CommunityVerdicts:
    """Community verdict and reputation management.

    Stores and aggregates community verdicts for skills to
    provide a consensus-based reputation score.
    """

    def __init__(self) -> None:
        self._verdicts: dict[str, list[CommunityVerdict]] = {}
        self._comments: dict[str, list[CommunityComment]] = {}

    async def add_verdict(self, sha256: str, verdict: CommunityVerdict) -> None:
        """Add a community verdict for a skill."""
        if sha256 not in self._verdicts:
            self._verdicts[sha256] = []
        self._verdicts[sha256].append(verdict)

    async def add_comment(self, sha256: str, comment: CommunityComment) -> None:
        """Add a comment on a skill."""
        if sha256 not in self._comments:
            self._comments[sha256] = []
        self._comments[sha256].append(comment)

    async def get_reputation(self, sha256: str) -> SkillReputation:
        """Get the aggregated community reputation for a skill."""
        verdicts = self._verdicts.get(sha256, [])
        comments = self._comments.get(sha256, [])

        malicious = sum(1 for v in verdicts if v.verdict == "malicious")
        suspicious = sum(1 for v in verdicts if v.verdict == "suspicious")
        clean = sum(1 for v in verdicts if v.verdict == "clean")
        total = len(verdicts)

        consensus_verdict = None
        consensus_confidence = 0.0
        if total > 0:
            if malicious > total / 2:
                consensus_verdict = "malicious"
                consensus_confidence = malicious / total
            elif (malicious + suspicious) > total / 2:
                consensus_verdict = "suspicious"
                consensus_confidence = (malicious + suspicious) / total
            elif clean > total / 2:
                consensus_verdict = "clean"
                consensus_confidence = clean / total

        first_seen = None
        last_updated = None
        if verdicts:
            timestamps = [v.timestamp for v in verdicts]
            first_seen = min(timestamps)
            last_updated = max(timestamps)

        return SkillReputation(
            sha256=sha256,
            total_verdicts=total,
            malicious_count=malicious,
            suspicious_count=suspicious,
            clean_count=clean,
            consensus_verdict=consensus_verdict,
            consensus_confidence=round(consensus_confidence, 3),
            comments=comments,
            first_seen=first_seen,
            last_updated=last_updated,
        )

    async def get_verdict_count(self, sha256: str) -> int:
        """Get the number of verdicts for a skill."""
        return len(self._verdicts.get(sha256, []))
