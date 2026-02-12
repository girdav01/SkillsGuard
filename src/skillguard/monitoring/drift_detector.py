"""Drift detection for installed skills.

Detects "rug pull" attacks where a skill is modified after installation
to introduce malicious behavior. Compares current file hashes against
known-good baselines to detect unauthorized changes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from skillguard.core.hasher import hash_content, hash_file, hash_skill
from skillguard.core.skill_parser import parse_skill_directory


class SkillBaseline(BaseModel):
    """Stored baseline for a monitored skill."""

    skill_path: str
    skill_sha256: str
    file_hashes: dict[str, str]  # relative_path -> sha256
    verdict: str = "unknown"
    score: int = 0
    captured_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DriftResult(BaseModel):
    """Result of a drift check."""

    skill_path: str
    has_drift: bool
    added_files: list[str] = Field(default_factory=list)
    modified_files: list[str] = Field(default_factory=list)
    removed_files: list[str] = Field(default_factory=list)
    old_hash: str = ""
    new_hash: str = ""
    checked_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DriftDetector:
    """Detects unauthorized changes to monitored skills.

    Maintains baselines of known-good skill states and compares
    current state against them to detect drift/rug-pull attacks.
    """

    def __init__(self) -> None:
        self._baselines: dict[str, SkillBaseline] = {}

    async def capture_baseline(
        self,
        skill_path: str,
        verdict: str = "unknown",
        score: int = 0,
    ) -> SkillBaseline:
        """Capture the current state of a skill as a baseline.

        Args:
            skill_path: Path to the skill directory.
            verdict: The scan verdict when baseline was captured.
            score: The risk score when baseline was captured.

        Returns:
            The captured baseline.
        """
        skill_files = parse_skill_directory(skill_path)

        file_hashes: dict[str, str] = {}
        for sf in skill_files:
            file_hashes[sf.path] = sf.sha256

        skill_sha256 = hash_skill([(sf.path, sf.sha256) for sf in skill_files])

        baseline = SkillBaseline(
            skill_path=str(Path(skill_path).resolve()),
            skill_sha256=skill_sha256,
            file_hashes=file_hashes,
            verdict=verdict,
            score=score,
        )

        self._baselines[baseline.skill_path] = baseline
        return baseline

    async def check_drift(self, skill_path: str) -> DriftResult:
        """Compare current skill state against stored baseline.

        Args:
            skill_path: Path to the skill directory.

        Returns:
            DriftResult indicating if and how the skill has changed.
        """
        resolved = str(Path(skill_path).resolve())
        baseline = self._baselines.get(resolved)

        if baseline is None:
            return DriftResult(
                skill_path=resolved,
                has_drift=False,  # No baseline means nothing to compare against
            )

        # Get current state
        skill_files = parse_skill_directory(skill_path)
        current_hashes: dict[str, str] = {}
        for sf in skill_files:
            current_hashes[sf.path] = sf.sha256

        current_sha256 = hash_skill([(sf.path, sf.sha256) for sf in skill_files])

        # Quick check: composite hash unchanged?
        if current_sha256 == baseline.skill_sha256:
            return DriftResult(
                skill_path=resolved,
                has_drift=False,
                old_hash=baseline.skill_sha256,
                new_hash=current_sha256,
            )

        # Detailed diff
        baseline_files = set(baseline.file_hashes.keys())
        current_files = set(current_hashes.keys())

        added = sorted(current_files - baseline_files)
        removed = sorted(baseline_files - current_files)
        modified = sorted(
            f
            for f in baseline_files & current_files
            if baseline.file_hashes[f] != current_hashes.get(f)
        )

        return DriftResult(
            skill_path=resolved,
            has_drift=True,
            added_files=added,
            modified_files=modified,
            removed_files=removed,
            old_hash=baseline.skill_sha256,
            new_hash=current_sha256,
        )

    async def get_baseline(self, skill_path: str) -> SkillBaseline | None:
        """Get the stored baseline for a skill."""
        resolved = str(Path(skill_path).resolve())
        return self._baselines.get(resolved)

    async def remove_baseline(self, skill_path: str) -> bool:
        """Remove the baseline for a skill."""
        resolved = str(Path(skill_path).resolve())
        if resolved in self._baselines:
            del self._baselines[resolved]
            return True
        return False

    async def list_monitored(self) -> list[str]:
        """List all skill paths with stored baselines."""
        return list(self._baselines.keys())
