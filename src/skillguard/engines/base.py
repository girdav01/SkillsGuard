"""Abstract base interface for all SkillGuard scanning engines."""

from __future__ import annotations

from abc import ABC, abstractmethod

from skillguard.core.models import DetectionRule, EngineResult, SkillFile


class ScanEngine(ABC):
    """Base interface for all SkillGuard scanning engines.

    Each engine independently analyzes skill files and produces a verdict
    with confidence score and detailed findings.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique engine name (e.g., 'regex_scanner')."""

    @property
    @abstractmethod
    def version(self) -> str:
        """Engine version string."""

    @abstractmethod
    async def scan(
        self,
        skill_files: list[SkillFile],
        rules: list[DetectionRule] | None = None,
    ) -> EngineResult:
        """Scan skill files and return results.

        Args:
            skill_files: Parsed skill files to scan.
            rules: Optional specific rules (uses defaults if None).

        Returns:
            EngineResult with verdict, confidence, and findings.
        """

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if engine is operational."""
