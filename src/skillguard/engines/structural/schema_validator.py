"""Schema validation engine for skill structure.

Validates that skill files conform to expected structure and
identifies anomalies that could indicate tampering or malicious intent.
"""

from __future__ import annotations

import re
import time

from skillguard.core.models import (
    DetectionRule,
    EngineResult,
    EngineVerdict,
    FileType,
    Finding,
    Severity,
    SkillFile,
)
from skillguard.engines.base import ScanEngine

# Expected sections in a well-formed SKILL.md
_EXPECTED_SECTIONS = {"description", "usage", "instructions", "examples"}

# Maximum reasonable file sizes (bytes)
_MAX_SKILL_MD_SIZE = 100_000
_MAX_SCRIPT_SIZE = 500_000


class SchemaValidator(ScanEngine):
    """Validates skill structure against expected schemas."""

    @property
    def name(self) -> str:
        return "schema_validator"

    @property
    def version(self) -> str:
        return "0.3.0"

    async def scan(
        self,
        skill_files: list[SkillFile],
        rules: list[DetectionRule] | None = None,
    ) -> EngineResult:
        start = time.monotonic()
        findings: list[Finding] = []

        # Check overall skill structure
        findings.extend(self._validate_structure(skill_files))

        # Validate individual files
        for sf in skill_files:
            findings.extend(self._validate_file(sf))

        elapsed_ms = int((time.monotonic() - start) * 1000)

        if not findings:
            return EngineResult(
                engine_name=self.name,
                engine_version=self.version,
                verdict=EngineVerdict.CLEAN,
                confidence=0.8,
                findings=[],
                duration_ms=elapsed_ms,
            )

        max_confidence = max(f.confidence for f in findings)
        severities = {f.severity for f in findings}
        if Severity.CRITICAL in severities or Severity.HIGH in severities:
            verdict = EngineVerdict.SUSPICIOUS
        elif Severity.MEDIUM in severities:
            verdict = EngineVerdict.SUSPICIOUS
        else:
            verdict = EngineVerdict.CLEAN

        return EngineResult(
            engine_name=self.name,
            engine_version=self.version,
            verdict=verdict,
            confidence=max_confidence,
            detection_name="Schema Validation" if findings else None,
            findings=findings,
            duration_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        return True

    def _validate_structure(self, skill_files: list[SkillFile]) -> list[Finding]:
        findings: list[Finding] = []

        # Check for SKILL.md presence
        has_skill_md = any(sf.file_type == FileType.SKILL_MD for sf in skill_files)
        if not has_skill_md:
            findings.append(
                Finding(
                    rule_id="SG-STRUCT-001",
                    rule_name="Missing SKILL.md",
                    severity=Severity.LOW,
                    category="structural",
                    description="No SKILL.md found. Skills should have a main description file.",
                    file_path="(skill root)",
                    confidence=0.90,
                )
            )

        # Check for suspiciously many executable scripts
        script_count = sum(
            1 for sf in skill_files
            if sf.file_type in {FileType.SCRIPT_PYTHON, FileType.SCRIPT_BASH, FileType.SCRIPT_JS}
        )
        if script_count > 10:
            findings.append(
                Finding(
                    rule_id="SG-STRUCT-002",
                    rule_name="Excessive Script Files",
                    severity=Severity.MEDIUM,
                    category="structural",
                    description=f"Skill contains {script_count} executable scripts, which is unusually high.",
                    file_path="(skill root)",
                    confidence=0.65,
                    remediation="Review whether all scripts are necessary.",
                )
            )

        # Check for hidden files
        hidden_files = [sf for sf in skill_files if sf.path.split("/")[-1].startswith(".")]
        for sf in hidden_files:
            findings.append(
                Finding(
                    rule_id="SG-STRUCT-003",
                    rule_name="Hidden File Detected",
                    severity=Severity.LOW,
                    category="structural",
                    description=f"Hidden file '{sf.path}' detected in skill package.",
                    file_path=sf.path,
                    confidence=0.60,
                )
            )

        return findings

    def _validate_file(self, sf: SkillFile) -> list[Finding]:
        findings: list[Finding] = []

        # Check file size limits
        if sf.file_type == FileType.SKILL_MD and sf.size_bytes > _MAX_SKILL_MD_SIZE:
            findings.append(
                Finding(
                    rule_id="SG-STRUCT-004",
                    rule_name="Oversized SKILL.md",
                    severity=Severity.MEDIUM,
                    category="structural",
                    description=f"SKILL.md is {sf.size_bytes:,} bytes, exceeding the {_MAX_SKILL_MD_SIZE:,} byte limit.",
                    file_path=sf.path,
                    confidence=0.75,
                    remediation="Reduce SKILL.md size. Large files may contain hidden payloads.",
                )
            )

        # Check for binary content in text files
        if sf.content and sf.file_type in {FileType.SKILL_MD, FileType.FRONTMATTER}:
            null_count = sf.content.count("\x00")
            if null_count > 0:
                findings.append(
                    Finding(
                        rule_id="SG-STRUCT-005",
                        rule_name="Binary Content in Text File",
                        severity=Severity.HIGH,
                        category="structural",
                        description="Text file contains null bytes, suggesting binary content or data hiding.",
                        file_path=sf.path,
                        confidence=0.85,
                    )
                )

        return findings
