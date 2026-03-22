"""Dependency checking engine for update drift analysis.

Analyzes skill dependency files for OWASP AST07 (Update Drift) issues
including unpinned versions, missing lock files, and mutable git references.
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

# Dependency file name patterns
_DEPENDENCY_FILE_NAMES = (
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "package.json",
    "go.mod",
    "Pipfile",
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
)

# Lock file names to check for
_LOCK_FILE_NAMES = (
    "requirements.lock",
    "poetry.lock",
    "Pipfile.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
)


class DependencyChecker(ScanEngine):
    """Checks for dependency staleness and pinning issues (OWASP AST07)."""

    @property
    def name(self) -> str:
        return "dependency_checker"

    @property
    def version(self) -> str:
        return "0.4.0"

    async def scan(
        self,
        skill_files: list[SkillFile],
        rules: list[DetectionRule] | None = None,
    ) -> EngineResult:
        start = time.monotonic()
        findings: list[Finding] = []

        for sf in skill_files:
            if sf.content is None:
                continue

            if not self._is_dependency_file(sf):
                continue

            findings.extend(self._check_unpinned_versions(sf))
            findings.extend(self._check_mutable_git_refs(sf))

        # Cross-file check for missing lock files
        findings.extend(self._check_missing_lock_files(skill_files))

        elapsed_ms = int((time.monotonic() - start) * 1000)

        if not findings:
            return EngineResult(
                engine_name=self.name,
                engine_version=self.version,
                verdict=EngineVerdict.CLEAN,
                confidence=0.7,
                findings=[],
                duration_ms=elapsed_ms,
            )

        max_confidence = max(f.confidence for f in findings)
        severities = {f.severity for f in findings}
        if Severity.HIGH in severities:
            verdict = EngineVerdict.SUSPICIOUS
        else:
            verdict = EngineVerdict.CLEAN

        return EngineResult(
            engine_name=self.name,
            engine_version=self.version,
            verdict=verdict,
            confidence=max_confidence,
            detection_name="Dependency Analysis" if findings else None,
            findings=findings,
            duration_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        return True

    def _is_dependency_file(self, sf: SkillFile) -> bool:
        """Check if a file looks like a dependency file."""
        path_lower = sf.path.lower()
        for dep_name in _DEPENDENCY_FILE_NAMES:
            if path_lower.endswith(dep_name.lower()):
                return True
        return False

    def _check_unpinned_versions(self, sf: SkillFile) -> list[Finding]:
        """SG-DEP-001: Detect unpinned dependency versions."""
        findings: list[Finding] = []
        content = sf.content or ""
        path_lower = sf.path.lower()

        if "requirements" in path_lower and path_lower.endswith(".txt"):
            # Bare package name (no version specifier at all)
            bare_pattern = r"(?m)^[a-zA-Z][\w.-]*\s*$"
            for match in re.finditer(bare_pattern, content):
                line_start = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        rule_id="SG-DEP-001",
                        rule_name="Unpinned Dependency Version",
                        severity=Severity.MEDIUM,
                        category="update_drift",
                        description=(
                            "Dependency declared without a version pin. "
                            "Unpinned dependencies can introduce breaking changes or vulnerabilities."
                        ),
                        file_path=sf.path,
                        line_start=line_start,
                        snippet=match.group(0).strip(),
                        owasp_ast=["AST07"],
                        confidence=0.80,
                        remediation="Pin dependencies to exact versions (use == in requirements.txt, exact versions in package.json).",
                    )
                )

            # Range specifiers (>=, <=, ~=, *)
            range_pattern = r"(?m)>=|<=|~=|\*"
            for match in re.finditer(range_pattern, content):
                line_start = content[: match.start()].count("\n") + 1
                # Get the full line for the snippet
                line_end = content.find("\n", match.start())
                if line_end == -1:
                    line_end = len(content)
                line_begin = content.rfind("\n", 0, match.start()) + 1
                snippet = content[line_begin:line_end].strip()

                findings.append(
                    Finding(
                        rule_id="SG-DEP-001",
                        rule_name="Unpinned Dependency Version",
                        severity=Severity.MEDIUM,
                        category="update_drift",
                        description=(
                            "Dependency uses a range version specifier instead of an exact pin. "
                            "This can lead to non-reproducible builds."
                        ),
                        file_path=sf.path,
                        line_start=line_start,
                        snippet=snippet,
                        owasp_ast=["AST07"],
                        confidence=0.80,
                        remediation="Pin dependencies to exact versions (use == in requirements.txt, exact versions in package.json).",
                    )
                )

        elif path_lower.endswith("package.json"):
            pkg_pattern = r'(?i)"version"\s*:\s*"[\^~*]|"latest"'
            for match in re.finditer(pkg_pattern, content):
                line_start = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        rule_id="SG-DEP-001",
                        rule_name="Unpinned Dependency Version",
                        severity=Severity.MEDIUM,
                        category="update_drift",
                        description=(
                            "Package dependency uses a non-exact version specifier. "
                            "Caret (^), tilde (~), wildcard (*), or 'latest' versions can introduce drift."
                        ),
                        file_path=sf.path,
                        line_start=line_start,
                        snippet=match.group(0),
                        owasp_ast=["AST07"],
                        confidence=0.80,
                        remediation="Pin dependencies to exact versions (use == in requirements.txt, exact versions in package.json).",
                    )
                )

        return findings

    def _check_missing_lock_files(self, skill_files: list[SkillFile]) -> list[Finding]:
        """SG-DEP-002: Check for missing lock files across all skill files."""
        findings: list[Finding] = []
        all_paths = {sf.path.lower() for sf in skill_files}
        all_basenames = set()
        for sf in skill_files:
            # Extract basename from path
            parts = sf.path.replace("\\", "/").split("/")
            all_basenames.add(parts[-1].lower())

        has_lock_file = any(
            lock_name.lower() in all_basenames for lock_name in _LOCK_FILE_NAMES
        )

        if has_lock_file:
            return findings

        # Check if any dependency manifest file exists
        for sf in skill_files:
            path_lower = sf.path.lower()
            if path_lower.endswith("requirements.txt") or path_lower.endswith("package.json"):
                findings.append(
                    Finding(
                        rule_id="SG-DEP-002",
                        rule_name="Missing Lock File Reference",
                        severity=Severity.MEDIUM,
                        category="update_drift",
                        description=(
                            f"Dependency manifest '{sf.path}' found but no corresponding "
                            "lock file detected in the skill files. Lock files ensure "
                            "reproducible dependency resolution."
                        ),
                        file_path=sf.path,
                        owasp_ast=["AST07"],
                        confidence=0.65,
                        remediation="Include a lock file to ensure reproducible dependency resolution.",
                    )
                )

        return findings

    def _check_mutable_git_refs(self, sf: SkillFile) -> list[Finding]:
        """SG-DEP-003: Detect mutable git references."""
        findings: list[Finding] = []
        content = sf.content or ""

        # Git dependencies pointing to branches
        branch_pattern = r"(?i)(git\+https?://[^\s]+@(?:main|master|develop|dev)\b|\"[^\"]*github\.com[^\"]*#(?:main|master|develop|dev)\")"
        for match in re.finditer(branch_pattern, content):
            line_start = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    rule_id="SG-DEP-003",
                    rule_name="Mutable Git Reference",
                    severity=Severity.HIGH,
                    category="update_drift",
                    description=(
                        "Git dependency points to a mutable branch reference. "
                        "Branch contents can change at any time, making builds non-reproducible "
                        "and vulnerable to supply chain attacks."
                    ),
                    file_path=sf.path,
                    line_start=line_start,
                    snippet=match.group(0),
                    owasp_ast=["AST07"],
                    mitre_attack=["T1195.002"],
                    confidence=0.75,
                    remediation="Pin git dependencies to specific commit SHAs or release tags.",
                )
            )

        # Bare git URL without ref
        bare_git_pattern = r"(?i)git://[^\s]+(?:\.git)?(?:\s|$)"
        for match in re.finditer(bare_git_pattern, content):
            line_start = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    rule_id="SG-DEP-003",
                    rule_name="Mutable Git Reference",
                    severity=Severity.HIGH,
                    category="update_drift",
                    description=(
                        "Git dependency uses a bare git:// URL without a specific ref. "
                        "This defaults to the HEAD of the default branch, which is mutable."
                    ),
                    file_path=sf.path,
                    line_start=line_start,
                    snippet=match.group(0).strip(),
                    owasp_ast=["AST07"],
                    mitre_attack=["T1195.002"],
                    confidence=0.75,
                    remediation="Pin git dependencies to specific commit SHAs or release tags.",
                )
            )

        return findings
