"""Regex-based scanning engine for prompt injection and other patterns.

This is the primary MVP engine that uses YAML-defined regex rules
to detect threats in skill files.
"""

from __future__ import annotations

import re
import time
from typing import Any

from skillguard.core.models import (
    DetectionRule,
    EngineResult,
    EngineVerdict,
    FileType,
    Finding,
    Severity,
    SkillFile,
)
from skillguard.core.rules_loader import load_rules
from skillguard.engines.base import ScanEngine

# File types that should be scanned for natural-language injection
_NL_TARGETS = {FileType.SKILL_MD, FileType.FRONTMATTER, FileType.TEMPLATE}

# File types that are scripts
_SCRIPT_TARGETS = {
    FileType.SCRIPT_PYTHON,
    FileType.SCRIPT_BASH,
    FileType.SCRIPT_JS,
    FileType.SCRIPT_TS,
}

# Mapping from rule target string to which file types match
_TARGET_MAP: dict[str, set[FileType]] = {
    "SKILL_MD": {FileType.SKILL_MD},
    "FRONTMATTER": {FileType.FRONTMATTER},
    "SCRIPT": _SCRIPT_TARGETS,
    "ANY": _NL_TARGETS | _SCRIPT_TARGETS | {FileType.CONFIG, FileType.OTHER},
    "CONFIG": {FileType.CONFIG},
}


class RegexScanner(ScanEngine):
    """Regex-based pattern matching engine."""

    def __init__(self, rules_dir: str | None = None) -> None:
        self._rules_dir = rules_dir
        self._rules: list[DetectionRule] | None = None

    @property
    def name(self) -> str:
        return "regex_scanner"

    @property
    def version(self) -> str:
        return "0.1.0"

    def _get_rules(self) -> list[DetectionRule]:
        if self._rules is None:
            self._rules = load_rules(
                rules_dir=self._rules_dir,
                engine_filter="REGEX",
            )
        return self._rules

    async def scan(
        self,
        skill_files: list[SkillFile],
        rules: list[DetectionRule] | None = None,
    ) -> EngineResult:
        start = time.monotonic()
        active_rules = rules if rules is not None else self._get_rules()
        all_findings: list[Finding] = []

        for sf in skill_files:
            if sf.content is None:
                continue
            for rule in active_rules:
                if not _file_matches_target(sf, rule.target):
                    continue
                findings = _apply_rule(rule, sf)
                all_findings.extend(findings)

        elapsed_ms = int((time.monotonic() - start) * 1000)

        verdict = _compute_verdict(all_findings)
        confidence = _compute_confidence(all_findings)

        return EngineResult(
            engine_name=self.name,
            engine_version=self.version,
            verdict=verdict,
            confidence=confidence,
            detection_name=_top_detection_name(all_findings),
            findings=all_findings,
            duration_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        return True


def _file_matches_target(sf: SkillFile, target: str) -> bool:
    """Check if a SkillFile matches the rule's target specification."""
    target_upper = target.upper()
    allowed = _TARGET_MAP.get(target_upper)
    if allowed is None:
        return True  # Unknown target = scan everything
    return sf.file_type in allowed


def _apply_rule(rule: DetectionRule, sf: SkillFile) -> list[Finding]:
    """Apply a single regex rule to a file's content."""
    if sf.content is None:
        return []

    patterns = _extract_patterns(rule.pattern)
    findings: list[Finding] = []
    lines = sf.content.splitlines()

    for pattern_str in patterns:
        try:
            compiled = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
        except re.error:
            continue

        for match in compiled.finditer(sf.content):
            line_start = sf.content[:match.start()].count("\n") + 1
            line_end = sf.content[:match.end()].count("\n") + 1

            # Extract snippet (matched line with context)
            snippet_start = max(0, line_start - 2)
            snippet_end = min(len(lines), line_end + 1)
            snippet = "\n".join(lines[snippet_start:snippet_end])
            if len(snippet) > 500:
                snippet = snippet[:500] + "..."

            findings.append(
                Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    file_path=sf.path,
                    line_start=line_start,
                    line_end=line_end,
                    snippet=snippet,
                    owasp_llm=rule.owasp_llm,
                    mitre_attack=rule.mitre_attack,
                    confidence=0.8,
                    remediation=rule.remediation,
                )
            )

    return findings


def _extract_patterns(pattern: str | dict | Any) -> list[str]:
    """Extract regex pattern strings from a rule's pattern field.

    Supports:
      - Simple string pattern
      - Dict with 'any' key containing a list of patterns
      - Dict with 'all' key containing a list of patterns
    """
    if isinstance(pattern, str):
        return [pattern]
    if isinstance(pattern, dict):
        if "any" in pattern:
            return [p for p in pattern["any"] if isinstance(p, str)]
        if "all" in pattern:
            return [p for p in pattern["all"] if isinstance(p, str)]
        if "pattern" in pattern:
            return [pattern["pattern"]] if isinstance(pattern["pattern"], str) else []
    return []


def _compute_verdict(findings: list[Finding]) -> EngineVerdict:
    """Compute engine verdict from findings."""
    if not findings:
        return EngineVerdict.CLEAN

    severities = {f.severity for f in findings}
    if Severity.CRITICAL in severities:
        return EngineVerdict.MALICIOUS
    if Severity.HIGH in severities:
        return EngineVerdict.MALICIOUS
    if Severity.MEDIUM in severities:
        return EngineVerdict.SUSPICIOUS
    return EngineVerdict.CLEAN


def _compute_confidence(findings: list[Finding]) -> float:
    """Compute overall confidence from findings."""
    if not findings:
        return 1.0
    return max(f.confidence for f in findings)


def _top_detection_name(findings: list[Finding]) -> str | None:
    """Get the name of the highest-severity finding."""
    if not findings:
        return None
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    for sev in severity_order:
        for f in findings:
            if f.severity == sev:
                return f.rule_name
    return findings[0].rule_name
