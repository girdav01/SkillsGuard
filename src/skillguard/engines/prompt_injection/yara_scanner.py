"""YARA-based scanning engine for pattern detection.

Uses YARA rules for matching obfuscation patterns, malware signatures,
and complex multi-pattern detection that goes beyond simple regex.
"""

from __future__ import annotations

import time
from pathlib import Path

from skillguard.core.models import (
    DetectionRule,
    EngineResult,
    EngineVerdict,
    Finding,
    Severity,
    SkillFile,
)
from skillguard.engines.base import ScanEngine

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

_DEFAULT_YARA_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent / "yara_rules"


class YaraScanner(ScanEngine):
    """YARA rule-based scanning engine."""

    def __init__(self, yara_dir: str | Path | None = None) -> None:
        self._yara_dir = Path(yara_dir) if yara_dir else _DEFAULT_YARA_DIR
        self._compiled_rules: object | None = None

    @property
    def name(self) -> str:
        return "yara_scanner"

    @property
    def version(self) -> str:
        return "0.1.0"

    def _get_compiled_rules(self) -> object | None:
        """Compile YARA rules from the rules directory."""
        if not YARA_AVAILABLE:
            return None
        if self._compiled_rules is not None:
            return self._compiled_rules

        if not self._yara_dir.exists():
            return None

        yar_files = list(self._yara_dir.glob("*.yar"))
        if not yar_files:
            return None

        filepaths = {f.stem: str(f) for f in yar_files}
        try:
            self._compiled_rules = yara.compile(filepaths=filepaths)  # type: ignore[union-attr]
        except Exception:
            return None

        return self._compiled_rules

    async def scan(
        self,
        skill_files: list[SkillFile],
        rules: list[DetectionRule] | None = None,
    ) -> EngineResult:
        start = time.monotonic()
        findings: list[Finding] = []

        compiled = self._get_compiled_rules()
        if compiled is None:
            # YARA not available - return clean with no findings
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return EngineResult(
                engine_name=self.name,
                engine_version=self.version,
                verdict=EngineVerdict.CLEAN,
                confidence=0.0,
                findings=[],
                duration_ms=elapsed_ms,
            )

        for sf in skill_files:
            if sf.content is None:
                continue
            try:
                matches = compiled.match(data=sf.content)  # type: ignore[union-attr]
                for match in matches:
                    severity = _yara_meta_severity(match)
                    category = _yara_meta_value(match, "category", "malware")
                    findings.append(
                        Finding(
                            rule_id=f"YARA-{match.rule}",
                            rule_name=match.rule,
                            severity=severity,
                            category=category,
                            description=_yara_meta_value(
                                match, "description", f"YARA rule matched: {match.rule}"
                            ),
                            file_path=sf.path,
                            snippet=_yara_match_snippet(match, sf.content),
                            owasp_llm=_yara_meta_list(match, "owasp_llm"),
                            mitre_attack=_yara_meta_list(match, "mitre_attack"),
                            confidence=0.85,
                            remediation=_yara_meta_value(match, "remediation"),
                        )
                    )
            except Exception:
                continue

        elapsed_ms = int((time.monotonic() - start) * 1000)
        verdict = _compute_verdict(findings)
        confidence = max((f.confidence for f in findings), default=0.0)

        return EngineResult(
            engine_name=self.name,
            engine_version=self.version,
            verdict=verdict,
            confidence=confidence,
            findings=findings,
            duration_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        return YARA_AVAILABLE


def _yara_meta_severity(match: object) -> Severity:
    """Extract severity from YARA rule metadata."""
    meta = getattr(match, "meta", {})
    sev = meta.get("severity", "medium").lower()
    try:
        return Severity(sev)
    except ValueError:
        return Severity.MEDIUM


def _yara_meta_value(match: object, key: str, default: str | None = None) -> str | None:
    """Extract a string metadata value from a YARA match."""
    meta = getattr(match, "meta", {})
    return meta.get(key, default)


def _yara_meta_list(match: object, key: str) -> list[str]:
    """Extract a list metadata value from a YARA match."""
    meta = getattr(match, "meta", {})
    val = meta.get(key, "")
    if isinstance(val, list):
        return val
    if isinstance(val, str) and val:
        return [v.strip() for v in val.split(",")]
    return []


def _yara_match_snippet(match: object, content: str) -> str | None:
    """Extract a snippet from a YARA match."""
    strings = getattr(match, "strings", [])
    if not strings:
        return None
    # Get the first matched string's offset
    first = strings[0]
    instances = getattr(first, "instances", [])
    if not instances:
        return None
    offset = instances[0].offset
    start = max(0, offset - 50)
    end = min(len(content), offset + 100)
    return content[start:end]


def _compute_verdict(findings: list[Finding]) -> EngineVerdict:
    if not findings:
        return EngineVerdict.CLEAN
    severities = {f.severity for f in findings}
    if Severity.CRITICAL in severities or Severity.HIGH in severities:
        return EngineVerdict.MALICIOUS
    if Severity.MEDIUM in severities:
        return EngineVerdict.SUSPICIOUS
    return EngineVerdict.CLEAN
