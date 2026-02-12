"""Obfuscation detection engine for encoded payloads.

Detects various forms of obfuscation and encoding used to hide
malicious payloads in skill files, including base64, hex encoding,
string concatenation tricks, and multi-layer encoding.
"""

from __future__ import annotations

import base64
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

# Obfuscation patterns with descriptions
_OBFUSCATION_PATTERNS: list[tuple[str, str, str, Severity, list[str]]] = [
    # Base64 encoded content
    (
        "SG-OBFUSC-001",
        r"(?:atob|btoa|base64\.(?:b64)?decode|Base64\.decode|fromCharCode)\s*\(",
        "Base64 encoding/decoding function call detected",
        Severity.MEDIUM,
        ["T1027"],
    ),
    # Large base64 strings (potential encoded payloads)
    (
        "SG-OBFUSC-002",
        r"['\"][A-Za-z0-9+/]{100,}={0,2}['\"]",
        "Large base64-like encoded string detected (potential payload)",
        Severity.HIGH,
        ["T1027"],
    ),
    # Hex-encoded strings
    (
        "SG-OBFUSC-003",
        r"(?:\\x[0-9a-fA-F]{2}){8,}",
        "Hex-encoded string sequence detected",
        Severity.MEDIUM,
        ["T1027.010"],
    ),
    # String concatenation obfuscation (building strings character by character)
    (
        "SG-OBFUSC-004",
        r"""(?:chr\s*\(\s*\d+\s*\)\s*\+?\s*){4,}""",
        "Character-by-character string construction (chr() concatenation)",
        Severity.HIGH,
        ["T1027.010"],
    ),
    # Eval with string construction
    (
        "SG-OBFUSC-005",
        r"(?:eval|exec|Function)\s*\(\s*(?:atob|String\.fromCharCode|chr|decode|decompress)",
        "Eval/exec with encoded input detected",
        Severity.CRITICAL,
        ["T1027", "T1059"],
    ),
    # Unicode escape sequences
    (
        "SG-OBFUSC-006",
        r"(?:\\u[0-9a-fA-F]{4}){6,}",
        "Long unicode escape sequence detected (potential obfuscation)",
        Severity.MEDIUM,
        ["T1027.010"],
    ),
    # ROT13 / Caesar cipher
    (
        "SG-OBFUSC-007",
        r"(?i)(?:rot13|codecs\.decode.*?rot_13|tr\s+['\"]A-Za-z['\"])",
        "ROT13 or character rotation encoding detected",
        Severity.MEDIUM,
        ["T1027"],
    ),
    # Compressed/packed code
    (
        "SG-OBFUSC-008",
        r"(?i)(?:zlib\.decompress|gzip\.decompress|bz2\.decompress|lzma\.decompress|inflate\s*\()",
        "Runtime decompression detected (potential packed payload)",
        Severity.HIGH,
        ["T1027"],
    ),
    # Dynamic function construction
    (
        "SG-OBFUSC-009",
        r"(?:getattr|__import__)\s*\(\s*['\"][^'\"]+['\"]\s*\)",
        "Dynamic attribute/module access (potential obfuscation of imports)",
        Severity.MEDIUM,
        ["T1027.010"],
    ),
    # Reverse string tricks
    (
        "SG-OBFUSC-010",
        r"\[::\s*-1\s*\]|\.reverse\(\)|reversed\(",
        "String reversal detected (common obfuscation technique)",
        Severity.LOW,
        ["T1027"],
    ),
]


class ObfuscationDetector(ScanEngine):
    """Detects obfuscated code and encoded payloads in skill files."""

    @property
    def name(self) -> str:
        return "obfuscation_detector"

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

        for sf in skill_files:
            if sf.content is None:
                continue

            # Check scripts and other text files
            findings.extend(self._check_patterns(sf))

            # Check for actual decodable base64 payloads
            if sf.file_type in {
                FileType.SCRIPT_PYTHON,
                FileType.SCRIPT_BASH,
                FileType.SCRIPT_JS,
                FileType.SKILL_MD,
            }:
                findings.extend(self._check_base64_payloads(sf))

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
        if Severity.CRITICAL in severities:
            verdict = EngineVerdict.MALICIOUS
        elif Severity.HIGH in severities:
            verdict = EngineVerdict.SUSPICIOUS
        else:
            verdict = EngineVerdict.CLEAN

        return EngineResult(
            engine_name=self.name,
            engine_version=self.version,
            verdict=verdict,
            confidence=max_confidence,
            detection_name="Obfuscation Detection" if findings else None,
            findings=findings,
            duration_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        return True

    def _check_patterns(self, sf: SkillFile) -> list[Finding]:
        findings: list[Finding] = []
        content = sf.content or ""

        for rule_id, pattern, description, severity, mitre_ids in _OBFUSCATION_PATTERNS:
            try:
                compiled = re.compile(pattern, re.MULTILINE)
            except re.error:
                continue

            for match in compiled.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        rule_name=f"Obfuscation: {description[:50]}",
                        severity=severity,
                        category="obfuscation",
                        description=description,
                        file_path=sf.path,
                        line_start=line_num,
                        snippet=match.group()[:200],
                        owasp_llm=["LLM06"],
                        mitre_attack=mitre_ids,
                        confidence=0.80,
                        remediation="Remove obfuscation and use clear, readable code.",
                    )
                )

        return findings

    def _check_base64_payloads(self, sf: SkillFile) -> list[Finding]:
        """Check for actual base64-encoded payloads that decode to suspicious content."""
        findings: list[Finding] = []
        content = sf.content or ""

        # Find base64-like strings
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
        for match in b64_pattern.finditer(content):
            b64_str = match.group()
            try:
                decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
            except Exception:
                continue

            # Check if decoded content contains suspicious patterns
            suspicious_keywords = [
                "import os", "subprocess", "socket", "/bin/sh", "/bin/bash",
                "eval(", "exec(", "curl ", "wget ", "nc ", "python -c",
                "powershell", "cmd.exe",
            ]
            for keyword in suspicious_keywords:
                if keyword.lower() in decoded.lower():
                    line_num = content[:match.start()].count("\n") + 1
                    findings.append(
                        Finding(
                            rule_id="SG-OBFUSC-B64",
                            rule_name="Decoded Base64 Contains Suspicious Code",
                            severity=Severity.CRITICAL,
                            category="obfuscation",
                            description=(
                                f"Base64-encoded string decodes to content containing "
                                f"'{keyword}', suggesting a hidden payload."
                            ),
                            file_path=sf.path,
                            line_start=line_num,
                            snippet=f"Encoded: {b64_str[:60]}... -> Decoded: {decoded[:100]}...",
                            owasp_llm=["LLM06"],
                            mitre_attack=["T1027", "T1059"],
                            confidence=0.92,
                            remediation="Remove base64-encoded executable content.",
                        )
                    )
                    break

        return findings
