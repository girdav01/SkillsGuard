"""Secret detection engine for finding hardcoded credentials and API keys.

Uses pattern matching to detect secrets, tokens, API keys, and other
sensitive information embedded in skill files.
"""

from __future__ import annotations

import re
import time

from skillguard.core.models import (
    DetectionRule,
    EngineResult,
    EngineVerdict,
    Finding,
    Severity,
    SkillFile,
)
from skillguard.engines.base import ScanEngine

# Patterns for detecting secrets - (name, pattern, severity)
_SECRET_PATTERNS: list[tuple[str, str, Severity]] = [
    # API Keys
    (
        "AWS Access Key",
        r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        Severity.CRITICAL,
    ),
    (
        "AWS Secret Key",
        r"(?i)aws[_\-\s]*secret[_\-\s]*(?:access)?[_\-\s]*key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})",
        Severity.CRITICAL,
    ),
    (
        "GitHub Token",
        r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
        Severity.CRITICAL,
    ),
    (
        "GitHub Fine-grained PAT",
        r"github_pat_[A-Za-z0-9_]{22,}",
        Severity.CRITICAL,
    ),
    (
        "Slack Token",
        r"xox[bporas]-[0-9]{10,}-[A-Za-z0-9-]+",
        Severity.HIGH,
    ),
    (
        "Slack Webhook",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        Severity.HIGH,
    ),
    (
        "OpenAI API Key",
        r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
        Severity.CRITICAL,
    ),
    (
        "Anthropic API Key",
        r"sk-ant-[A-Za-z0-9\-_]{40,}",
        Severity.CRITICAL,
    ),
    (
        "Google API Key",
        r"AIza[0-9A-Za-z\-_]{35}",
        Severity.HIGH,
    ),
    (
        "Stripe Secret Key",
        r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
        Severity.CRITICAL,
    ),
    (
        "Stripe Publishable Key",
        r"pk_(?:live|test)_[0-9a-zA-Z]{24,}",
        Severity.MEDIUM,
    ),
    (
        "Twilio API Key",
        r"SK[a-f0-9]{32}",
        Severity.HIGH,
    ),
    (
        "SendGrid API Key",
        r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
        Severity.HIGH,
    ),
    (
        "Mailgun API Key",
        r"key-[0-9a-zA-Z]{32}",
        Severity.HIGH,
    ),
    (
        "Discord Bot Token",
        r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}",
        Severity.HIGH,
    ),
    (
        "Heroku API Key",
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        Severity.MEDIUM,
    ),
    # Private Keys
    (
        "RSA Private Key",
        r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
        Severity.CRITICAL,
    ),
    (
        "SSH Private Key (EC)",
        r"-----BEGIN EC PRIVATE KEY-----",
        Severity.CRITICAL,
    ),
    (
        "SSH Private Key (OpenSSH)",
        r"-----BEGIN OPENSSH PRIVATE KEY-----",
        Severity.CRITICAL,
    ),
    (
        "PGP Private Key",
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        Severity.CRITICAL,
    ),
    # Generic patterns
    (
        "Generic Secret Assignment",
        r"""(?i)(?:secret|password|passwd|pwd|token|auth_token|api_key|apikey|access_key)\s*[=:]\s*['"][A-Za-z0-9+/=_\-]{16,}['"]""",
        Severity.HIGH,
    ),
    (
        "Basic Auth in URL",
        r"https?://[^:]+:[^@]+@[^\s]+",
        Severity.HIGH,
    ),
    (
        "Bearer Token",
        r"""(?i)(?:bearer|authorization)\s*[=:]\s*['"]?[A-Za-z0-9\-._~+/]+=*['"]?""",
        Severity.MEDIUM,
    ),
    (
        "JWT Token",
        r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        Severity.HIGH,
    ),
    (
        "Connection String",
        r"(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^\s'\"]+",
        Severity.HIGH,
    ),
]


class SecretDetector(ScanEngine):
    """Engine for detecting hardcoded secrets and credentials."""

    @property
    def name(self) -> str:
        return "secret_detector"

    @property
    def version(self) -> str:
        return "0.1.0"

    async def scan(
        self,
        skill_files: list[SkillFile],
        rules: list[DetectionRule] | None = None,
    ) -> EngineResult:
        start = time.monotonic()
        findings: list[Finding] = []

        compiled_patterns = [
            (name, re.compile(pattern), severity)
            for name, pattern, severity in _SECRET_PATTERNS
        ]

        for sf in skill_files:
            if sf.content is None:
                continue
            lines = sf.content.splitlines()
            for secret_name, regex, severity in compiled_patterns:
                for match in regex.finditer(sf.content):
                    line_num = sf.content[: match.start()].count("\n") + 1
                    # Redact the actual secret in the snippet
                    matched_text = match.group()
                    redacted = matched_text[:8] + "..." + matched_text[-4:]
                    snippet_line = lines[line_num - 1] if line_num <= len(lines) else ""

                    findings.append(
                        Finding(
                            rule_id=f"SG-SECRET-{secret_name.replace(' ', '_').upper()}",
                            rule_name=f"Hardcoded {secret_name}",
                            severity=severity,
                            category="credential_theft",
                            description=f"Potential {secret_name} found in file. "
                            "Hardcoded secrets can be extracted and misused.",
                            file_path=sf.path,
                            line_start=line_num,
                            line_end=line_num,
                            snippet=_redact_line(snippet_line),
                            cwe="CWE-798",
                            owasp_llm=["LLM06"],
                            confidence=0.75,
                            remediation="Remove hardcoded secrets and use environment "
                            "variables or a secret manager instead.",
                        )
                    )

        elapsed_ms = int((time.monotonic() - start) * 1000)

        if not findings:
            verdict = EngineVerdict.CLEAN
            confidence = 1.0
        else:
            severities = {f.severity for f in findings}
            if Severity.CRITICAL in severities:
                verdict = EngineVerdict.MALICIOUS
            elif Severity.HIGH in severities:
                verdict = EngineVerdict.SUSPICIOUS
            else:
                verdict = EngineVerdict.SUSPICIOUS
            confidence = max(f.confidence for f in findings)

        return EngineResult(
            engine_name=self.name,
            engine_version=self.version,
            verdict=verdict,
            confidence=confidence,
            findings=findings,
            duration_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        return True


def _redact_line(line: str) -> str:
    """Partially redact a line that contains a secret."""
    if len(line) > 200:
        return line[:100] + " [REDACTED] " + line[-50:]
    return line
