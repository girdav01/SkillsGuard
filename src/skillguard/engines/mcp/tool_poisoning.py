"""Tool poisoning detection engine for MCP servers.

Detects attempts to embed malicious instructions in tool descriptions
that could manipulate the AI agent's behavior when it reads the tool's
metadata. This is a key attack vector in MCP environments.
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

# Patterns that indicate tool description poisoning
_POISONING_PATTERNS: list[tuple[str, str, Severity, str]] = [
    # Hidden instructions in descriptions
    (
        "Hidden Instructions in Tool Description",
        r'(?i)(?:description|summary)\s*[=:]\s*["\'].*?(?:ignore|disregard|override|forget)\s+(?:previous|prior|all|your)\s+(?:instructions|rules|guidelines)',
        Severity.CRITICAL,
        "Tool description contains hidden override instructions that could manipulate agent behavior.",
    ),
    # Invisible characters / zero-width
    (
        "Zero-Width Characters in Description",
        r"[\u200b\u200c\u200d\u2060\ufeff]",
        Severity.HIGH,
        "Invisible zero-width characters detected that could hide malicious instructions.",
    ),
    # Excessively long descriptions (used to hide payloads)
    (
        "Suspiciously Long Tool Description",
        r'(?i)(?:description|summary)\s*[=:]\s*["\'].{2000,}["\']',
        Severity.MEDIUM,
        "Tool description is unusually long and may contain hidden payloads.",
    ),
    # Instructions to access files/env
    (
        "File Access in Tool Description",
        r'(?i)(?:description|summary)\s*[=:]\s*["\'].*?(?:read|access|open|cat|type)\s+.*?(?:\.env|credentials|\.ssh|\.aws|config|secret)',
        Severity.CRITICAL,
        "Tool description instructs agent to access sensitive files.",
    ),
    # URL injection in description
    (
        "External URL in Tool Description",
        r'(?i)(?:description|summary)\s*[=:]\s*["\'].*?https?://(?!(?:localhost|127\.0\.0\.1|example\.com|docs\.))',
        Severity.MEDIUM,
        "Tool description contains external URLs that could be used for exfiltration.",
    ),
    # Role manipulation in description
    (
        "Role Manipulation in Description",
        r'(?i)(?:description|summary)\s*[=:]\s*["\'].*?(?:you\s+are\s+now|act\s+as|pretend|your\s+new\s+role)',
        Severity.CRITICAL,
        "Tool description attempts to change the agent's role or identity.",
    ),
    # Instructing to call other tools
    (
        "Cross-Tool Invocation",
        r'(?i)(?:description|summary)\s*[=:]\s*["\'].*?(?:first\s+call|also\s+(?:call|invoke|run|execute)|before\s+(?:running|using)\s+this.*?call)',
        Severity.HIGH,
        "Tool description instructs agent to invoke other tools, potentially chaining attacks.",
    ),
    # Prompt injection markers in JSON schemas
    (
        "Injection in JSON Schema",
        r'(?i)"(?:description|title)"\s*:\s*".*?(?:ignore|override|system|admin|root).*?(?:instruction|prompt|command|directive)',
        Severity.HIGH,
        "JSON schema contains potentially injected instructions in field descriptions.",
    ),
]

# Patterns specifically for MCP config files
_CONFIG_POISONING_PATTERNS: list[tuple[str, str, Severity, str]] = [
    (
        "Unrestricted Tool Permissions",
        r'(?i)(?:permissions?|allow(?:ed)?)\s*[=:]\s*\[?\s*["\']?\*["\']?\s*\]?',
        Severity.HIGH,
        "MCP config grants unrestricted permissions to tools.",
    ),
    (
        "Remote Server with No Auth",
        r'(?i)(?:server|endpoint|url)\s*[=:]\s*["\']https?://.*?["\'](?!.*?(?:auth|token|key|bearer))',
        Severity.MEDIUM,
        "MCP config connects to remote server without apparent authentication.",
    ),
    (
        "Suspicious Environment Pass-through",
        r'(?i)(?:env|environment)\s*[=:]\s*(?:\{[^}]*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)[^}]*\}|\[.*?(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL).*?\])',
        Severity.HIGH,
        "MCP config passes sensitive environment variables to tool server.",
    ),
]


class ToolPoisoningDetector(ScanEngine):
    """Detects malicious instruction injection in MCP tool descriptions."""

    @property
    def name(self) -> str:
        return "mcp_tool_poisoning"

    @property
    def version(self) -> str:
        return "0.2.0"

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

            # Apply description poisoning patterns to all text files
            if sf.file_type in {
                FileType.SKILL_MD,
                FileType.FRONTMATTER,
                FileType.CONFIG,
                FileType.OTHER,
            }:
                findings.extend(self._check_description_poisoning(sf))

            # Apply config-specific patterns
            if sf.file_type == FileType.CONFIG or sf.path.endswith(
                (".json", ".yaml", ".yml", ".toml")
            ):
                findings.extend(self._check_config_poisoning(sf))

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
            detection_name="MCP Tool Poisoning" if findings else None,
            findings=findings,
            duration_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        return True

    def _check_description_poisoning(self, sf: SkillFile) -> list[Finding]:
        findings: list[Finding] = []
        for pattern_name, pattern, severity, description in _POISONING_PATTERNS:
            try:
                compiled = re.compile(pattern, re.MULTILINE)
            except re.error:
                continue

            for match in compiled.finditer(sf.content or ""):
                line_start = (sf.content or "")[:match.start()].count("\n") + 1
                snippet = match.group()[:300]
                findings.append(
                    Finding(
                        rule_id=f"SG-MCP-TP-{pattern_name.replace(' ', '_')[:20].upper()}",
                        rule_name=pattern_name,
                        severity=severity,
                        category="mcp_tool_poisoning",
                        description=description,
                        file_path=sf.path,
                        line_start=line_start,
                        snippet=snippet,
                        owasp_llm=["LLM01", "LLM07"],
                        mitre_attack=["T1195.002"],
                        confidence=0.85,
                        remediation=(
                            "Review and sanitize tool descriptions. Remove any "
                            "instructions that attempt to manipulate agent behavior. "
                            "Tool descriptions should only describe the tool's functionality."
                        ),
                    )
                )
        return findings

    def _check_config_poisoning(self, sf: SkillFile) -> list[Finding]:
        findings: list[Finding] = []
        for pattern_name, pattern, severity, description in _CONFIG_POISONING_PATTERNS:
            try:
                compiled = re.compile(pattern, re.MULTILINE)
            except re.error:
                continue

            for match in compiled.finditer(sf.content or ""):
                line_start = (sf.content or "")[:match.start()].count("\n") + 1
                snippet = match.group()[:300]
                findings.append(
                    Finding(
                        rule_id=f"SG-MCP-CFG-{pattern_name.replace(' ', '_')[:20].upper()}",
                        rule_name=pattern_name,
                        severity=severity,
                        category="mcp_config",
                        description=description,
                        file_path=sf.path,
                        line_start=line_start,
                        snippet=snippet,
                        owasp_llm=["LLM07"],
                        mitre_attack=["T1195.002"],
                        confidence=0.80,
                        remediation=(
                            "Review MCP configuration for security issues. "
                            "Apply principle of least privilege to tool permissions."
                        ),
                    )
                )
        return findings
