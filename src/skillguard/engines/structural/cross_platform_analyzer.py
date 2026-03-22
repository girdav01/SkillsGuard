"""Cross-platform reuse analysis engine.

Analyzes skill files for OWASP AST10 (Cross-Platform Reuse) security gaps,
detecting platform-specific patterns that may not work across different
AI coding assistant platforms.
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

# Cross-platform detection rules: (rule_id, rule_name, pattern, severity, confidence, description, owasp_ast, mitre_attack, remediation)
_XPLAT_RULES: list[dict] = [
    {
        "rule_id": "SG-XPLAT-001",
        "rule_name": "Platform-Specific API Without Guard",
        "pattern": r"(?i)(Bash\s*\(|execute_command|run_terminal|computer_use|browser_use)",
        "severity": Severity.MEDIUM,
        "confidence": 0.65,
        "description": (
            "Detected platform-specific tool call. These are Claude Code/Desktop "
            "specific APIs that won't work on other platforms."
        ),
        "owasp_ast": ["AST10"],
        "mitre_attack": [],
        "remediation": "Wrap platform-specific API calls in platform detection guards.",
    },
    {
        "rule_id": "SG-XPLAT-002",
        "rule_name": "Incompatible Permission Model",
        "pattern": r"(?i)(allow_commands|server_commands|mcp_servers|tool_permissions)",
        "severity": Severity.MEDIUM,
        "confidence": 0.60,
        "description": (
            "Detected platform-specific permission declaration in frontmatter/config. "
            "Permission models differ across AI coding platforms."
        ),
        "owasp_ast": ["AST10"],
        "mitre_attack": [],
        "remediation": "Use a universal permission manifest format compatible across platforms.",
    },
    {
        "rule_id": "SG-XPLAT-003",
        "rule_name": "Hardcoded Platform Path",
        "pattern": r"(?i)(~/\.claude/|~/\.cursor/|~/\.windsurf/|~/\.openclaw/|~/\.config/claude|\.claude/settings)",
        "severity": Severity.LOW,
        "confidence": 0.80,
        "description": (
            "Detected hardcoded platform-specific path. These paths are tied to a "
            "single platform and will break on others."
        ),
        "owasp_ast": ["AST10"],
        "mitre_attack": [],
        "remediation": "Use platform-agnostic path resolution instead of hardcoded platform paths.",
    },
    {
        "rule_id": "SG-XPLAT-004",
        "rule_name": "Transport Mismatch",
        "pattern": r"(?i)(transport:\s*stdio|transport:\s*sse|StdioServerTransport|SSEServerTransport)",
        "severity": Severity.MEDIUM,
        "confidence": 0.70,
        "description": (
            "Detected transport-specific code. When a skill assumes a specific transport, "
            "it may not work on platforms that use a different one."
        ),
        "owasp_ast": ["AST10"],
        "mitre_attack": [],
        "remediation": "Support both stdio and SSE transport modes, or document transport requirements.",
    },
    {
        "rule_id": "SG-XPLAT-005",
        "rule_name": "Sandbox Escalation Risk",
        "pattern": r"(?i)(host_mode:\s*true|sandbox:\s*false|disable_sandbox|no.?sandbox|unrestricted_mode)",
        "severity": Severity.HIGH,
        "confidence": 0.70,
        "description": (
            "Detected sandbox-bypassing feature. This feature is sandboxed on some "
            "platforms but unrestricted on others, creating a security gap."
        ),
        "owasp_ast": ["AST10"],
        "mitre_attack": ["T1190"],
        "remediation": "Ensure consistent sandboxing across all target platforms.",
    },
]


class CrossPlatformAnalyzer(ScanEngine):
    """Analyzes skills for cross-platform reuse security gaps (OWASP AST10)."""

    @property
    def name(self) -> str:
        return "cross_platform_analyzer"

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

            file_findings = self._analyze_file(sf)
            findings.extend(file_findings)

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
            detection_name="Cross-Platform Analysis" if findings else None,
            findings=findings,
            duration_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        return True

    def _analyze_file(self, sf: SkillFile) -> list[Finding]:
        """Scan a single file against all cross-platform rules."""
        findings: list[Finding] = []
        content = sf.content or ""

        for rule in _XPLAT_RULES:
            matches = list(re.finditer(rule["pattern"], content))
            for match in matches:
                line_start = content[: match.start()].count("\n") + 1
                snippet = match.group(0)

                findings.append(
                    Finding(
                        rule_id=rule["rule_id"],
                        rule_name=rule["rule_name"],
                        severity=rule["severity"],
                        category="cross_platform",
                        description=rule["description"],
                        file_path=sf.path,
                        line_start=line_start,
                        snippet=snippet,
                        owasp_ast=rule["owasp_ast"],
                        mitre_attack=rule["mitre_attack"],
                        confidence=rule["confidence"],
                        remediation=rule["remediation"],
                    )
                )

        return findings
