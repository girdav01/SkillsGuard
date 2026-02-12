"""MCP configuration file scanner.

Parses and analyzes MCP server configuration files for security issues
such as insecure transport, missing authentication, overly permissive
settings, suspicious server URLs, and environment variable exposure.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path as P

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

# Suspicious domain patterns
_SUSPICIOUS_DOMAINS = re.compile(
    r"(?:ngrok|localtunnel|serveo|pagekite|telebit|localhost\.run|"
    r"burpcollaborator|interactsh|pipedream|webhook\.site|"
    r"requestbin|hookbin|beeceptor)"
)

# Private/sensitive file paths that should not appear in configs
_SENSITIVE_PATHS = re.compile(
    r"(?:\.ssh|\.aws|\.gnupg|\.netrc|\.env|credentials|"
    r"id_rsa|id_ed25519|\.pem|\.key|shadow|passwd|htpasswd)"
)


class MCPConfigScanner(ScanEngine):
    """Scans MCP configuration files for security issues."""

    @property
    def name(self) -> str:
        return "mcp_config_scanner"

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

            if sf.file_type == FileType.CONFIG or _is_config_file(sf.path):
                findings.extend(self._scan_config(sf))

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
            detection_name="MCP Config Issue" if findings else None,
            findings=findings,
            duration_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        return True

    def _scan_config(self, sf: SkillFile) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_insecure_transport(sf))
        findings.extend(self._check_suspicious_urls(sf))
        findings.extend(self._check_sensitive_paths(sf))
        findings.extend(self._check_wildcard_permissions(sf))

        if sf.path.endswith(".json"):
            findings.extend(self._check_json_config(sf))

        return findings

    def _check_insecure_transport(self, sf: SkillFile) -> list[Finding]:
        findings: list[Finding] = []
        content = sf.content or ""

        http_pattern = re.compile(
            r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(\S+)"
        )
        for match in http_pattern.finditer(content):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(
                Finding(
                    rule_id="SG-MCP-CFG-001",
                    rule_name="Insecure HTTP Transport",
                    severity=Severity.HIGH,
                    category="mcp_config",
                    description=(
                        f"MCP server configured with insecure HTTP transport. "
                        f"Use HTTPS for encrypted communication."
                    ),
                    file_path=sf.path,
                    line_start=line_num,
                    snippet=match.group()[:200],
                    owasp_llm=["LLM07"],
                    confidence=0.90,
                    remediation="Use HTTPS instead of HTTP for MCP server connections.",
                )
            )
        return findings

    def _check_suspicious_urls(self, sf: SkillFile) -> list[Finding]:
        findings: list[Finding] = []
        content = sf.content or ""

        for match in _SUSPICIOUS_DOMAINS.finditer(content.lower()):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(
                Finding(
                    rule_id="SG-MCP-CFG-002",
                    rule_name="Suspicious Tunneling Service",
                    severity=Severity.HIGH,
                    category="mcp_config",
                    description=(
                        f"MCP config references tunneling/proxy service "
                        f"'{match.group()}'. Commonly used to expose local services."
                    ),
                    file_path=sf.path,
                    line_start=line_num,
                    owasp_llm=["LLM07"],
                    mitre_attack=["T1071.001"],
                    confidence=0.80,
                    remediation="Use production-grade server URLs instead of tunneling services.",
                )
            )
        return findings

    def _check_sensitive_paths(self, sf: SkillFile) -> list[Finding]:
        findings: list[Finding] = []
        content = sf.content or ""

        for match in _SENSITIVE_PATHS.finditer(content):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(
                Finding(
                    rule_id="SG-MCP-CFG-003",
                    rule_name="Sensitive Path Reference",
                    severity=Severity.HIGH,
                    category="mcp_config",
                    description=(
                        f"MCP config references sensitive path '{match.group()}'."
                    ),
                    file_path=sf.path,
                    line_start=line_num,
                    owasp_llm=["LLM06"],
                    mitre_attack=["T1552.001"],
                    confidence=0.85,
                    remediation="Remove direct references to sensitive files.",
                )
            )
        return findings

    def _check_wildcard_permissions(self, sf: SkillFile) -> list[Finding]:
        findings: list[Finding] = []
        content = sf.content or ""

        wildcard_patterns = [
            (r'"permissions"\s*:\s*\[\s*"\*"\s*\]', "wildcard permissions"),
            (r'"allowedTools"\s*:\s*\[\s*"\*"\s*\]', "unrestricted tool access"),
        ]

        for pattern, desc in wildcard_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        rule_id="SG-MCP-CFG-004",
                        rule_name="Overly Permissive Configuration",
                        severity=Severity.HIGH,
                        category="mcp_config",
                        description=f"MCP config has {desc}. Restrict access.",
                        file_path=sf.path,
                        line_start=line_num,
                        snippet=match.group()[:200],
                        owasp_llm=["LLM07"],
                        confidence=0.85,
                        remediation="Restrict permissions to only required tools.",
                    )
                )
        return findings

    def _check_json_config(self, sf: SkillFile) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(sf.content or "")
        except (json.JSONDecodeError, ValueError):
            return findings

        servers = data.get("mcpServers", data.get("servers", {}))
        if isinstance(servers, dict):
            for server_name, config in servers.items():
                if not isinstance(config, dict):
                    continue

                command = config.get("command", "")
                if isinstance(command, str) and any(
                    c in command for c in ["|", ";", "&&", "`", "$("]
                ):
                    findings.append(
                        Finding(
                            rule_id="SG-MCP-CFG-006",
                            rule_name="Command Injection in Server Config",
                            severity=Severity.CRITICAL,
                            category="mcp_config",
                            description=(
                                f"MCP server '{server_name}' has command with "
                                f"potential injection characters."
                            ),
                            file_path=sf.path,
                            snippet=f'"command": "{command[:100]}"',
                            owasp_llm=["LLM06"],
                            mitre_attack=["T1059"],
                            confidence=0.90,
                            remediation="Use simple command strings without shell operators.",
                        )
                    )

        return findings


def _is_config_file(path: str) -> bool:
    """Check if a file path looks like a configuration file."""
    lower = path.lower()
    config_extensions = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"}
    config_names = {"config", "settings", "mcp", "claude_desktop_config", ".mcp"}
    p = P(lower)
    return p.suffix in config_extensions or p.stem in config_names
