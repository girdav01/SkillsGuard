"""Permission analysis engine for skill tool access.

Analyzes skill files to understand what permissions and capabilities
the skill requests, and flags overly broad or dangerous access patterns.
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

# Permission categories and their detection patterns
_PERMISSION_PATTERNS: list[tuple[str, str, str, Severity]] = [
    # File system access
    ("filesystem_read", r"(?i)(?:read|open|load|cat|head|tail|less)\s+.{0,30}(?:file|path|dir)", "File system read access", Severity.LOW),
    ("filesystem_write", r"(?i)(?:write|create|append|overwrite|save)\s+.{0,30}(?:file|path|dir)", "File system write access", Severity.MEDIUM),
    ("filesystem_delete", r"(?i)(?:delete|remove|unlink|rm\s+|rmdir)", "File system delete access", Severity.HIGH),
    # Network access
    ("network_outbound", r"(?i)(?:fetch|request|http|https|curl|wget|api\s*call)", "Outbound network access", Severity.MEDIUM),
    ("network_dns", r"(?i)(?:dns|resolve|nslookup|dig\s+)", "DNS resolution", Severity.LOW),
    # Shell/command execution
    ("shell_access", r"(?i)(?:execute|run|shell|command|bash|terminal|subprocess)", "Shell/command execution", Severity.HIGH),
    # Environment access
    ("env_access", r"(?i)(?:environment|env\s+var|process\.env|os\.environ)", "Environment variable access", Severity.MEDIUM),
    # System info access
    ("system_info", r"(?i)(?:system\s+info|hostname|uname|whoami|os\s+type)", "System information access", Severity.LOW),
    # Git/repo access
    ("git_access", r"(?i)(?:git\s+|repository|commit|push|pull|clone)", "Git repository access", Severity.MEDIUM),
    # Browser/web access
    ("browser_access", r"(?i)(?:browse|navigate|web\s+page|screenshot|dom\s+)", "Browser/web access", Severity.MEDIUM),
]


class PermissionAnalyzer(ScanEngine):
    """Analyzes requested permissions and access patterns in skills."""

    @property
    def name(self) -> str:
        return "permission_analyzer"

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

        # Track all permissions across files
        all_permissions: dict[str, int] = {}

        for sf in skill_files:
            if sf.content is None:
                continue

            if sf.file_type in {FileType.SKILL_MD, FileType.FRONTMATTER, FileType.CONFIG}:
                file_findings, perms = self._analyze_permissions(sf)
                findings.extend(file_findings)
                for perm, count in perms.items():
                    all_permissions[perm] = all_permissions.get(perm, 0) + count

        # Check for dangerous permission combinations
        findings.extend(self._check_combinations(all_permissions, skill_files))

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
            detection_name="Permission Analysis" if findings else None,
            findings=findings,
            duration_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        return True

    def _analyze_permissions(self, sf: SkillFile) -> tuple[list[Finding], dict[str, int]]:
        findings: list[Finding] = []
        permissions: dict[str, int] = {}
        content = sf.content or ""

        for perm_name, pattern, desc, severity in _PERMISSION_PATTERNS:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                permissions[perm_name] = len(matches)

        return findings, permissions

    def _check_combinations(
        self, permissions: dict[str, int], skill_files: list[SkillFile]
    ) -> list[Finding]:
        """Check for dangerous permission combinations."""
        findings: list[Finding] = []

        # Shell + network = potential RCE + exfil
        if "shell_access" in permissions and "network_outbound" in permissions:
            findings.append(
                Finding(
                    rule_id="SG-PERM-001",
                    rule_name="Dangerous Permission Combination: Shell + Network",
                    severity=Severity.HIGH,
                    category="permissions",
                    description=(
                        "Skill requests both shell execution and network access. "
                        "This combination enables remote code execution and data exfiltration."
                    ),
                    file_path="(skill-wide)",
                    owasp_llm=["LLM06"],
                    mitre_attack=["T1059", "T1071"],
                    confidence=0.75,
                    remediation="Minimize required permissions. Avoid combining shell and network access.",
                )
            )

        # File delete + shell = potential destructive
        if "filesystem_delete" in permissions and "shell_access" in permissions:
            findings.append(
                Finding(
                    rule_id="SG-PERM-002",
                    rule_name="Dangerous Permission Combination: Delete + Shell",
                    severity=Severity.HIGH,
                    category="permissions",
                    description=(
                        "Skill requests file deletion and shell execution permissions. "
                        "This combination enables destructive operations."
                    ),
                    file_path="(skill-wide)",
                    owasp_llm=["LLM06"],
                    confidence=0.70,
                    remediation="Restrict file deletion capabilities.",
                )
            )

        # Env access + network = credential exfil risk
        if "env_access" in permissions and "network_outbound" in permissions:
            findings.append(
                Finding(
                    rule_id="SG-PERM-003",
                    rule_name="Risk: Environment Access + Network",
                    severity=Severity.MEDIUM,
                    category="permissions",
                    description=(
                        "Skill accesses environment variables and has network capabilities. "
                        "This could enable credential exfiltration."
                    ),
                    file_path="(skill-wide)",
                    owasp_llm=["LLM06"],
                    mitre_attack=["T1552.001", "T1048"],
                    confidence=0.65,
                    remediation="Review whether environment access and network are both needed.",
                )
            )

        # Too many high-privilege permissions
        high_priv = {"shell_access", "filesystem_delete", "env_access", "network_outbound"}
        active_high_priv = high_priv & set(permissions.keys())
        if len(active_high_priv) >= 3:
            findings.append(
                Finding(
                    rule_id="SG-PERM-004",
                    rule_name="Excessive Permissions Requested",
                    severity=Severity.HIGH,
                    category="permissions",
                    description=(
                        f"Skill requests {len(active_high_priv)} high-privilege permissions: "
                        f"{', '.join(sorted(active_high_priv))}. "
                        f"Apply principle of least privilege."
                    ),
                    file_path="(skill-wide)",
                    owasp_llm=["LLM06"],
                    confidence=0.70,
                    remediation="Reduce the number of privileged permissions requested.",
                )
            )

        return findings
