"""Isolation and sandboxing configuration checker.

Analyzes skill files for weak isolation and sandboxing configurations
that could allow container escapes or host compromise (OWASP AST06).
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

# Isolation rule definitions: (rule_id, rule_name, pattern, severity, confidence, description, remediation, owasp_ast, mitre_attack)
_ISOLATION_PATTERNS: list[
    tuple[str, str, str, Severity, float, str, str, list[str], list[str]]
] = [
    (
        "SG-ISOL-001",
        "Docker Host Network Mode",
        r"(?i)(--network[=\s]+host|network_mode:\s*host|hostNetwork:\s*true)",
        Severity.CRITICAL,
        0.90,
        "Container is configured to use the host network namespace. "
        "This removes network isolation and allows the container to access "
        "all host network interfaces and services.",
        "Use bridge or custom Docker networks instead of host networking. "
        "Define explicit port mappings for required services.",
        ["AST06"],
        ["T1610"],
    ),
    (
        "SG-ISOL-002",
        "Privileged Container",
        r"(?i)(--privileged|privileged:\s*true|securityContext:.*privileged:\s*true)",
        Severity.CRITICAL,
        0.90,
        "Container is configured to run in privileged mode. "
        "This grants the container nearly all capabilities of the host "
        "and disables security mechanisms like seccomp and AppArmor.",
        "Remove the privileged flag. Grant only specific capabilities "
        "needed via --cap-add instead of full privileged access.",
        ["AST06"],
        ["T1610"],
    ),
    (
        "SG-ISOL-004",
        "Sensitive Port Exposure",
        r"(?i)(?:ports:|EXPOSE|--publish|-p)\s*[:\s]*(?:22|3306|5432|6379|27017|2375|2376|9200|5601|8500)\b",
        Severity.HIGH,
        0.75,
        "Container exposes sensitive service ports (e.g., SSH, databases, "
        "Docker daemon, Elasticsearch). These ports can be targeted by "
        "attackers for unauthorized access.",
        "Avoid exposing sensitive ports externally. Use internal Docker "
        "networks for inter-service communication and restrict port "
        "bindings to localhost (127.0.0.1) when possible.",
        ["AST06"],
        ["T1190"],
    ),
    (
        "SG-ISOL-005",
        "Dangerous Volume Mount",
        r"(?i)(?:volumes:|--volume|-v)\s*[:\s]*(?:/:|/etc[:/]|/var/run/docker\.sock|/proc[:/]|/sys[:/]|/dev[:/])",
        Severity.CRITICAL,
        0.85,
        "Container mounts a sensitive host path (e.g., root filesystem, "
        "/etc, Docker socket, /proc, /sys, or /dev). This can allow "
        "container escape or full host compromise.",
        "Avoid mounting sensitive host paths into containers. Use named "
        "volumes or bind-mount only specific, non-sensitive directories. "
        "Never mount the Docker socket inside a container.",
        ["AST06"],
        ["T1610"],
    ),
]

# Container marker patterns used to detect Docker/container configuration files
_CONTAINER_MARKERS = re.compile(
    r"(?i)(?:^FROM\s+|docker-compose|services:\s*$|image:\s*\S+)",
    re.MULTILINE,
)

# Security profile patterns
_SECURITY_PROFILE_PATTERNS = re.compile(
    r"(?i)(?:security_opt|seccomp|apparmor|securityContext)",
)


class IsolationChecker(ScanEngine):
    """Checks for weak isolation and sandboxing configurations in skills."""

    @property
    def name(self) -> str:
        return "isolation_checker"

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

            content = sf.content

            for (
                rule_id,
                rule_name,
                pattern,
                severity,
                confidence,
                description,
                remediation,
                owasp_ast,
                mitre_attack,
            ) in _ISOLATION_PATTERNS:
                matches = list(re.finditer(pattern, content))
                if matches:
                    for match in matches:
                        line_num = content[: match.start()].count("\n") + 1
                        findings.append(
                            Finding(
                                rule_id=rule_id,
                                rule_name=rule_name,
                                severity=severity,
                                category="isolation",
                                description=description,
                                file_path=sf.path,
                                line_start=line_num,
                                snippet=match.group(0),
                                owasp_ast=owasp_ast,
                                mitre_attack=mitre_attack,
                                confidence=confidence,
                                remediation=remediation,
                            )
                        )

        # Check for missing security profiles across all files
        findings.extend(self._check_missing_security_profile(skill_files))

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
            detection_name="Isolation Analysis" if findings else None,
            findings=findings,
            duration_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        return True

    def _check_missing_security_profile(
        self, skill_files: list[SkillFile]
    ) -> list[Finding]:
        """Check if container configs exist but lack security profiles.

        If any file contains Docker/container markers (FROM, docker-compose,
        services:, image:) but no file mentions seccomp, apparmor,
        security_opt, or securityContext, emit a finding.
        """
        findings: list[Finding] = []
        container_file: str | None = None
        has_security_profile = False

        for sf in skill_files:
            if sf.content is None:
                continue

            if container_file is None and _CONTAINER_MARKERS.search(sf.content):
                container_file = sf.path

            if _SECURITY_PROFILE_PATTERNS.search(sf.content):
                has_security_profile = True

        if container_file is not None and not has_security_profile:
            findings.append(
                Finding(
                    rule_id="SG-ISOL-003",
                    rule_name="Missing Security Profile",
                    severity=Severity.HIGH,
                    category="isolation",
                    description=(
                        "Container configuration detected but no seccomp or "
                        "AppArmor security profile is specified. Without a "
                        "security profile, containers run with the default "
                        "set of syscalls which may be overly permissive."
                    ),
                    file_path=container_file,
                    owasp_ast=["AST06"],
                    confidence=0.70,
                    remediation=(
                        "Add a seccomp or AppArmor profile to your container "
                        "configuration. Use 'security_opt: [seccomp:profile.json]' "
                        "in docker-compose or '--security-opt seccomp=profile.json' "
                        "with docker run."
                    ),
                )
            )

        return findings
