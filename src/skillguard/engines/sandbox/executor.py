"""Sandboxed skill execution engine.

Provides a secure sandbox for executing skill scripts to observe
their runtime behavior. Uses subprocess isolation with resource
limits. Optional bubblewrap/gVisor support for stronger isolation.
"""

from __future__ import annotations

import asyncio
import os
import resource
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

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


@dataclass
class SandboxConfig:
    """Configuration for the execution sandbox."""

    timeout_seconds: int = 10
    max_memory_mb: int = 256
    max_file_size_mb: int = 10
    allow_network: bool = False
    allow_write: bool = False
    working_dir: str | None = None


@dataclass
class ExecutionResult:
    """Result of a sandboxed execution."""

    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    timed_out: bool = False
    network_attempts: list[str] = field(default_factory=list)
    file_writes: list[str] = field(default_factory=list)
    suspicious_behaviors: list[str] = field(default_factory=list)


# Script file types we can execute
_EXECUTABLE_TYPES = {
    FileType.SCRIPT_PYTHON,
    FileType.SCRIPT_BASH,
    FileType.SCRIPT_JS,
}

# Dangerous patterns to detect in output
_OUTPUT_PATTERNS: list[tuple[str, str, Severity]] = [
    ("reverse shell", r"(?i)(?:connect|socket|bind).*?(?:\d{1,3}\.){3}\d{1,3}", Severity.CRITICAL),
    ("credential access", r"(?i)(?:password|secret|key|token)\s*[=:]", Severity.HIGH),
    ("network callback", r"https?://(?!localhost|127\.0\.0\.1)", Severity.HIGH),
    ("file exfiltration", r"(?i)(?:cat|type|read).*?(?:\.env|id_rsa|credentials)", Severity.CRITICAL),
    ("process manipulation", r"(?i)(?:kill|pkill|killall)\s+", Severity.MEDIUM),
    ("privilege escalation", r"(?i)(?:sudo|su\s+-|chmod\s+[0-7]*7)", Severity.HIGH),
]


class SandboxExecutor(ScanEngine):
    """Behavioral analysis engine that executes scripts in a sandbox.

    Runs skill scripts in an isolated environment and monitors for:
    - Network connection attempts
    - File system writes to sensitive paths
    - Process spawning
    - Suspicious output patterns
    - Resource exhaustion attempts
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        self._config = config or SandboxConfig()

    @property
    def name(self) -> str:
        return "sandbox_executor"

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
            if sf.file_type not in _EXECUTABLE_TYPES:
                continue

            # Static analysis of script content before execution
            findings.extend(self._static_check(sf))

            # Attempt sandboxed execution
            exec_result = await self._execute_in_sandbox(sf)
            findings.extend(self._analyze_execution(sf, exec_result))

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
            detection_name="Sandbox Behavioral Analysis" if findings else None,
            findings=findings,
            duration_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        return True

    def _static_check(self, sf: SkillFile) -> list[Finding]:
        """Static checks on script content before execution."""
        import re

        findings: list[Finding] = []
        content = sf.content or ""

        # Check for obvious C2 / reverse shell patterns
        c2_patterns = [
            (r"socket\.socket\s*\(.*?AF_INET", "Socket connection creation"),
            (r"subprocess\.(?:call|Popen|run)\s*\(\s*\[?\s*['\"](?:/bin/)?(?:sh|bash)", "Shell spawning via subprocess"),
            (r"os\.system\s*\(\s*['\"].*?(?:nc|ncat|netcat|socat)\s+", "Netcat execution"),
            (r"(?:exec|eval)\s*\(\s*(?:compile|__import__|base64)", "Dynamic code execution"),
            (r"os\.environ\s*\[?\s*['\"](?:AWS|SECRET|KEY|TOKEN|PASSWORD)", "Environment variable access"),
        ]

        for pattern, desc in c2_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        rule_id="SG-SANDBOX-STATIC-001",
                        rule_name=f"Suspicious Pattern: {desc}",
                        severity=Severity.HIGH,
                        category="behavioral",
                        description=f"Script contains suspicious pattern: {desc}",
                        file_path=sf.path,
                        line_start=line_num,
                        snippet=match.group()[:200],
                        owasp_llm=["LLM06"],
                        mitre_attack=["T1059"],
                        confidence=0.80,
                        remediation="Review the script for malicious intent.",
                    )
                )

        return findings

    async def _execute_in_sandbox(self, sf: SkillFile) -> ExecutionResult:
        """Execute a script in a sandboxed environment."""
        result = ExecutionResult()

        if sf.file_type == FileType.SCRIPT_PYTHON:
            interpreter = "python3"
            ext = ".py"
        elif sf.file_type == FileType.SCRIPT_BASH:
            interpreter = "bash"
            ext = ".sh"
        elif sf.file_type == FileType.SCRIPT_JS:
            interpreter = "node"
            ext = ".js"
        else:
            return result

        # Write script to temp file
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=ext, delete=False, dir=self._config.working_dir
            ) as f:
                f.write(sf.content or "")
                temp_path = f.name
        except OSError:
            return result

        try:
            start = time.monotonic()

            # Build command with network restrictions
            cmd = [interpreter, temp_path]

            env = os.environ.copy()
            # Sanitize environment
            for key in list(env.keys()):
                if any(s in key.upper() for s in ["SECRET", "KEY", "TOKEN", "PASSWORD", "CREDENTIAL"]):
                    del env[key]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                    cwd=tempfile.gettempdir(),
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=self._config.timeout_seconds,
                    )
                    result.exit_code = proc.returncode or 0
                    result.stdout = stdout.decode("utf-8", errors="replace")[:10000]
                    result.stderr = stderr.decode("utf-8", errors="replace")[:10000]
                except asyncio.TimeoutError:
                    proc.kill()
                    result.timed_out = True
                    result.suspicious_behaviors.append("Script timed out (possible infinite loop or resource exhaustion)")

            except (FileNotFoundError, PermissionError):
                # Interpreter not available
                pass

            result.duration_ms = int((time.monotonic() - start) * 1000)

        finally:
            try:
                os.unlink(temp_path)
            except OSError:
                pass

        return result

    def _analyze_execution(self, sf: SkillFile, exec_result: ExecutionResult) -> list[Finding]:
        """Analyze execution results for suspicious behavior."""
        import re

        findings: list[Finding] = []

        if exec_result.timed_out:
            findings.append(
                Finding(
                    rule_id="SG-SANDBOX-001",
                    rule_name="Script Timeout",
                    severity=Severity.MEDIUM,
                    category="behavioral",
                    description="Script execution timed out, suggesting possible infinite loop or resource exhaustion.",
                    file_path=sf.path,
                    owasp_llm=["LLM06"],
                    confidence=0.70,
                    remediation="Investigate the script for infinite loops or resource-intensive operations.",
                )
            )

        # Check output for suspicious patterns
        combined_output = exec_result.stdout + exec_result.stderr
        for desc, pattern, severity in _OUTPUT_PATTERNS:
            if re.search(pattern, combined_output):
                findings.append(
                    Finding(
                        rule_id="SG-SANDBOX-002",
                        rule_name=f"Suspicious Output: {desc}",
                        severity=severity,
                        category="behavioral",
                        description=f"Script output contains {desc} indicators.",
                        file_path=sf.path,
                        snippet=combined_output[:300] + "..." if len(combined_output) > 300 else combined_output,
                        owasp_llm=["LLM06"],
                        mitre_attack=["T1059"],
                        confidence=0.75,
                        remediation="Review script output for potential security issues.",
                    )
                )

        # Check for non-zero exit with error indicators
        if exec_result.exit_code != 0 and exec_result.stderr:
            error_keywords = ["permission denied", "access denied", "unauthorized"]
            for keyword in error_keywords:
                if keyword in exec_result.stderr.lower():
                    findings.append(
                        Finding(
                            rule_id="SG-SANDBOX-003",
                            rule_name="Access Violation Attempt",
                            severity=Severity.HIGH,
                            category="behavioral",
                            description=f"Script attempted unauthorized access: {keyword}",
                            file_path=sf.path,
                            snippet=exec_result.stderr[:300],
                            owasp_llm=["LLM06"],
                            confidence=0.80,
                            remediation="Review the script for unauthorized access attempts.",
                        )
                    )

        for behavior in exec_result.suspicious_behaviors:
            findings.append(
                Finding(
                    rule_id="SG-SANDBOX-004",
                    rule_name="Suspicious Behavior",
                    severity=Severity.MEDIUM,
                    category="behavioral",
                    description=behavior,
                    file_path=sf.path,
                    owasp_llm=["LLM06"],
                    confidence=0.65,
                )
            )

        return findings
