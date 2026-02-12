"""Behavior analysis engine for post-execution analysis.

Analyzes the artifacts and side effects of sandboxed script execution
to detect malicious behavior patterns without executing the scripts
directly.
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

# Behavioral patterns indicating C2, exfiltration, or persistence
_BEHAVIOR_PATTERNS: list[tuple[str, str, Severity, str, list[str]]] = [
    # C2 indicators
    (
        "SG-BEHAV-001",
        r"(?i)(?:socket\.connect|urllib\.request\.urlopen|requests\.(?:get|post)|httpx\.(?:get|post)|aiohttp\.ClientSession)\s*\(",
        Severity.HIGH,
        "Network connection initiation detected. Script attempts to establish outbound connections.",
        ["T1071.001"],
    ),
    # Exfiltration via HTTP POST
    (
        "SG-BEHAV-002",
        r"(?i)(?:requests\.post|httpx\.post|urllib\.request\.urlopen.*?data=|fetch\s*\(.*?method.*?POST)",
        Severity.CRITICAL,
        "HTTP POST request detected. Could be used for data exfiltration.",
        ["T1048.003"],
    ),
    # Persistence mechanisms
    (
        "SG-BEHAV-003",
        r"(?i)(?:crontab|systemctl\s+enable|launchctl\s+load|schtasks\s+/create|@reboot|\.bashrc|\.profile|\.zshrc)",
        Severity.HIGH,
        "Persistence mechanism detected. Script attempts to install persistent access.",
        ["T1053", "T1547"],
    ),
    # Process injection / spawning
    (
        "SG-BEHAV-004",
        r"(?i)(?:subprocess\.Popen|os\.system|os\.exec|child_process\.exec|spawn\s*\()",
        Severity.MEDIUM,
        "Child process spawning detected. Review for potential command injection.",
        ["T1059"],
    ),
    # File system access to sensitive paths
    (
        "SG-BEHAV-005",
        r"""(?i)(?:open|read|readFile)\s*\(\s*['"]\s*(?:/etc/(?:passwd|shadow)|~?/\.ssh|~?/\.aws|~?/\.env|~?/\.gnupg)""",
        Severity.CRITICAL,
        "Sensitive file access detected. Script attempts to read credentials or system files.",
        ["T1552.001"],
    ),
    # DNS-based exfiltration
    (
        "SG-BEHAV-006",
        r"(?i)(?:dns\.resolver|socket\.gethostbyname|nslookup|dig\s+)",
        Severity.MEDIUM,
        "DNS resolution detected. Could be used for DNS tunneling or exfiltration.",
        ["T1048"],
    ),
    # Clipboard access
    (
        "SG-BEHAV-007",
        r"(?i)(?:pyperclip|clipboard|pbcopy|xclip|xsel|wl-copy)",
        Severity.MEDIUM,
        "Clipboard access detected. Could be used to steal copied credentials.",
        ["T1115"],
    ),
    # Screenshot/screen capture
    (
        "SG-BEHAV-008",
        r"(?i)(?:screenshot|screen_capture|pyautogui\.screenshot|mss\.mss|screencapture)",
        Severity.HIGH,
        "Screen capture capability detected.",
        ["T1113"],
    ),
    # Keylogging indicators
    (
        "SG-BEHAV-009",
        r"(?i)(?:keyboard\.on_press|pynput|keylog|GetAsyncKeyState|SetWindowsHookEx)",
        Severity.CRITICAL,
        "Keylogging capability detected.",
        ["T1056.001"],
    ),
    # Cryptocurrency mining
    (
        "SG-BEHAV-010",
        r"(?i)(?:stratum\+tcp|xmrig|minergate|coinhive|hashrate|mining_pool)",
        Severity.HIGH,
        "Cryptocurrency mining indicators detected.",
        ["T1496"],
    ),
]


class BehaviorAnalyzer(ScanEngine):
    """Static behavioral analysis engine.

    Analyzes script content for behavioral patterns that indicate
    malicious intent without actually executing the scripts.
    """

    @property
    def name(self) -> str:
        return "behavior_analyzer"

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
            # Analyze all script types
            if sf.file_type in {
                FileType.SCRIPT_PYTHON,
                FileType.SCRIPT_BASH,
                FileType.SCRIPT_JS,
                FileType.SCRIPT_TS,
            }:
                findings.extend(self._analyze_behavior(sf))

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
            detection_name="Behavioral Analysis" if findings else None,
            findings=findings,
            duration_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        return True

    def _analyze_behavior(self, sf: SkillFile) -> list[Finding]:
        findings: list[Finding] = []
        content = sf.content or ""

        for rule_id, pattern, severity, description, mitre_ids in _BEHAVIOR_PATTERNS:
            try:
                compiled = re.compile(pattern, re.MULTILINE)
            except re.error:
                continue

            for match in compiled.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        rule_name=f"Behavioral: {description[:50]}",
                        severity=severity,
                        category="behavioral",
                        description=description,
                        file_path=sf.path,
                        line_start=line_num,
                        snippet=match.group()[:200],
                        owasp_llm=["LLM06"],
                        mitre_attack=mitre_ids,
                        confidence=0.80,
                        remediation="Review the script for malicious behavioral patterns.",
                    )
                )

        return findings
