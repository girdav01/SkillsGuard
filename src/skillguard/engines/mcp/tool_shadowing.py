"""Tool shadowing detection engine for MCP servers.

Detects when a skill or MCP server defines tools with names that
shadow or conflict with built-in tools or well-known tool names.
This can be used to intercept legitimate tool calls.
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

# Well-known tool names that should not be shadowed
_PROTECTED_TOOL_NAMES: set[str] = {
    # File operations
    "read_file", "write_file", "edit_file", "create_file", "delete_file",
    "list_files", "search_files", "read", "write", "edit",
    # Shell
    "run_command", "execute", "bash", "shell", "terminal",
    "run_bash", "exec", "command",
    # Browser / Web
    "browse", "web_search", "fetch_url", "navigate",
    "browser", "web_fetch",
    # Code
    "search_code", "grep", "find", "glob",
    # Git
    "git", "git_commit", "git_push", "git_pull",
    # System
    "list_directory", "get_cwd", "pwd",
    # Claude built-ins
    "computer", "text_editor", "str_replace_editor",
}

# Patterns indicating tool name extraction from config/code
_TOOL_NAME_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    ("json_name", re.compile(r'"name"\s*:\s*"([^"]+)"')),
    ("yaml_name", re.compile(r"^\s*name\s*:\s*['\"]?(\w+)['\"]?", re.MULTILINE)),
    ("python_name", re.compile(r"(?:tool_name|name)\s*=\s*['\"](\w+)['\"]")),
    ("decorator", re.compile(r"@(?:tool|function)\(['\"](\w+)['\"]")),
]


class ToolShadowingDetector(ScanEngine):
    """Detects tool name shadowing and conflicts in MCP configurations."""

    @property
    def name(self) -> str:
        return "mcp_tool_shadowing"

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

        # Collect all tool names across files
        all_tool_names: dict[str, list[tuple[str, int]]] = {}

        for sf in skill_files:
            if sf.content is None:
                continue

            tool_names = self._extract_tool_names(sf)
            for tool_name, line_num in tool_names:
                if tool_name not in all_tool_names:
                    all_tool_names[tool_name] = []
                all_tool_names[tool_name].append((sf.path, line_num))

        # Check for shadowing of protected names
        for tool_name, locations in all_tool_names.items():
            normalized = tool_name.lower().replace("-", "_")
            if normalized in _PROTECTED_TOOL_NAMES:
                for file_path, line_num in locations:
                    findings.append(
                        Finding(
                            rule_id="SG-MCP-SHADOW-001",
                            rule_name="Protected Tool Name Shadowing",
                            severity=Severity.HIGH,
                            category="mcp_tool_shadowing",
                            description=(
                                f"Tool name '{tool_name}' shadows a protected/built-in "
                                f"tool name. This could intercept legitimate tool calls."
                            ),
                            file_path=file_path,
                            line_start=line_num,
                            owasp_llm=["LLM07"],
                            mitre_attack=["T1557"],
                            confidence=0.85,
                            remediation=(
                                f"Rename the tool to avoid shadowing '{normalized}'. "
                                f"Use a unique, descriptive name."
                            ),
                        )
                    )

        # Check for duplicate tool names
        for tool_name, locations in all_tool_names.items():
            if len(locations) > 1:
                for file_path, line_num in locations[1:]:
                    findings.append(
                        Finding(
                            rule_id="SG-MCP-SHADOW-002",
                            rule_name="Duplicate Tool Name",
                            severity=Severity.MEDIUM,
                            category="mcp_tool_shadowing",
                            description=(
                                f"Tool name '{tool_name}' is defined multiple times. "
                                f"Duplicate definitions could cause unpredictable behavior."
                            ),
                            file_path=file_path,
                            line_start=line_num,
                            owasp_llm=["LLM07"],
                            confidence=0.75,
                            remediation="Remove duplicate tool definitions.",
                        )
                    )

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
        if Severity.CRITICAL in severities or Severity.HIGH in severities:
            verdict = EngineVerdict.MALICIOUS
        elif Severity.MEDIUM in severities:
            verdict = EngineVerdict.SUSPICIOUS
        else:
            verdict = EngineVerdict.CLEAN

        return EngineResult(
            engine_name=self.name,
            engine_version=self.version,
            verdict=verdict,
            confidence=max_confidence,
            detection_name="MCP Tool Shadowing" if findings else None,
            findings=findings,
            duration_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        return True

    def _extract_tool_names(self, sf: SkillFile) -> list[tuple[str, int]]:
        """Extract tool names from a skill file."""
        if sf.content is None:
            return []

        tool_names: list[tuple[str, int]] = []
        for _, pattern in _TOOL_NAME_PATTERNS:
            for match in pattern.finditer(sf.content):
                name = match.group(1)
                line_num = sf.content[:match.start()].count("\n") + 1
                tool_names.append((name, line_num))

        return tool_names
