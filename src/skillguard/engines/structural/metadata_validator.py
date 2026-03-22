"""Metadata validation engine for skill packages.

Validates skill metadata fields for OWASP AST04 (Insecure Metadata),
including author impersonation, misleading descriptions, missing license,
invalid version formats, and suspicious homepage URLs.
"""

from __future__ import annotations

import re
import time

import yaml

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

_KNOWN_VENDORS = ["anthropic", "openai", "microsoft", "google", "meta", "cursor", "openclaw"]

_VENDOR_TYPOSQUAT_PATTERN = re.compile(
    r"(?i)^(anthr[o0]p[i1l]c|[o0]pen[a@]i|micr[o0]s[o0]ft|g[o0]{2}gle|m[e3]ta|curs[o0]r|[o0]pencl[a@]w)$"
)

_SAFETY_CLAIMS_PATTERN = re.compile(
    r"(?i)\b(safe|read-only|harmless|no side effects|sandboxed)\b"
)

_DANGEROUS_PATTERNS = re.compile(
    r"(?i)(subprocess|os\.system|exec|child_process|requests\.|fetch\(|http|curl|write_file|fs\.write)"
)

_SUSPICIOUS_URL_PATTERN = re.compile(
    r"(?i)(ngrok|localtunnel|serveo|localhost|127\.0\.0\.1|0\.0\.0\.0|\d+\.\d+\.\d+\.\d+|data:)"
)

_SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+")


class MetadataValidator(ScanEngine):
    """Validates skill metadata for insecure or misleading fields."""

    @property
    def name(self) -> str:
        return "metadata_validator"

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

        # Collect all file contents for misleading-description cross-check
        all_contents: list[str] = []
        for sf in skill_files:
            if sf.content is not None:
                all_contents.append(sf.content)

        has_dangerous_code = any(
            _DANGEROUS_PATTERNS.search(c) for c in all_contents
        )

        for sf in skill_files:
            if sf.content is None:
                continue

            if sf.file_type not in {FileType.SKILL_MD, FileType.FRONTMATTER}:
                continue

            metadata = self._parse_frontmatter(sf.content)
            if not metadata:
                continue

            # SG-META-001 — Author Impersonation
            author = metadata.get("author", "")
            if isinstance(author, str) and author.strip():
                author_lower = author.strip().lower()
                if (
                    _VENDOR_TYPOSQUAT_PATTERN.match(author.strip())
                    and author_lower not in _KNOWN_VENDORS
                ):
                    findings.append(
                        Finding(
                            rule_id="SG-META-001",
                            rule_name="Author Impersonation",
                            severity=Severity.HIGH,
                            category="metadata",
                            description=(
                                f"Author field '{author.strip()}' appears to impersonate a "
                                f"well-known vendor via typosquatting."
                            ),
                            file_path=sf.path,
                            owasp_ast=["AST04"],
                            owasp_llm=["LLM06"],
                            confidence=0.80,
                            remediation="Use the correct, verified vendor name or your own identity.",
                        )
                    )

            # SG-META-002 — Misleading Description
            description = metadata.get("description", "")
            if isinstance(description, str) and _SAFETY_CLAIMS_PATTERN.search(description):
                if has_dangerous_code:
                    findings.append(
                        Finding(
                            rule_id="SG-META-002",
                            rule_name="Misleading Description",
                            severity=Severity.MEDIUM,
                            category="metadata",
                            description=(
                                "Skill description contains safety claims but the package "
                                "includes code with dangerous capabilities (shell execution, "
                                "network access, or file writes)."
                            ),
                            file_path=sf.path,
                            owasp_ast=["AST04"],
                            confidence=0.65,
                            remediation="Remove misleading safety claims or remove dangerous code patterns.",
                        )
                    )

            # SG-META-003 — Missing License
            license_val = metadata.get("license")
            if not license_val or (isinstance(license_val, str) and not license_val.strip()):
                findings.append(
                    Finding(
                        rule_id="SG-META-003",
                        rule_name="Missing License",
                        severity=Severity.LOW,
                        category="metadata",
                        description="Skill metadata does not include a license field.",
                        file_path=sf.path,
                        owasp_ast=["AST04"],
                        confidence=0.90,
                        remediation="Add a 'license' field with a valid SPDX identifier to the skill metadata.",
                    )
                )

            # SG-META-004 — Invalid Version Format
            version_val = metadata.get("version")
            if version_val is not None:
                version_str = str(version_val).strip()
                if version_str and not _SEMVER_PATTERN.match(version_str):
                    findings.append(
                        Finding(
                            rule_id="SG-META-004",
                            rule_name="Invalid Version Format",
                            severity=Severity.LOW,
                            category="metadata",
                            description=(
                                f"Version field '{version_str}' does not follow semantic "
                                f"versioning (expected MAJOR.MINOR.PATCH)."
                            ),
                            file_path=sf.path,
                            owasp_ast=["AST04"],
                            confidence=0.85,
                            remediation="Use semantic versioning format (e.g., '1.0.0').",
                        )
                    )

            # SG-META-005 — Suspicious Homepage URL
            for url_field in ("homepage", "url"):
                url_val = metadata.get(url_field, "")
                if isinstance(url_val, str) and _SUSPICIOUS_URL_PATTERN.search(url_val):
                    findings.append(
                        Finding(
                            rule_id="SG-META-005",
                            rule_name="Suspicious Homepage URL",
                            severity=Severity.MEDIUM,
                            category="metadata",
                            description=(
                                f"The '{url_field}' field contains a suspicious URL: "
                                f"'{url_val}'. This may point to a temporary or local endpoint."
                            ),
                            file_path=sf.path,
                            owasp_ast=["AST04"],
                            confidence=0.70,
                            remediation="Use a stable, publicly verifiable URL for the homepage.",
                        )
                    )

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
            detection_name="Metadata Validation" if findings else None,
            findings=findings,
            duration_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        return True

    def _parse_frontmatter(self, content: str) -> dict:
        """Extract YAML metadata from frontmatter delimited by --- markers."""
        match = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
        if not match:
            return {}
        try:
            data = yaml.safe_load(match.group(1))
            return data if isinstance(data, dict) else {}
        except yaml.YAMLError:
            return {}
