"""Core data models for SkillGuard."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(str, Enum):
    CLEAN = "clean"
    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"
    MALICIOUS = "malicious"


class EngineVerdict(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class SkillPlatform(str, Enum):
    CLAUDE_CODE = "claude_code"
    CLAUDE_DESKTOP = "claude_desktop"
    CURSOR = "cursor"
    WINDSURF = "windsurf"
    OPENCLAW = "openclaw"
    GENERIC = "generic"


class FileType(str, Enum):
    SKILL_MD = "skill_md"
    FRONTMATTER = "frontmatter"
    SCRIPT_PYTHON = "script_python"
    SCRIPT_BASH = "script_bash"
    SCRIPT_JS = "script_javascript"
    SCRIPT_TS = "script_typescript"
    TEMPLATE = "template"
    RESOURCE = "resource"
    CONFIG = "config"
    OTHER = "other"


class SkillFile(BaseModel):
    """A single file within a skill package."""

    path: str
    file_type: FileType
    sha256: str
    size_bytes: int
    content: str | None = None


class Finding(BaseModel):
    """A single security finding from a scan engine."""

    rule_id: str
    rule_name: str
    severity: Severity
    category: str
    description: str
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    snippet: str | None = None
    cwe: str | None = None
    owasp_llm: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    remediation: str | None = None


class EngineResult(BaseModel):
    """Result from a single scanning engine."""

    engine_name: str
    engine_version: str
    verdict: EngineVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    detection_name: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    duration_ms: int


class ScanResult(BaseModel):
    """Complete scan result aggregating all engine results."""

    scan_id: str
    skill_name: str
    skill_sha256: str
    platform: SkillPlatform
    scan_started: datetime
    scan_completed: datetime
    composite_score: int = Field(ge=0, le=100)
    verdict: Verdict
    engine_results: list[EngineResult] = Field(default_factory=list)
    total_findings: int
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    files_scanned: int
    owasp_coverage: list[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    """Request to scan a skill."""

    skill_path: str | None = None
    git_url: str | None = None
    scan_type: str = "full"
    platform: SkillPlatform = SkillPlatform.GENERIC


class DetectionRule(BaseModel):
    """A detection rule definition loaded from YAML."""

    id: str
    name: str
    description: str
    severity: Severity
    category: str
    owasp_llm: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    target: str  # SKILL_MD, FRONTMATTER, SCRIPT, ANY
    engine: str  # REGEX, YARA, SEMGREP, ML_CLASSIFIER
    pattern: str | dict
    false_positive_notes: str | None = None
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    enabled: bool = True
