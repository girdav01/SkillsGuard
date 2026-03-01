# SkillGuard

**Multi-engine security scanner for AI skills, MCP servers, and agentic tool definitions.s**
SkillGuard scans AI agent skill packages with 12 parallel engines to detect prompt injection, credential theft, code execution, data exfiltration, obfuscation, and MCP-specific attacks. It produces risk-scored verdicts, CycloneDX SBOMs, and maps findings to OWASP LLM Top 10 and MITRE ATT&CK frameworks.
![App screenshot](./images/screenshot.png)
---

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [CLI Commands](#cli-commands)
  - [scan](#scan)
  - [bom](#bom)
  - [monitor](#monitor)
  - [rules](#rules)
  - [server](#server)
- [Scan Engines](#scan-engines)
- [Detection Rules](#detection-rules)
- [Risk Scoring](#risk-scoring)
- [SBOM Generation](#sbom-generation)
- [REST API](#rest-api)
- [Reporting Formats](#reporting-formats)
- [Governance](#governance)
  - [Policy Engine](#policy-engine)
  - [RBAC](#rbac)
  - [Audit Log](#audit-log)
- [Intelligence](#intelligence)
  - [Threat Intelligence Database](#threat-intelligence-database)
  - [Community Verdicts](#community-verdicts)
  - [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Monitoring](#monitoring)
- [Supported Platforms](#supported-platforms)
- [Architecture](#architecture)
- [Development](#development)
- [License](#license)

---

## Quick Start

### Python

```bash
pip install skillguard
skillguard scan /path/to/skill
```

### Go

```bash
cd go-skillguard
go build -o bin/skillguard ./cmd/skillguard
./bin/skillguard scan /path/to/skill
```

Scan a skill directory and get an instant risk verdict:

```
$ skillguard scan ./my-skill

  SkillGuard - AI Agent Skills Scanner 
  ============================================

  Skill: my-skill
  SHA256: a1b2c3d4e5f6...
  Verdict: SUSPICIOUS (score: 45/100)

  Findings (3):
    [CRITICAL]  SG-PI-001  Instruction Override Pattern    SKILL.md:15
    [HIGH]      SG-CT-002  Environment File Access         install.sh:8
    [MEDIUM]    SG-OB-001  Base64 Encoded Payloads         payload.py:23

  Engines: 12/12 completed (47ms)
  OWASP Coverage: LLM01, LLM06
```

---

## Installation

### Python

**Core install (all engines except YARA and ML):**

```bash
pip install skillguard
```

**With optional extras:**

```bash
# YARA rule engine
pip install "skillguard[yara]"

# ML classifier (DeBERTa ONNX + sentence-transformers)
pip install "skillguard[ml]"

# Database persistence
pip install "skillguard[db]"

# Everything
pip install "skillguard[all]"

# Development
pip install "skillguard[dev]"
```

**Requirements:** Python 3.11+

### Go

**Build from source:**

```bash
cd go-skillguard
make build
```

**Or install directly:**

```bash
go install github.com/girdav01/skillguard/cmd/skillguard@latest
```

**Requirements:** Go 1.22+

**Dependencies:** chi (HTTP router), cobra (CLI), yaml.v3 (YAML parsing) — no CGO required.

The Go version includes the same 12 scan engines, CLI commands, REST API, governance, intelligence, monitoring, and reporting features as the Python version. Engines run in parallel via goroutines.

---

## CLI Commands

### scan

Scan a skill directory or git repository for security issues.

```bash
skillguard scan <PATH> [OPTIONS]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `PATH` | Path to the skill directory (or omit and use `--git`) |

**Options:**

| Option | Description |
|--------|-------------|
| `--git URL` | Git repository URL to scan |
| `--format {rich,json,sarif,html}` | Output format (default: `rich`) |
| `--output, -o FILE` | Write output to file |
| `--platform {generic,claude_code,claude_desktop,cursor,windsurf,openclaw}` | Skill platform (default: `generic`) |
| `--quick` | Quick scan (hash lookup only) |
| `--fail-on {critical,high,medium,low}` | Exit with code 1 if findings at or above this severity |
| `--rules-dir DIR` | Custom rules directory |

**Examples:**

```bash
# Basic scan with rich terminal output
skillguard scan ./my-skill

# Scan with JSON output
skillguard scan ./my-skill --format json

# Scan and save SARIF report (for GitHub Code Scanning)
skillguard scan ./my-skill --format sarif -o results.sarif

# Generate an HTML report
skillguard scan ./my-skill --format html -o report.html

# Scan a git repository
skillguard scan --git https://github.com/user/skill-repo

# Scan for a specific platform
skillguard scan ./my-skill --platform claude_code

# CI/CD gate: fail the build on HIGH or CRITICAL findings
skillguard scan ./my-skill --fail-on high

# Quick hash lookup (no full scan)
skillguard scan ./my-skill --quick

# Scan with custom detection rules
skillguard scan ./my-skill --rules-dir ./custom-rules

# Combine options: JSON output to file with CI gate
skillguard scan ./my-skill --format json -o scan.json --fail-on critical
```

---

### bom

Generate a CycloneDX SBOM (Software Bill of Materials) for a skill package.

```bash
skillguard bom <PATH> [OPTIONS]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `PATH` | Path to the skill directory |

**Options:**

| Option | Description |
|--------|-------------|
| `--format {cyclonedx,json}` | Output format (default: `cyclonedx`) |
| `--output, -o FILE` | Write SBOM to file |
| `--include-scan / --no-include-scan` | Run a security scan and embed findings in the SBOM |

**Examples:**

```bash
# Generate SBOM to stdout
skillguard bom ./my-skill

# Save SBOM to file
skillguard bom ./my-skill -o skill-bom.json

# Generate SBOM with embedded security scan findings
skillguard bom ./my-skill --include-scan -o skill-bom.json
```

The SBOM includes:

- Complete file inventory with SHA-256 integrity hashes
- Dependencies extracted from `requirements.txt`, `package.json`, and `pyproject.toml`
- Package URLs (purl) for every dependency (`pkg:pypi/pandas@2.1.4`, `pkg:npm/express@4.18.0`)
- Skill metadata from YAML frontmatter (name, version, author, description)
- Declared tool/capability list
- License detection (MIT, Apache-2.0, GPL, BSD, ISC)
- External URL references classified by type (vcs, distribution, documentation)
- Dependency graph in CycloneDX format
- Vulnerability data (when `--include-scan` is used)

---

### monitor

Monitor a skill directory for file changes and automatically re-scan on drift.

```bash
skillguard monitor <PATH> [OPTIONS]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `PATH` | Path to the skill directory to monitor |

**Options:**

| Option | Description |
|--------|-------------|
| `--interval SECONDS` | Poll interval in seconds, fallback mode (default: `5.0`) |

**Examples:**

```bash
# Monitor for changes (uses watchdog/inotify when available)
skillguard monitor ./my-skill

# Monitor with a custom poll interval
skillguard monitor ./my-skill --interval 10

# Monitor in the background
skillguard monitor ./my-skill &
```

Output:

```
Monitoring ./my-skill for changes (watchdog mode)... (Ctrl+C to stop)
Baseline captured.

Detected 2 change(s):
  [modified] SKILL.md
  [created]  exploit.py

  DRIFT DETECTED - re-scanning...
  Verdict: HIGH_RISK (score: 72/100)
```

---

### rules

List and manage detection rules.

```bash
skillguard rules [OPTIONS]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--list` | List all detection rules |
| `--category CATEGORY` | Filter by category |

**Examples:**

```bash
# List all rules
skillguard rules --list

# Filter by category
skillguard rules --list --category prompt_injection
skillguard rules --list --category credential_theft
skillguard rules --list --category code_execution
skillguard rules --list --category data_exfiltration
skillguard rules --list --category obfuscation
skillguard rules --list --category mcp_specific
```

Output:

```
Loaded 87 rules:

  [CRITICAL]  SG-PI-001       Instruction Override Pattern
  [CRITICAL]  SG-PI-002       Role Hijacking Pattern
  [CRITICAL]  SG-PI-003       System Prompt Extraction Attempt
  [HIGH    ]  SG-PI-004       Ignore Previous Instructions
  ...
```

---

### server

Start the SkillGuard REST API server.

```bash
skillguard server
```

**Examples:**

```bash
# Start the API server on port 8080
skillguard server

# The API is available at:
# http://localhost:8080/docs     (Swagger UI)
# http://localhost:8080/redoc    (ReDoc)
# http://localhost:8080/health   (Health check)
```

---

## Scan Engines

SkillGuard runs **12 engines in parallel** on every scan:

| # | Engine | What it Detects |
|---|--------|-----------------|
| 1 | **Regex Scanner** | Pattern-matched prompt injection, credential theft, code execution from 87 YAML rules |
| 2 | **YARA Scanner** | Complex multi-pattern malware signatures via YARA rules |
| 3 | **Secret Detector** | 24+ types of hardcoded secrets (AWS keys, API tokens, private keys, DB connection strings) |
| 4 | **ML Classifier** | Prompt injection in natural language via DeBERTa v3 ONNX model (heuristic fallback) |
| 5 | **Vector Search** | Semantic similarity to 20+ known attack patterns via ChromaDB embeddings (keyword fallback) |
| 6 | **Tool Poisoning Detector** | MCP tool description injection: hidden instructions, zero-width chars, role manipulation |
| 7 | **Tool Shadowing Detector** | MCP tool name conflicts with 44 protected built-in tools |
| 8 | **MCP Config Scanner** | Insecure transport, tunneling services, command injection, wildcard permissions in MCP configs |
| 9 | **Behavior Analyzer** | C2 callbacks, data exfiltration, persistence, keylogging, crypto mining in scripts |
| 10 | **Schema Validator** | Missing SKILL.md, excessive scripts, hidden files, oversized files, binary in text |
| 11 | **Permission Analyzer** | Dangerous permission combinations (shell+network, env+network, excessive privileges) |
| 12 | **Obfuscation Detector** | Base64, hex, chr() concatenation, eval+decode, ROT13, compression, dynamic imports |

Every engine produces typed `Finding` objects with severity, confidence, OWASP LLM mapping, and MITRE ATT&CK technique IDs.

---

## Detection Rules

**87 YAML-based detection rules** across 7 categories:

| Category | Rules | IDs | Severity |
|----------|-------|-----|----------|
| Prompt Injection | 25 | SG-PI-001 - SG-PI-025 | CRITICAL, HIGH |
| Credential Theft | 15 | SG-CT-001 - SG-CT-015 | CRITICAL |
| Code Execution | 15 | SG-CE-001 - SG-CE-015 | CRITICAL, HIGH |
| Data Exfiltration | 10 | SG-DE-001 - SG-DE-010 | CRITICAL, HIGH |
| Obfuscation | 10 | SG-OB-001 - SG-OB-010 | CRITICAL, HIGH, MEDIUM |
| MCP-Specific | 12 | SG-MCP-001 - SG-MCP-012 | CRITICAL, HIGH, MEDIUM |

Each rule includes:

```yaml
id: SG-PI-001
name: Instruction Override Pattern
description: Detects patterns that attempt to override agent system instructions
severity: critical
category: prompt_injection
owasp_llm: [LLM01]
mitre_attack: [T1059.006]
target: SKILL_MD
engine: REGEX
pattern:
  any:
    - "(?i)ignore\\s+(all\\s+)?(previous|prior)\\s+(instructions|prompts)"
remediation: Remove instructions that override system prompts
references:
  - https://genai.owasp.org/llmrisk/llm01-prompt-injection/
```

---

## Risk Scoring

Findings are aggregated into a **composite risk score** (0-100):

| Severity | Points |
|----------|--------|
| CRITICAL | +40 |
| HIGH | +20 |
| MEDIUM | +10 |
| LOW | +3 |
| INFO | 0 |

**Modifiers:**

- Threat intelligence match: instant score = 100
- Engine consensus (majority MALICIOUS): score x 1.3
- Trusted publisher: score x 0.7

**Verdict thresholds:**

| Score | Verdict |
|-------|---------|
| 0-20 | CLEAN |
| 21-40 | LOW_RISK |
| 41-60 | SUSPICIOUS |
| 61-80 | HIGH_RISK |
| 81-100 | MALICIOUS |

---

## SBOM Generation

SkillGuard provides two types of bill of materials:

### Skill SBOM (from directory)

Generate a CycloneDX 1.5 SBOM directly from a skill directory, without running a scan:

```bash
skillguard bom ./my-skill -o sbom.json
```

Produces a comprehensive inventory including file manifest, dependencies (pip, npm, pyproject.toml), metadata, licenses, external references, and declared capabilities.

### AI-BOM (from scan results)

Generate a CycloneDX AI-BOM from a completed scan via the API:

```bash
# Submit scan, then get AI-BOM
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"skill_path": "./my-skill"}'

# Returns: {"scan_id": "abc123", "status": "completed"}

curl http://localhost:8080/api/v1/ai-bom/abc123
```

Includes security findings as CycloneDX vulnerabilities with OWASP/MITRE mappings and remediation guidance.

---

## REST API

Start the server with `skillguard server`, then access Swagger UI at `http://localhost:8080/docs`.

### Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan` | Submit a skill for scanning |
| `GET` | `/api/v1/scan/{scan_id}` | Get scan results by ID |
| `GET` | `/api/v1/scan/{scan_id}/report?format={json,sarif,html}` | Download scan report |

```bash
# Submit a scan
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"skill_path": "./my-skill", "platform": "claude_code"}'

# Get results
curl http://localhost:8080/api/v1/scan/{scan_id}

# Download SARIF report
curl http://localhost:8080/api/v1/scan/{scan_id}/report?format=sarif
```

### Skill Reputation

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/skill/{sha256}` | Instant reputation lookup by hash |

```bash
# Look up a skill by SHA256 hash
curl http://localhost:8080/api/v1/skill/a1b2c3d4e5f6...
```

### SBOM & AI-BOM

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/sbom` | Generate CycloneDX SBOM from a skill directory |
| `GET` | `/api/v1/ai-bom/{scan_id}` | Generate CycloneDX AI-BOM from scan results |

```bash
# Generate SBOM (with optional scan result embedding)
curl -X POST http://localhost:8080/api/v1/sbom \
  -H "Content-Type: application/json" \
  -d '{"skill_path": "./my-skill", "include_scan_id": "optional-scan-id"}'

# Generate AI-BOM from a completed scan
curl http://localhost:8080/api/v1/ai-bom/{scan_id}
```

### Policy Engine

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/policies` | List all configured policies |
| `POST` | `/api/v1/policies` | Create a new policy rule |
| `DELETE` | `/api/v1/policies/{policy_id}` | Delete a policy rule |
| `POST` | `/api/v1/policies/load-yaml` | Load policies from YAML |
| `POST` | `/api/v1/policies/evaluate/{scan_id}` | Evaluate scan against policies |

```bash
# List policies
curl http://localhost:8080/api/v1/policies

# Create a custom policy
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "id": "CUSTOM-001",
    "name": "Block High Score",
    "action": "block",
    "conditions": {"min_score": 70}
  }'

# Evaluate a scan against all policies
curl -X POST http://localhost:8080/api/v1/policies/evaluate/{scan_id}
```

### Community Verdicts

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/community/{sha256}` | Get community reputation |
| `POST` | `/api/v1/community/{sha256}/verdict` | Submit a verdict |
| `POST` | `/api/v1/community/{sha256}/comment` | Submit a comment |

```bash
# Get community reputation
curl http://localhost:8080/api/v1/community/{sha256}

# Submit a verdict
curl -X POST http://localhost:8080/api/v1/community/{sha256}/verdict \
  -H "Content-Type: application/json" \
  -d '{"analyst_id": "analyst1", "verdict": "malicious", "confidence": 0.95}'

# Submit a comment
curl -X POST http://localhost:8080/api/v1/community/{sha256}/comment \
  -H "Content-Type: application/json" \
  -d '{"author_id": "author1", "text": "Contains reverse shell pattern"}'
```

### Monitoring

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/monitor` | Register a skill for monitoring |
| `GET` | `/api/v1/monitor` | List all monitored skills |
| `GET` | `/api/v1/monitor/check?skill_path=...` | Check for drift |
| `DELETE` | `/api/v1/monitor?skill_path=...` | Stop monitoring |

```bash
# Register for monitoring
curl -X POST http://localhost:8080/api/v1/monitor \
  -H "Content-Type: application/json" \
  -d '{"skill_path": "./my-skill"}'

# Check for drift
curl "http://localhost:8080/api/v1/monitor/check?skill_path=./my-skill"

# List all monitored skills
curl http://localhost:8080/api/v1/monitor
```

### Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/rules?category=...&engine=...` | List detection rules |

```bash
# List all rules
curl http://localhost:8080/api/v1/rules

# Filter by category
curl "http://localhost:8080/api/v1/rules?category=prompt_injection"
```

### Audit Log

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/audit` | Query the audit log |
| `GET` | `/api/v1/audit/verify` | Verify audit log integrity |
| `GET` | `/api/v1/audit/export` | Export full audit log |

```bash
# Query audit entries
curl "http://localhost:8080/api/v1/audit?action=scan_completed&limit=50"

# Verify integrity of the audit chain
curl http://localhost:8080/api/v1/audit/verify

# Export entire audit log
curl http://localhost:8080/api/v1/audit/export
```

### Health Check

```bash
curl http://localhost:8080/health
# {"status": "healthy", "version": "0.3.0"}
```

---

## Reporting Formats

| Format | CLI Flag | Description |
|--------|----------|-------------|
| **Rich** | `--format rich` | Colorized terminal output with severity badges (default) |
| **JSON** | `--format json` | Full scan result as structured JSON |
| **SARIF** | `--format sarif` | Static Analysis Results Interchange Format 2.1.0 (GitHub Code Scanning compatible) |
| **HTML** | `--format html` | Self-contained HTML report with dark theme, score visualization, and findings table |
| **CycloneDX** | `skillguard bom` | CycloneDX 1.5 SBOM with file inventory and dependency graph |

```bash
# Terminal output (default)
skillguard scan ./my-skill

# JSON for programmatic use
skillguard scan ./my-skill --format json | jq '.verdict'

# SARIF for GitHub Code Scanning
skillguard scan ./my-skill --format sarif -o results.sarif

# HTML report for sharing
skillguard scan ./my-skill --format html -o report.html

# SBOM for supply chain transparency
skillguard bom ./my-skill -o sbom.json
```

---

## Governance

### Policy Engine

Evaluate scan results against configurable organizational policies with block/warn/audit actions.

**6 built-in default policies:**

| ID | Name | Action | Condition |
|----|------|--------|-----------|
| POL-001 | Block Malicious Skills | block | verdict = malicious |
| POL-002 | Block Critical Findings | block | any critical findings |
| POL-003 | Warn on High Risk | warn | verdict = high_risk |
| POL-004 | Warn on Suspicious | warn | verdict = suspicious |
| POL-005 | Block High Score | block | score >= 80 |
| POL-006 | Require OWASP Coverage | warn | OWASP LLM01 detected |

**Custom policies via YAML:**

```yaml
policies:
  - id: ORG-001
    name: Block Network Skills
    description: Block skills that request network access
    action: block
    conditions:
      min_severity: high
      min_count: 1
    enabled: true
```

```bash
# Load custom policies via API
curl -X POST http://localhost:8080/api/v1/policies/load-yaml \
  -H "Content-Type: application/json" \
  -d '{"yaml_content": "policies:\n  - id: ORG-001\n    name: Custom\n    action: block\n    conditions:\n      min_score: 50"}'
```

### RBAC

Role-based access control for the API with 4 built-in roles:

| Role | Permissions |
|------|------------|
| **admin** | All permissions (scan, rules, policy, monitor, audit, admin) |
| **analyst** | Scan, rules (read/write), policy (read), monitor, audit |
| **developer** | Scan, rules (read only), skill lookup, monitor (read only) |
| **viewer** | Read-only access to scans, rules, and skill lookups |

### Audit Log

Tamper-evident, integrity-chained audit trail for all significant actions. Each entry is SHA-256 hash-chained to the previous entry for tamper detection.

```bash
# Verify the audit log hasn't been tampered with
curl http://localhost:8080/api/v1/audit/verify
# {"is_valid": true, "total_entries": 42, "last_valid_index": 42}
```

---

## Intelligence

### Threat Intelligence Database

Known-malicious skill hash database seeded with indicators from the ToxicSkills research. Integrated into the scan pipeline for instant hash lookups that override risk scoring to score = 100.

### Community Verdicts

Crowdsourced reputation system where analysts can submit verdicts (clean/suspicious/malicious) and comments on scanned skills. Consensus is calculated via majority voting.

### MITRE ATT&CK Mapping

Findings are mapped to 18 MITRE ATT&CK techniques including:

- T1059 - Command and Scripting Interpreter
- T1071 - Application Layer Protocol
- T1048 - Exfiltration Over Alternative Protocol
- T1552 - Unsecured Credentials
- T1053 - Scheduled Task/Job
- T1547 - Boot or Logon Autostart Execution
- T1027 - Obfuscated Files or Information
- T1195 - Supply Chain Compromise

---

## Monitoring

### Drift Detection

SkillGuard monitors skill directories for unauthorized modifications ("rug pull" attacks) by capturing a hash baseline and detecting added, modified, or removed files.

```bash
# CLI monitoring with auto-rescan
skillguard monitor ./my-skill

# API-based monitoring
curl -X POST http://localhost:8080/api/v1/monitor \
  -H "Content-Type: application/json" \
  -d '{"skill_path": "./my-skill"}'

# Check for drift
curl "http://localhost:8080/api/v1/monitor/check?skill_path=./my-skill"
```

Uses `watchdog` (inotify/FSEvents) for real-time file system events with automatic polling fallback.

---

## Supported Platforms

SkillGuard supports skills targeting these AI agent platforms:

| Platform | Value |
|----------|-------|
| Claude Code | `claude_code` |
| Claude Desktop | `claude_desktop` |
| Cursor | `cursor` |
| Windsurf | `windsurf` |
| OpenClaw | `openclaw` |
| Generic | `generic` (default) |

```bash
skillguard scan ./my-skill --platform claude_code
```

---

## Architecture

Both the Python and Go implementations share the same architecture:

```
Skill Package
    |
    v
[Skill Parser] --> Parse files, classify types, extract frontmatter
    |
    v
[Scan Orchestrator] --> Run 12 engines in parallel
    |                    (Python: asyncio.gather / Go: goroutines + sync.WaitGroup)
    |
    +--> [Regex Scanner]         87 YAML rules
    +--> [YARA Scanner]          Multi-pattern signatures
    +--> [Secret Detector]       24+ credential patterns
    +--> [ML Classifier]         DeBERTa v3 ONNX model (Go: heuristic fallback)
    +--> [Vector Search]         ChromaDB embeddings (Go: keyword similarity)
    +--> [Tool Poisoning]        MCP description injection
    +--> [Tool Shadowing]        MCP name conflicts
    +--> [Config Scanner]        MCP config vulnerabilities
    +--> [Behavior Analyzer]     C2, exfil, persistence patterns
    +--> [Schema Validator]      Structural anomalies
    +--> [Permission Analyzer]   Dangerous permission combos
    +--> [Obfuscation Detector]  Encoded/packed payloads
    |
    v
[Verdict Engine] --> Aggregate findings into risk score (0-100)
    |
    +--> [Threat Intel] --> Known-malicious hash lookup
    +--> [Policy Engine] --> Evaluate against organizational policies
    |
    v
[Reports] --> JSON, SARIF, HTML, CycloneDX SBOM
```

### Go Project Structure

```
go-skillguard/
├── cmd/skillguard/main.go        # Cobra CLI (scan, bom, monitor, rules, server)
├── internal/
│   ├── core/                     # Models, hasher, parser, rules loader, verdict, scanner
│   ├── engines/                  # ScanEngine interface + 12 engine implementations
│   ├── governance/               # Policy engine, RBAC, integrity-chained audit log
│   ├── intelligence/             # Threat DB, community verdicts, MITRE ATT&CK mapper
│   ├── monitoring/               # Drift detector
│   ├── reporting/                # JSON, SARIF, HTML, CycloneDX SBOM, AI-BOM
│   └── api/                      # Chi-based REST API (19 endpoints)
├── go.mod
├── go.sum
└── Makefile
```

---

## Development

### Python

```bash
# Clone and install in development mode
git clone https://github.com/girdav01/SkillsGuard.git
cd SkillsGuard
pip install -e ".[dev]"

# Run tests (330 tests)
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=skillguard --cov-report=html

# Lint
ruff check src/
```

**Python test coverage by module:**

| Module | Tests |
|--------|-------|
| Core (scanner, verdict, hasher, parser) | 35 |
| Prompt injection engines | 24 |
| MCP engines | 20 |
| Secret detector | 18 |
| ML classifier & vector search | 18 |
| Monitoring (drift, watcher) | 14 |
| HTML reporting | 6 |
| Threat intel & community | 16 |
| REST API (Phase 1-2) | 18 |
| Sandbox & behavior analysis | 18 |
| Structural engines | 30 |
| Governance (policy, RBAC, audit) | 40 |
| AI-BOM | 8 |
| Phase 3 API routes | 19 |
| Skill SBOM | 61 |
| **Total** | **330** |

### Go

```bash
cd go-skillguard

# Build
make build

# Run all tests (62 tests)
make test

# Format and vet
make fmt
make vet

# Build and test in one command
make
```

**Go test coverage by package:**

| Package | Tests |
|---------|-------|
| core (models, hasher, parser, verdict) | 23 |
| engines (all 12 engines) | 20 |
| governance (policy, RBAC, audit) | 11 |
| intelligence (threat DB, community, MITRE) | 3 |
| monitoring (drift detector) | 5 |
| reporting (JSON, SARIF, HTML, AI-BOM) | 7 |
| **Total** | **62** |

### Feature Parity

Both implementations share the same detection logic, risk scoring algorithm, and output formats. Key differences:

| Feature | Python | Go |
|---------|--------|-----|
| ML Classifier | DeBERTa v3 ONNX model | Heuristic fallback (33 indicators) |
| Vector Search | ChromaDB embeddings | Keyword similarity (20 patterns) |
| YARA Scanner | Native via yara-python | Placeholder (no CGO) |
| Sandbox | nsjail/Docker isolation | Placeholder |
| HTTP Framework | FastAPI + Uvicorn | Chi router |
| CLI Framework | Click | Cobra |
| Parallelism | asyncio.gather | goroutines + sync.WaitGroup |
| Package Manager | pip (PyPI) | go modules |

---

## License

MIT License. See [pyproject.toml](pyproject.toml) for details.

**Author:** David Girard

**Motivation:** The [Snyk ToxicSkills research](https://snyk.io/) found 76 confirmed malicious skills out of 3,984 scanned, with 36% exhibiting prompt injection patterns. OWASP ranks Prompt Injection as the #1 LLM vulnerability, affecting 73% of production deployments. SkillGuard was built to address this gap in AI agent supply chain security.
