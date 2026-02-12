# SkillGuard

Multi-engine security scanner for AI Agent Skills, MCP Servers, and agentic tool definitions.

## Quick Start

```bash
pip install skillguard
skillguard scan /path/to/skill
```

## Features

- Multi-engine scanning (regex, YARA, secret detection)
- 50+ detection rules for prompt injection, credential theft, code execution
- CLI with rich terminal output
- REST API (FastAPI)
- JSON and SARIF report generation
- OWASP LLM Top 10 mapping
