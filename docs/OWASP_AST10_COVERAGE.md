# OWASP Agentic Skills Top 10 — Coverage & Roadmap

SkillGuard aligns its detection engines, rules, scoring, and governance features with the
[OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)
(AST10, 2026 Edition). This document describes how each risk is covered today, and the
improvement roadmap for closing the remaining gaps.

Every `Finding` carries an `owasp_ast` list, scan results expose a deduplicated
`owasp_ast_coverage` list, and the policy engine can gate on AST IDs
(`owasp_ast_detected` in Python, the `owasp_ast` condition field in Go).

## Coverage matrix

| ID | Risk | SkillGuard coverage today |
|----|------|---------------------------|
| AST01 | Malicious Skills | 87+ regex/YARA rules (prompt injection, credential theft, code execution, exfiltration, obfuscation), behavior analyzer, sandbox executor, threat-intel hash database, ML classifier, vector search |
| AST02 | Supply Chain Compromise | `rules/supply_chain` (typosquats, unpinned deps, non-official registries, missing integrity hashes, deprecated packages), dependency checker engine, MCP config transport checks, CycloneDX SBOM with purl + hash inventory |
| AST03 | Over-Privileged Skills | Permission analyzer (dangerous permission combos), `rules/credential_theft` (tagged AST03), MCP excessive-permission rules, POL-008 default policy blocks unapproved skills with AST03 findings |
| AST04 | Insecure Metadata | Metadata validator engine, `rules/metadata` (author impersonation, misleading safety claims, missing license, invalid version, suspicious homepage), `rules/deserialization` (unsafe YAML/XML/JSON parsing of skill content) |
| AST05 | Prompt Injection | 25 `rules/prompt_injection` rules, ML classifier (DeBERTa), vector similarity search, MCP tool-description poisoning detector |
| AST06 | Weak Isolation | Isolation checker (`rules/isolation`: privileged containers, host networking, dangerous mounts, missing security profiles), exfiltration rules tagged AST06, sandbox execution (Python) |
| AST07 | Update Drift | Drift monitor (`skillguard monitor`, REST monitoring API) with hash baselines and auto-rescan, `rules/update_drift` (unpinned deps, missing lock files, mutable git references), MCP rug-pull indicator |
| AST08 | Poor Scanning | SkillGuard *is* the countermeasure: 12 parallel engines combining pattern, semantic (ML/vector), structural, and behavioral analysis at publish/install time; SARIF output for CI gates (`--fail-on`) |
| AST09 | No Governance | Policy engine (block/warn/audit, AST-aware conditions), RBAC, tamper-evident audit log, skill inventory registration policy (POL-007), approval workflow policy (POL-008), community verdicts |
| AST10 | Cross-Platform Reuse | Cross-platform analyzer + `rules/cross_platform` (platform-specific APIs, incompatible permissions, hardcoded platform paths, transport mismatch, sandbox escalation), `--platform` scan flag |

## Conventions for `owasp_ast` tagging

- Rules that only make sense as part of a deliberately malicious skill keep `AST01`
  and add the more specific risk where one exists (e.g. prompt-injection rules are
  `[AST01, AST05]`, credential theft is `[AST01, AST03]`, exfiltration is `[AST01, AST06]`).
- Hygiene/posture rules map to the specific risk alone (e.g. supply chain `[AST02]`,
  metadata `[AST04]`, isolation `[AST06]`, update drift `[AST07]`, cross-platform `[AST10]`).
- Engines that emit hardcoded findings (secret detector, tool poisoning, behavior
  analyzer, obfuscation detector, ML classifier, vector search) tag findings with the
  same conventions as the equivalent YAML rules.

## Improvement roadmap

### AST02 — Supply Chain Compromise
- **Vulnerability enrichment:** query the [OSV](https://osv.dev) API for known CVEs in
  dependencies extracted for the SBOM, and embed them as CycloneDX vulnerabilities.
- **Registry provenance:** verify package publisher/signing metadata (npm provenance,
  PyPI Trusted Publishers, Sigstore) where available.
- **Expanded typosquat corpus:** generate candidate typosquats from the top packages of
  each ecosystem rather than a static list.

### AST03 — Over-Privileged Skills
- **Declared-vs-observed privilege delta:** compare permissions declared in skill
  frontmatter against capabilities inferred from code (network calls, file access,
  subprocess use) and flag understated scope.
- **Risk-tier validation:** validate a `risk_tier` frontmatter field and require
  approval workflows for high tiers.

### AST04 — Insecure Metadata
- **Frontmatter schema validation:** strict schema for SKILL.md frontmatter
  (name, version, author, permissions, requires) with findings for missing or
  malformed fields, not just suspicious values.
- **Claim/behavior correlation:** automatically correlate "safe/read-only/sandboxed"
  claims (SG-MD-002) with dangerous-operation findings from other engines and escalate
  severity when both are present.

### AST05 — Prompt Injection
- **Cross-file injection chains:** detect instructions in one file that direct the agent
  to read/execute another file in the package (multi-stage injection).
- **Model refresh:** periodically retrain/refresh the DeBERTa ONNX classifier and the
  vector attack-pattern corpus from newly published skill malware research.

### AST06 — Weak Isolation
- **Go sandbox parity:** the Go port's sandbox executor is a placeholder; implement
  container-based dynamic analysis or clearly report reduced coverage in results.
- **Runtime syscall profiling:** optional seccomp/eBPF profiling during sandbox
  execution to observe real capability use.

### AST07 — Update Drift
- **Signed baselines:** sign the monitor's hash baseline so a compromised host cannot
  silently re-baseline after a rug pull.
- **Approval-scoped baselines:** tie baselines to the approving identity (RBAC) and
  automatically revoke approval (policy block) when drift is detected.
- **Registry re-scan hooks:** webhook/CI integration to re-scan on upstream release.

### AST08 — Poor Scanning
- **Install-time hook:** a lightweight `skillguard install-check` intended to run in
  agent platforms' skill-install flows (pre-commit style), not only in CI.
- **Coverage reporting:** report per-scan which engines ran vs. degraded (e.g. YARA or
  ML unavailable) so consumers can detect reduced-scanning conditions.

### AST09 — No Governance
- **Persistent skill inventory:** a first-class inventory store (currently policy
  POL-007 only warns based on a flag) with fleet-wide AI-BOM export.
- **Approval workflow API:** endpoints to record approvals (`approved_by`) that POL-008
  consumes, wired into RBAC roles.

### AST10 — Cross-Platform Reuse
- **Platform capability matrix:** encode per-platform capability/permission semantics
  (Claude Code vs. Cursor vs. Windsurf, etc.) and diff a skill's requirements against
  the target platform at scan time instead of pattern-only checks.

## References

- OWASP Agentic Skills Top 10: https://owasp.org/www-project-agentic-skills-top-10/
- Per-risk pages: `https://owasp.org/www-project-agentic-skills-top-10/ast01` … `ast10`
- OWASP Top 10 for LLM Applications: https://genai.owasp.org/
