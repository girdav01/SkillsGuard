"""CycloneDX AI-BOM (AI Bill of Materials) generator.

Generates a CycloneDX-compatible Software Bill of Materials (SBOM)
extended with AI-specific metadata for scanned skills. This enables
supply chain transparency for AI agent tools.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from skillguard.core.models import ScanResult


def generate_ai_bom(result: ScanResult) -> dict[str, Any]:
    """Generate a CycloneDX AI-BOM from scan results.

    Returns a dict conforming to CycloneDX 1.5+ with AI extensions.
    """
    verdict_str = result.verdict if isinstance(result.verdict, str) else result.verdict.value

    # Build component entry for the skill
    component: dict[str, Any] = {
        "type": "application",
        "name": result.skill_name,
        "version": "unknown",
        "bom-ref": f"skill:{result.skill_sha256[:16]}",
        "hashes": [
            {
                "alg": "SHA-256",
                "content": result.skill_sha256,
            }
        ],
        "properties": [
            {"name": "skillguard:platform", "value": result.platform if isinstance(result.platform, str) else result.platform.value},
            {"name": "skillguard:verdict", "value": verdict_str},
            {"name": "skillguard:score", "value": str(result.composite_score)},
            {"name": "skillguard:scan_id", "value": result.scan_id},
            {"name": "skillguard:files_scanned", "value": str(result.files_scanned)},
            {"name": "skillguard:total_findings", "value": str(result.total_findings)},
        ],
    }

    # Add OWASP coverage as properties
    for owasp_id in result.owasp_coverage:
        component["properties"].append({
            "name": "skillguard:owasp_llm",
            "value": owasp_id,
        })

    # Add engine results as evidence
    evidence: list[dict[str, Any]] = []
    for er in result.engine_results:
        engine_verdict = er.verdict if isinstance(er.verdict, str) else er.verdict.value
        evidence.append({
            "name": f"skillguard:engine:{er.engine_name}",
            "value": json.dumps({
                "verdict": engine_verdict,
                "confidence": er.confidence,
                "findings_count": len(er.findings),
                "duration_ms": er.duration_ms,
            }),
        })

    if evidence:
        component["evidence"] = {"identity": {"tools": evidence}}

    # Build vulnerability entries from findings
    vulnerabilities: list[dict[str, Any]] = []
    seen_rules: set[str] = set()

    for er in result.engine_results:
        for finding in er.findings:
            if finding.rule_id in seen_rules:
                continue
            seen_rules.add(finding.rule_id)

            vuln: dict[str, Any] = {
                "id": finding.rule_id,
                "source": {
                    "name": "SkillGuard",
                    "url": "https://github.com/skillguard/skillguard",
                },
                "description": finding.description,
                "ratings": [
                    {
                        "source": {"name": "SkillGuard"},
                        "severity": finding.severity if isinstance(finding.severity, str) else finding.severity.value,
                        "score": finding.confidence,
                        "method": "other",
                    }
                ],
                "affects": [
                    {
                        "ref": f"skill:{result.skill_sha256[:16]}",
                    }
                ],
                "properties": [],
            }

            if finding.cwe:
                vuln["cwes"] = [int(finding.cwe.replace("CWE-", ""))] if finding.cwe.startswith("CWE-") else []

            for owasp in finding.owasp_llm:
                vuln["properties"].append({"name": "owasp:llm", "value": owasp})
            for mitre in finding.mitre_attack:
                vuln["properties"].append({"name": "mitre:attack", "value": mitre})

            if finding.remediation:
                vuln["recommendation"] = finding.remediation

            vulnerabilities.append(vuln)

    # Build the BOM
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "SkillGuard",
                        "version": "0.3.0",
                        "description": "Multi-engine security scanner for AI Agent Skills",
                    }
                ]
            },
            "component": component,
        },
        "components": [component],
        "vulnerabilities": vulnerabilities,
    }

    return bom


def generate_ai_bom_json(result: ScanResult) -> str:
    """Generate a CycloneDX AI-BOM as a JSON string."""
    return json.dumps(generate_ai_bom(result), indent=2)
