"""SARIF (Static Analysis Results Interchange Format) report generator.

Generates SARIF v2.1.0 compatible output for integration with GitHub
Code Scanning, VS Code, and other SARIF-consuming tools.
"""

from __future__ import annotations

import json
from typing import Any

from skillguard.core.models import ScanResult, Severity

# SARIF severity levels mapping
_SEVERITY_MAP: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def generate_sarif_report(result: ScanResult) -> str:
    """Generate a SARIF 2.1.0 report from scan results.

    Returns:
        JSON string in SARIF format.
    """
    # Collect all unique rules
    rules_map: dict[str, dict[str, Any]] = {}
    results_list: list[dict[str, Any]] = []

    for engine_result in result.engine_results:
        for finding in engine_result.findings:
            # Build rule entry
            if finding.rule_id not in rules_map:
                rule_entry: dict[str, Any] = {
                    "id": finding.rule_id,
                    "name": finding.rule_name,
                    "shortDescription": {"text": finding.rule_name},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {
                        "level": _SEVERITY_MAP.get(finding.severity.value, "warning")
                    },
                    "properties": {
                        "tags": [finding.category],
                    },
                }
                if finding.owasp_llm:
                    rule_entry["properties"]["owasp_llm"] = finding.owasp_llm
                if finding.mitre_attack:
                    rule_entry["properties"]["mitre_attack"] = finding.mitre_attack
                if finding.cwe:
                    rule_entry["properties"]["cwe"] = finding.cwe
                rules_map[finding.rule_id] = rule_entry

            # Build result entry
            sarif_result: dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": _SEVERITY_MAP.get(finding.severity.value, "warning"),
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": {},
                        }
                    }
                ],
            }

            if finding.line_start is not None:
                sarif_result["locations"][0]["physicalLocation"]["region"][
                    "startLine"
                ] = finding.line_start
            if finding.line_end is not None:
                sarif_result["locations"][0]["physicalLocation"]["region"][
                    "endLine"
                ] = finding.line_end
            if finding.snippet:
                sarif_result["locations"][0]["physicalLocation"]["region"][
                    "snippet"
                ] = {"text": finding.snippet}

            if finding.remediation:
                sarif_result["fixes"] = [
                    {
                        "description": {"text": finding.remediation},
                    }
                ]

            results_list.append(sarif_result)

    # Build SARIF document
    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillGuard",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/skillguard/skillguard",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results_list,
                "properties": {
                    "skillName": result.skill_name,
                    "skillSha256": result.skill_sha256,
                    "compositeScore": result.composite_score,
                    "verdict": result.verdict if isinstance(result.verdict, str) else result.verdict.value,
                    "filesScanned": result.files_scanned,
                },
            }
        ],
    }

    return json.dumps(sarif, indent=2)
