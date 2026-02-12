"""Policy engine for organizational security policies.

Evaluates scan results against configurable organizational policies
to enforce security standards. Supports YAML-based policy definitions
with optional OPA (Open Policy Agent) integration for complex policies.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import yaml
from pydantic import BaseModel, Field

from skillguard.core.models import ScanResult, Severity, Verdict


class PolicyRule(BaseModel):
    """A single policy rule."""

    id: str
    name: str
    description: str = ""
    action: str = "block"  # block, warn, audit
    conditions: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class PolicyViolation(BaseModel):
    """A policy violation found during evaluation."""

    policy_id: str
    policy_name: str
    action: str
    description: str
    details: str = ""


class PolicyResult(BaseModel):
    """Result of policy evaluation."""

    allowed: bool
    violations: list[PolicyViolation] = Field(default_factory=list)
    warnings: list[PolicyViolation] = Field(default_factory=list)
    evaluated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PolicyEngine:
    """Evaluates scan results against organizational policies.

    Supports configurable policies that can block, warn, or audit
    based on scan results. Policies are defined in YAML format.
    """

    def __init__(self) -> None:
        self._policies: list[PolicyRule] = []
        self._load_default_policies()

    def _load_default_policies(self) -> None:
        """Load built-in default policies."""
        self._policies = [
            PolicyRule(
                id="POL-001",
                name="Block Malicious Skills",
                description="Block any skill with a MALICIOUS verdict",
                action="block",
                conditions={"verdict": "malicious"},
            ),
            PolicyRule(
                id="POL-002",
                name="Block Critical Findings",
                description="Block skills with critical severity findings",
                action="block",
                conditions={"min_severity": "critical", "min_count": 1},
            ),
            PolicyRule(
                id="POL-003",
                name="Warn on High Risk",
                description="Warn on skills with HIGH_RISK verdict",
                action="warn",
                conditions={"verdict": "high_risk"},
            ),
            PolicyRule(
                id="POL-004",
                name="Warn on Suspicious",
                description="Warn on skills with SUSPICIOUS verdict",
                action="warn",
                conditions={"verdict": "suspicious"},
            ),
            PolicyRule(
                id="POL-005",
                name="Block High Score",
                description="Block skills with composite score >= 80",
                action="block",
                conditions={"min_score": 80},
            ),
            PolicyRule(
                id="POL-006",
                name="Require OWASP Coverage",
                description="Warn if OWASP LLM01 is detected",
                action="warn",
                conditions={"owasp_detected": "LLM01"},
            ),
        ]

    def load_policies_from_yaml(self, yaml_content: str) -> int:
        """Load policies from a YAML string.

        Returns the number of policies loaded.
        """
        try:
            data = yaml.safe_load(yaml_content)
        except yaml.YAMLError:
            return 0

        if not isinstance(data, dict) or "policies" not in data:
            return 0

        count = 0
        for entry in data.get("policies", []):
            if isinstance(entry, dict) and "id" in entry:
                try:
                    policy = PolicyRule(**entry)
                    self._policies.append(policy)
                    count += 1
                except Exception:
                    continue
        return count

    async def evaluate(self, result: ScanResult) -> PolicyResult:
        """Evaluate a scan result against all active policies.

        Returns:
            PolicyResult with allowed status and any violations.
        """
        violations: list[PolicyViolation] = []
        warnings: list[PolicyViolation] = []

        verdict_str = result.verdict if isinstance(result.verdict, str) else result.verdict.value

        for policy in self._policies:
            if not policy.enabled:
                continue

            violated = self._check_conditions(policy, result, verdict_str)
            if not violated:
                continue

            violation = PolicyViolation(
                policy_id=policy.id,
                policy_name=policy.name,
                action=policy.action,
                description=policy.description,
                details=violated,
            )

            if policy.action == "block":
                violations.append(violation)
            elif policy.action == "warn":
                warnings.append(violation)
            else:  # audit
                warnings.append(violation)

        return PolicyResult(
            allowed=len(violations) == 0,
            violations=violations,
            warnings=warnings,
        )

    def _check_conditions(
        self, policy: PolicyRule, result: ScanResult, verdict_str: str
    ) -> str:
        """Check if a policy's conditions are met. Returns details string if violated."""
        conditions = policy.conditions

        # Check verdict condition
        if "verdict" in conditions:
            if verdict_str == conditions["verdict"]:
                return f"Verdict is {verdict_str}"

        # Check minimum score
        if "min_score" in conditions:
            if result.composite_score >= conditions["min_score"]:
                return f"Score {result.composite_score} >= {conditions['min_score']}"

        # Check minimum severity count
        if "min_severity" in conditions and "min_count" in conditions:
            sev = conditions["min_severity"]
            count = result.findings_by_severity.get(sev, 0)
            if count >= conditions["min_count"]:
                return f"{count} {sev} findings (threshold: {conditions['min_count']})"

        # Check OWASP detection
        if "owasp_detected" in conditions:
            owasp_id = conditions["owasp_detected"]
            if owasp_id in result.owasp_coverage:
                return f"OWASP {owasp_id} detected"

        return ""

    def add_policy(self, policy: PolicyRule) -> None:
        """Add a policy rule."""
        self._policies.append(policy)

    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy by ID."""
        initial = len(self._policies)
        self._policies = [p for p in self._policies if p.id != policy_id]
        return len(self._policies) < initial

    def list_policies(self) -> list[PolicyRule]:
        """List all configured policies."""
        return list(self._policies)
