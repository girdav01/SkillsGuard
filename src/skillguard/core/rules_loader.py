"""Load detection rules from YAML files."""

from __future__ import annotations

from pathlib import Path

import yaml

from skillguard.core.models import DetectionRule

# Default rules directory (relative to package root)
_DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "rules"


def load_rules(
    rules_dir: str | Path | None = None,
    engine_filter: str | None = None,
    category_filter: str | None = None,
    enabled_only: bool = True,
) -> list[DetectionRule]:
    """Load detection rules from YAML files in the rules directory.

    Args:
        rules_dir: Path to rules directory. Uses default if None.
        engine_filter: Only load rules for this engine (e.g., 'REGEX').
        category_filter: Only load rules for this category.
        enabled_only: Only load enabled rules.

    Returns:
        List of DetectionRule objects.
    """
    path = Path(rules_dir) if rules_dir else _DEFAULT_RULES_DIR
    if not path.exists():
        return []

    rules: list[DetectionRule] = []
    for yml_file in sorted(path.rglob("*.yml")):
        try:
            rule = _load_rule_file(yml_file)
        except Exception:
            continue

        if rule is None:
            continue
        if enabled_only and not rule.enabled:
            continue
        if engine_filter and rule.engine.upper() != engine_filter.upper():
            continue
        if category_filter and rule.category != category_filter:
            continue

        rules.append(rule)

    return rules


def _load_rule_file(path: Path) -> DetectionRule | None:
    """Load a single rule YAML file."""
    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    if not isinstance(data, dict) or "id" not in data:
        return None

    return DetectionRule(
        id=data["id"],
        name=data.get("name", data["id"]),
        description=data.get("description", ""),
        severity=data.get("severity", "medium"),
        category=data.get("category", "unknown"),
        owasp_llm=data.get("owasp_llm", []),
        mitre_attack=data.get("mitre_attack", []),
        target=data.get("target", "ANY"),
        engine=data.get("engine", "REGEX"),
        pattern=data.get("pattern", ""),
        false_positive_notes=data.get("false_positive_notes"),
        remediation=data.get("remediation"),
        references=data.get("references", []),
        enabled=data.get("enabled", True),
    )
