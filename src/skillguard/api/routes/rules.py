"""Detection rules management routes."""

from __future__ import annotations

from fastapi import APIRouter

from skillguard.core.rules_loader import load_rules

router = APIRouter()


@router.get("/rules")
async def list_rules(
    category: str | None = None,
    engine: str | None = None,
) -> dict:
    """List all detection rules."""
    rules = load_rules(
        category_filter=category,
        engine_filter=engine,
    )
    return {
        "total": len(rules),
        "rules": [
            {
                "id": r.id,
                "name": r.name,
                "severity": r.severity.value,
                "category": r.category,
                "engine": r.engine,
                "target": r.target,
                "enabled": r.enabled,
            }
            for r in rules
        ],
    }
