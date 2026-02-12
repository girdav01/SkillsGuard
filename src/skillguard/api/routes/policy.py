"""Policy engine API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from skillguard.governance.policy_engine import PolicyEngine, PolicyResult, PolicyRule

router = APIRouter()

# Shared policy engine instance
_policy_engine = PolicyEngine()


class PolicyCreateRequest(BaseModel):
    """Request to create a new policy rule."""

    id: str
    name: str
    description: str = ""
    action: str = "block"
    conditions: dict = Field(default_factory=dict)
    enabled: bool = True


class PolicyYAMLRequest(BaseModel):
    """Request to load policies from YAML."""

    yaml_content: str


@router.get("/policies")
async def list_policies() -> dict:
    """List all configured policies."""
    policies = _policy_engine.list_policies()
    return {
        "total": len(policies),
        "policies": [p.model_dump() for p in policies],
    }


@router.post("/policies")
async def create_policy(request: PolicyCreateRequest) -> dict:
    """Create a new policy rule."""
    policy = PolicyRule(
        id=request.id,
        name=request.name,
        description=request.description,
        action=request.action,
        conditions=request.conditions,
        enabled=request.enabled,
    )
    _policy_engine.add_policy(policy)
    return {"status": "created", "policy_id": policy.id}


@router.delete("/policies/{policy_id}")
async def delete_policy(policy_id: str) -> dict:
    """Delete a policy rule by ID."""
    removed = _policy_engine.remove_policy(policy_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id} not found")
    return {"status": "deleted", "policy_id": policy_id}


@router.post("/policies/load-yaml")
async def load_policies_yaml(request: PolicyYAMLRequest) -> dict:
    """Load policies from YAML content."""
    count = _policy_engine.load_policies_from_yaml(request.yaml_content)
    return {"status": "loaded", "policies_loaded": count}


@router.post("/policies/evaluate/{scan_id}")
async def evaluate_policy(scan_id: str) -> dict:
    """Evaluate a completed scan result against all active policies."""
    from skillguard.api.routes.scan import _scan_results

    result = _scan_results.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    policy_result = await _policy_engine.evaluate(result)
    return policy_result.model_dump()
