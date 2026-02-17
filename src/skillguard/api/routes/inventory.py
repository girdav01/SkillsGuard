"""AI-BOM and audit log API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from skillguard.api.routes.scan import _sanitize_path
from skillguard.governance.audit_log import AuditLog

router = APIRouter()

# Shared audit log instance
_audit_log = AuditLog()


def get_audit_log() -> AuditLog:
    """Get the shared audit log instance (for use by other modules)."""
    return _audit_log


class SBOMRequest(BaseModel):
    """Request to generate a Skill SBOM."""

    skill_path: str
    include_scan_id: str | None = None


@router.post("/sbom")
async def generate_sbom(request: SBOMRequest) -> dict:
    """Generate a CycloneDX SBOM for a skill directory.

    Inventories all files, dependencies, metadata, licenses,
    external references, and declared tool capabilities.
    Optionally embeds findings from a previous scan.
    """
    from skillguard.core.skill_sbom import generate_skill_sbom

    # Validate and sanitize path to prevent traversal
    safe_path = _sanitize_path(request.skill_path)

    scan_result = None
    if request.include_scan_id:
        from skillguard.api.routes.scan import _scan_results

        scan_result = _scan_results.get(request.include_scan_id)

    try:
        return generate_skill_sbom(safe_path, include_scan_result=scan_result)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="skill path not found")


@router.get("/ai-bom/{scan_id}")
async def get_ai_bom(scan_id: str) -> dict:
    """Generate a CycloneDX AI-BOM for a completed scan."""
    from skillguard.api.routes.scan import _scan_results
    from skillguard.core.ai_bom import generate_ai_bom

    result = _scan_results.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    return generate_ai_bom(result)


@router.get("/audit")
async def query_audit_log(
    action: str | None = None,
    actor: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Query the audit log with optional filters."""
    entries = await _audit_log.query(
        action=action,
        actor=actor,
        resource_type=resource_type,
        resource_id=resource_id,
        limit=limit,
        offset=offset,
    )
    total = await _audit_log.count()
    return {
        "total": total,
        "returned": len(entries),
        "entries": [e.model_dump() for e in entries],
    }


@router.get("/audit/verify")
async def verify_audit_integrity() -> dict:
    """Verify the integrity of the audit log chain."""
    is_valid, last_valid = await _audit_log.verify_integrity()
    total = await _audit_log.count()
    return {
        "is_valid": is_valid,
        "total_entries": total,
        "last_valid_index": last_valid,
    }


@router.get("/audit/export")
async def export_audit_log() -> dict:
    """Export the full audit log."""
    import json

    data = await _audit_log.export_json()
    entries = json.loads(data) if data.strip() else []
    return {"entries": entries, "total": len(entries)}
