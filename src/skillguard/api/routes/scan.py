"""Scan API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from skillguard.api.models import ScanSubmitRequest, ScanSubmitResponse, ScanStatusResponse
from skillguard.core.models import ScanRequest, ScanResult
from skillguard.core.scanner import ScanOrchestrator
from skillguard.engines.prompt_injection.regex_scanner import RegexScanner
from skillguard.engines.prompt_injection.yara_scanner import YaraScanner
from skillguard.engines.sast.secret_detector import SecretDetector

router = APIRouter()

# In-memory store for MVP (would be database in production)
_scan_results: dict[str, ScanResult] = {}


def _get_orchestrator() -> ScanOrchestrator:
    """Create a scan orchestrator with default engines."""
    engines = [
        RegexScanner(),
        YaraScanner(),
        SecretDetector(),
    ]
    return ScanOrchestrator(engines=engines)


@router.post("/scan", response_model=ScanSubmitResponse, status_code=202)
async def submit_scan(request: ScanSubmitRequest) -> ScanSubmitResponse:
    """Submit a skill for scanning."""
    if not request.skill_path and not request.git_url:
        raise HTTPException(status_code=400, detail="Provide skill_path or git_url")

    scan_request = ScanRequest(
        skill_path=request.skill_path,
        git_url=request.git_url,
        scan_type=request.scan_type,
        platform=request.platform,
    )

    orchestrator = _get_orchestrator()

    try:
        result = await orchestrator.scan(scan_request)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    _scan_results[result.scan_id] = result

    return ScanSubmitResponse(
        scan_id=result.scan_id,
        status="completed",
    )


@router.get("/scan/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_result(scan_id: str) -> ScanStatusResponse:
    """Get scan results by ID."""
    result = _scan_results.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    return ScanStatusResponse(
        scan_id=scan_id,
        status="completed",
        result=result,
    )


@router.get("/scan/{scan_id}/report")
async def get_scan_report(scan_id: str, format: str = "json") -> dict:
    """Download scan report in specified format."""
    result = _scan_results.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    if format == "sarif":
        from skillguard.reporting.sarif_report import generate_sarif_report
        import json

        return json.loads(generate_sarif_report(result))
    else:
        return result.model_dump()
