"""Scan API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from skillguard.api.models import ScanSubmitRequest, ScanSubmitResponse, ScanStatusResponse
from skillguard.core.models import ScanRequest, ScanResult
from skillguard.core.scanner import ScanOrchestrator
from skillguard.engines.prompt_injection.regex_scanner import RegexScanner
from skillguard.engines.prompt_injection.yara_scanner import YaraScanner
from skillguard.engines.prompt_injection.ml_classifier import MLClassifier
from skillguard.engines.prompt_injection.vector_search import VectorSearchEngine
from skillguard.engines.sast.secret_detector import SecretDetector
from skillguard.engines.mcp.tool_poisoning import ToolPoisoningDetector
from skillguard.engines.mcp.tool_shadowing import ToolShadowingDetector
from skillguard.engines.mcp.config_scanner import MCPConfigScanner
from skillguard.engines.sandbox.behavior_analyzer import BehaviorAnalyzer
from skillguard.engines.structural.schema_validator import SchemaValidator
from skillguard.engines.structural.permission_analyzer import PermissionAnalyzer
from skillguard.engines.structural.obfuscation_detector import ObfuscationDetector
from skillguard.intelligence.threat_db import ThreatIntelDB

router = APIRouter()

# In-memory store (would be database in production)
_scan_results: dict[str, ScanResult] = {}


def _get_orchestrator() -> ScanOrchestrator:
    """Create a scan orchestrator with all available engines."""
    engines = [
        RegexScanner(),
        YaraScanner(),
        SecretDetector(),
        MLClassifier(),
        VectorSearchEngine(),
        ToolPoisoningDetector(),
        ToolShadowingDetector(),
        MCPConfigScanner(),
        BehaviorAnalyzer(),
        SchemaValidator(),
        PermissionAnalyzer(),
        ObfuscationDetector(),
    ]
    threat_intel = ThreatIntelDB()
    return ScanOrchestrator(engines=engines, threat_intel=threat_intel)


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
    elif format == "html":
        from fastapi.responses import HTMLResponse
        from skillguard.reporting.html_report import generate_html_report

        return HTMLResponse(content=generate_html_report(result))
    else:
        return result.model_dump()
