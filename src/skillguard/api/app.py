"""FastAPI application for SkillGuard REST API."""

from __future__ import annotations

from fastapi import FastAPI

from skillguard.api.routes.scan import router as scan_router
from skillguard.api.routes.skill import router as skill_router
from skillguard.api.routes.rules import router as rules_router
from skillguard.api.routes.monitor import router as monitor_router
from skillguard.api.routes.policy import router as policy_router
from skillguard.api.routes.community import router as community_router
from skillguard.api.routes.inventory import router as inventory_router


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="SkillGuard API",
        description=(
            "Multi-engine security scanner for AI Agent Skills, "
            "MCP Servers, and agentic tool definitions."
        ),
        version="0.3.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.include_router(scan_router, prefix="/api/v1", tags=["Scanning"])
    app.include_router(skill_router, prefix="/api/v1", tags=["Skills"])
    app.include_router(rules_router, prefix="/api/v1", tags=["Rules"])
    app.include_router(monitor_router, prefix="/api/v1", tags=["Monitoring"])
    app.include_router(policy_router, prefix="/api/v1", tags=["Policy"])
    app.include_router(community_router, prefix="/api/v1", tags=["Community"])
    app.include_router(inventory_router, prefix="/api/v1", tags=["Inventory"])

    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "version": "0.3.0"}

    return app
