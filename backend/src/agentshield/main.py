"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agentshield import __version__
from agentshield.api.deps import AdminAccess, AgentAccess, AnalystAccess  # noqa: F401
from agentshield.api.middleware import (
    BodyLimitMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)
from agentshield.api.routers import guard, modules, system
from agentshield.config import Settings, get_settings
from agentshield.container import Container, build_container

API_PREFIX = "/api/v1"


def create_app(settings: Settings | None = None, container: Container | None = None) -> FastAPI:
    settings = settings or get_settings()
    if settings.is_production:
        problems = settings.production_problems()
        if problems:
            raise RuntimeError("Refusing to start in production: " + "; ".join(problems))

    app = FastAPI(
        title="AgentShield API",
        version=__version__,
        description="Runtime security for AI agents: injection firewall, anomaly detection, SOC copilot, fraud guard, compliance automation.",
        docs_url="/docs" if settings.docs_on else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_on else None,
    )
    app.state.container = container or build_container(settings)

    # Order matters: the last added runs first (outermost). Limits apply before any work is done.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-API-Key"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(RateLimitMiddleware, per_minute=settings.rate_limit_per_min)

    app.include_router(system.public, prefix=API_PREFIX)
    app.include_router(guard.agent_router, prefix=API_PREFIX, dependencies=[AgentAccess])
    for r in (system.router, guard.router, modules.router):
        app.include_router(r, prefix=API_PREFIX, dependencies=[AnalystAccess])
    return app


app = create_app()
