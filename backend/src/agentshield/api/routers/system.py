"""System routes: health, overview, audit log, demo."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from agentshield import __version__
from agentshield.api.deps import AdminAccess, C
from agentshield.demo.scenario import run as run_demo
from agentshield.services.overview import overview

public = APIRouter(tags=["system"])
router = APIRouter(tags=["system"])


@public.get("/health")
def health(c: C) -> dict[str, Any]:
    return {"status": "ok", "version": __version__, "llm": c.llm.enabled}


@router.get("/overview")
def get_overview(c: C) -> dict[str, Any]:
    return overview(c)


@router.get("/events")
def events(
    c: C, limit: int = 100, type: str | None = None, session_id: str | None = None
) -> list[dict[str, Any]]:
    return c.store.events(
        types=[type] if type else None, session_id=session_id, limit=min(limit, 1000)
    )


@router.get("/events/verify")
def verify(c: C) -> dict[str, Any]:
    return c.store.verify_chain()


def demo_enabled(c: C) -> None:
    if not c.settings.demo_on:
        raise HTTPException(404, "Not found")


@router.post("/demo/run", dependencies=[AdminAccess, Depends(demo_enabled)])
def demo_run(c: C) -> dict[str, Any]:
    return run_demo(c)


@router.post("/demo/reset", status_code=204, dependencies=[AdminAccess, Depends(demo_enabled)])
def demo_reset(c: C) -> None:
    c.store.reset()
