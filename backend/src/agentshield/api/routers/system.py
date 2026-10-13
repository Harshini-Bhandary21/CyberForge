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


@router.post("/events/anchor", status_code=201, dependencies=[AdminAccess])
def anchor(c: C) -> dict[str, Any]:
    return c.anchors.checkpoint()


@router.get("/events/anchors")
def anchors(c: C) -> list[dict[str, Any]]:
    return c.anchors.list()


@router.get("/events/anchors/verify")
def verify_anchors(c: C) -> dict[str, Any]:
    return c.anchors.verify()


@router.get("/events/{event_id}/proof")
def event_proof(event_id: int, c: C) -> dict[str, Any]:
    cps = c.anchors.list(1)
    if not cps:
        raise HTTPException(404, "no checkpoint yet; create one first")
    proof = c.anchors.prove(event_id, cps[0])
    if not proof:
        raise HTTPException(404, "event is not covered by the latest checkpoint")
    return proof


def demo_enabled(c: C) -> None:
    if not c.settings.demo_on:
        raise HTTPException(404, "Not found")


@router.post("/demo/run", dependencies=[AdminAccess, Depends(demo_enabled)])
def demo_run(c: C) -> dict[str, Any]:
    return run_demo(c)


@router.post("/demo/reset", status_code=204, dependencies=[AdminAccess, Depends(demo_enabled)])
def demo_reset(c: C) -> None:
    c.store.reset()
