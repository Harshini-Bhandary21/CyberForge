"""Injection Firewall API: sessions, context ingestion, tool-call guarding, approvals."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from agentshield.api.deps import Analyst, C
from agentshield.core.approvals import Approval, DuplicateReviewer
from agentshield.core.models import (
    ContextItem,
    ContextKind,
    GuardDecision,
    Session,
    ToolCallRequest,
    Trust,
)
from agentshield.core.tools import all_specs

# Endpoints an AI agent integration may call (role: agent, analyst, admin).
agent_router = APIRouter(tags=["guard"])
# Operator endpoints (role: analyst, admin).
router = APIRouter(tags=["guard"])


class SessionIn(BaseModel):
    agent_id: str = Field(
        min_length=1, max_length=128, pattern=r"^[\w.@:-]+$", examples=["email-assistant"]
    )
    user_goal: str = Field(min_length=1, max_length=2_000, examples=["Summarize my unread emails."])
    capabilities: list[str] | None = Field(
        default=None, description="Override; defaults to least-privilege derived from the goal."
    )
    signature: str | None = Field(default=None, description="Agent identity credential (HMAC).")


class ContextIn(BaseModel):
    source: str
    content: str = Field(max_length=200_000)
    kind: ContextKind = ContextKind.DOCUMENT
    trust: Trust = Trust.UNTRUSTED
    metadata: dict[str, Any] = Field(default_factory=dict)


class ResolveIn(BaseModel):
    approve: bool
    reviewer: str = "analyst"
    note: str | None = None


@agent_router.get("/tools")
def tools() -> list[dict[str, Any]]:
    return [s.model_dump() for s in all_specs()]


@agent_router.post("/sessions", response_model=Session, status_code=201)
def create_session(body: SessionIn, c: C) -> Session:
    return c.sessions.create(body.agent_id, body.user_goal, body.capabilities, body.signature)


@router.get("/sessions", response_model=list[Session])
def list_sessions(c: C, limit: int = 50) -> list[Session]:
    return c.sessions.list(limit)


@router.get("/sessions/{session_id}", response_model=Session)
def get_session(session_id: str, c: C) -> Session:
    s = c.sessions.get(session_id)
    if not s:
        raise HTTPException(404, "session not found")
    return s


@agent_router.post("/sessions/{session_id}/context", response_model=ContextItem, status_code=201)
def add_context(session_id: str, body: ContextIn, c: C) -> ContextItem:
    item = c.sessions.add_context(
        session_id,
        source=body.source,
        content=body.content,
        kind=body.kind,
        trust=body.trust,
        metadata=body.metadata,
    )
    if not item:
        raise HTTPException(404, "session not found")
    return item


@agent_router.post("/sessions/{session_id}/guard", response_model=GuardDecision)
def guard_call(session_id: str, body: ToolCallRequest, c: C) -> GuardDecision:
    d = c.guard.evaluate(session_id, body)
    if not d:
        raise HTTPException(404, "session not found")
    return d


@agent_router.post("/sessions/{session_id}/close", response_model=Session)
def close_session(session_id: str, c: C) -> Session:
    s = c.sessions.close(session_id)
    if not s:
        raise HTTPException(404, "session not found")
    return s


@router.get("/decisions", response_model=list[GuardDecision])
def decisions(c: C, limit: int = 100, session_id: str | None = None) -> list[GuardDecision]:
    items = c.guard.recent(500)
    if session_id:
        items = [d for d in items if d.session_id == session_id]
    return items[:limit]


@router.get("/approvals", response_model=list[Approval])
def approvals(c: C, status: str | None = None) -> list[Approval]:
    return c.approvals.list(status)


@router.post("/approvals/{approval_id}/resolve", response_model=Approval)
def resolve_approval(approval_id: str, body: ResolveIn, c: C, who: Analyst) -> Approval:
    # Identity comes from the authenticated key; the supplied name is only a display label.
    reviewer = f"{body.reviewer} ({who.id})" if c.settings.auth_configured else body.reviewer
    try:
        apr = c.approvals.resolve(
            approval_id, approve=body.approve, reviewer=reviewer, note=body.note, reviewer_id=who.id
        )
    except DuplicateReviewer as e:
        raise HTTPException(409, str(e)) from e
    if not apr:
        raise HTTPException(404, "approval not found")
    return apr
