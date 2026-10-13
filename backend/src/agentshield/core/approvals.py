"""Human-in-the-loop approvals for actions the policy engine will not auto-allow."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, Field

from agentshield.core.models import Risk, new_id, now
from agentshield.storage.store import Store


def args_hash(tool: str, args: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps([tool, args], sort_keys=True, default=str).encode()
    ).hexdigest()[:16]


class Approval(BaseModel):
    id: str = Field(default_factory=lambda: new_id("apr"))
    session_id: str
    agent_id: str
    tool: str
    args: dict[str, Any]
    args_hash: str
    risk: Risk
    reasons: list[str]
    status: Literal["pending", "approved", "denied"] = "pending"
    reviewer: str | None = None
    note: str | None = None
    created_at: float = Field(default_factory=now)
    resolved_at: float | None = None


class ApprovalService:
    COLLECTION = "approvals"

    def __init__(self, store: Store) -> None:
        self.store = store

    def create(self, **kw: Any) -> Approval:
        # The hash binds the approval to the *original* arguments; stored args may be redacted.
        kw.setdefault("args_hash", args_hash(kw["tool"], kw["args"]))
        apr = Approval(**kw)
        self.store.put(self.COLLECTION, apr.id, apr.model_dump(mode="json"))
        self.store.append_event(
            "approval.requested",
            {"approval_id": apr.id, "tool": apr.tool, "risk": apr.risk, "reasons": apr.reasons},
            session_id=apr.session_id,
            agent_id=apr.agent_id,
        )
        return apr

    def get(self, approval_id: str) -> Approval | None:
        raw = self.store.get(self.COLLECTION, approval_id)
        return Approval(**raw) if raw else None

    def list(self, status: str | None = None) -> list[Approval]:
        items = [Approval(**d) for d in self.store.list(self.COLLECTION)]
        return [a for a in items if status is None or a.status == status]

    def resolve(
        self, approval_id: str, approve: bool, reviewer: str, note: str | None
    ) -> Approval | None:
        apr = self.get(approval_id)
        if not apr or apr.status != "pending":
            return apr
        apr.status = "approved" if approve else "denied"
        apr.reviewer, apr.note, apr.resolved_at = reviewer, note, now()
        self.store.put(self.COLLECTION, apr.id, apr.model_dump(mode="json"))
        self.store.append_event(
            "approval.resolved",
            {"approval_id": apr.id, "status": apr.status, "reviewer": reviewer, "tool": apr.tool},
            session_id=apr.session_id,
            agent_id=apr.agent_id,
        )
        return apr
