"""Agent registry: identity, lifecycle state (for incident containment) and signed identity."""

from __future__ import annotations

import hashlib
import hmac

from pydantic import BaseModel, Field

from agentshield.core.models import now
from agentshield.storage.store import Store


class AgentRecord(BaseModel):
    id: str
    status: str = "active"  # active | quarantined
    revoked_tools: list[str] = Field(default_factory=list)
    blocked_sources: list[str] = Field(default_factory=list)
    first_seen: float = Field(default_factory=now)
    last_seen: float = Field(default_factory=now)
    sessions: int = 0


class AgentRegistry:
    COLLECTION = "agents"

    def __init__(self, store: Store, signing_secret: str) -> None:
        self.store = store
        self._secret = signing_secret.encode()

    def get(self, agent_id: str) -> AgentRecord:
        raw = self.store.get(self.COLLECTION, agent_id)
        return AgentRecord(**raw) if raw else AgentRecord(id=agent_id)

    def save(self, rec: AgentRecord) -> None:
        self.store.put(self.COLLECTION, rec.id, rec.model_dump())

    def touch(self, agent_id: str) -> AgentRecord:
        rec = self.get(agent_id)
        rec.last_seen = now()
        rec.sessions += 1
        self.save(rec)
        return rec

    def list(self) -> list[AgentRecord]:
        return [AgentRecord(**d) for d in self.store.list(self.COLLECTION)]

    # ---- containment actions (used by the incident copilot)
    def quarantine(self, agent_id: str) -> AgentRecord:
        rec = self.get(agent_id)
        rec.status = "quarantined"
        self.save(rec)
        return rec

    def release(self, agent_id: str) -> AgentRecord:
        rec = self.get(agent_id)
        rec.status = "active"
        rec.revoked_tools = []
        self.save(rec)
        return rec

    def revoke_tool(self, agent_id: str, tool: str) -> AgentRecord:
        rec = self.get(agent_id)
        if tool not in rec.revoked_tools:
            rec.revoked_tools.append(tool)
        self.save(rec)
        return rec

    def block_source(self, agent_id: str, source: str) -> AgentRecord:
        rec = self.get(agent_id)
        if source not in rec.blocked_sources:
            rec.blocked_sources.append(source)
        self.save(rec)
        return rec

    # ---- signed identity (anti-impersonation of agents / bots)
    def sign(self, agent_id: str) -> str:
        """Issue the credential an enrolled agent presents (demo/enrolment helper)."""
        return hmac.new(self._secret, agent_id.encode(), hashlib.sha256).hexdigest()

    def verify(self, agent_id: str, signature: str | None) -> bool:
        return bool(signature) and hmac.compare_digest(self.sign(agent_id), signature or "")
