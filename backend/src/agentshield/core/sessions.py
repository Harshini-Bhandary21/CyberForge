"""Session lifecycle and context ingestion (the shield's input side)."""

from __future__ import annotations

from typing import Any

from agentshield.config import Settings
from agentshield.core.agents import AgentRegistry
from agentshield.core.detectors import noisy_or, scan_injection
from agentshield.core.dlp import redact_text
from agentshield.core.intent import derive_capabilities
from agentshield.core.models import ContextItem, ContextKind, Session, Signal, Trust
from agentshield.modules.anomaly.engine import AnomalyEngine
from agentshield.modules.incidents.service import IncidentService
from agentshield.modules.phishing.scanner import EmailInput, scan_email
from agentshield.storage.store import Store

HOSTILE_THRESHOLD = 0.55


class SessionService:
    COLLECTION = "sessions"

    def __init__(
        self,
        store: Store,
        settings: Settings,
        agents: AgentRegistry,
        incidents: IncidentService,
        anomaly: AnomalyEngine,
    ) -> None:
        self.store, self.settings, self.agents = store, settings, agents
        self.incidents, self.anomaly = incidents, anomaly

    def get(self, session_id: str) -> Session | None:
        raw = self.store.get(self.COLLECTION, session_id)
        return Session(**raw) if raw else None

    def save(self, session: Session) -> None:
        self.store.put(self.COLLECTION, session.id, session.model_dump(mode="json"))

    def list(self, limit: int = 100) -> list[Session]:
        return [Session(**d) for d in self.store.list(self.COLLECTION, limit)]

    def create(
        self,
        agent_id: str,
        user_goal: str,
        capabilities: list[str] | None = None,
        signature: str | None = None,
    ) -> Session:
        verified = self.agents.verify(agent_id, signature)
        session = Session(
            agent_id=agent_id,
            user_goal=user_goal,
            capabilities=capabilities
            if capabilities is not None
            else derive_capabilities(user_goal),
            identity_verified=verified,
        )
        self.agents.touch(agent_id)
        self.save(session)
        self.store.append_event(
            "session.created",
            {
                "goal": user_goal,
                "capabilities": session.capabilities,
                "identity_verified": verified,
            },
            session_id=session.id,
            agent_id=agent_id,
        )
        return session

    def add_context(
        self,
        session_id: str,
        *,
        source: str,
        content: str,
        kind: ContextKind = ContextKind.DOCUMENT,
        trust: Trust = Trust.UNTRUSTED,
        metadata: dict[str, Any] | None = None,
    ) -> ContextItem | None:
        session = self.get(session_id)
        if not session:
            return None
        metadata = metadata or {}
        item = ContextItem(
            kind=kind, source=source, content=content, trust=trust, metadata=metadata
        )

        if trust != Trust.TRUSTED:
            score, signals = scan_injection(content)
            if kind == ContextKind.EMAIL:
                phish = scan_email(
                    EmailInput(
                        sender=str(metadata.get("sender", "")),
                        reply_to=str(metadata.get("reply_to", "")),
                        subject=str(metadata.get("subject", "")),
                        body=content,
                        headers=metadata.get("headers", {}) or {},
                    )
                )
                seen = {s.name for s in signals}
                signals += [s for s in phish.signals if s.name not in seen]
                score = max(score, noisy_or([s.weight for s in signals]))
                item.metadata["phishing_verdict"] = phish.verdict
                item.metadata["phishing_score"] = phish.score
            item.risk_score, item.signals = score, signals
            blocked = source in self.agents.get(session.agent_id).blocked_sources
            if blocked:
                item.signals.append(
                    Signal(
                        name="blocked_source",
                        weight=1.0,
                        detail=f"Source '{source}' was blocked by incident response",
                    )
                )
                item.risk_score = 1.0
            if item.risk_score >= HOSTILE_THRESHOLD:
                item.trust = Trust.HOSTILE

        item.content = redact_text(item.content)  # scanned raw above; persisted without secrets
        session.context.append(item)
        self.save(session)
        self.store.append_event(
            "context.ingested",
            {
                "item_id": item.id,
                "kind": kind,
                "source": source,
                "trust": item.trust,
                "risk_score": item.risk_score,
                "signals": [s.name for s in item.signals],
            },
            session_id=session.id,
            agent_id=session.agent_id,
        )
        self.incidents.ingest_context(session.id, session.agent_id, session.user_goal, item)
        return item

    def close(self, session_id: str) -> Session | None:
        session = self.get(session_id)
        if not session or session.status == "closed":
            return session
        session.status = "closed"
        self.save(session)
        self.anomaly.learn_session(session.agent_id, session.call_count)
        self.store.append_event(
            "session.closed",
            {"calls": session.call_count},
            session_id=session.id,
            agent_id=session.agent_id,
        )
        return session
