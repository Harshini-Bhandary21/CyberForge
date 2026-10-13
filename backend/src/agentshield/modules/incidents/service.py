"""Incident Copilot: correlates raw guard events into one explained incident with a response plan."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from agentshield.core.agents import AgentRegistry
from agentshield.core.models import (
    RISK_ORDER,
    ContextItem,
    GuardDecision,
    Risk,
    Trust,
    Verdict,
    new_id,
    now,
)
from agentshield.llm.client import LLM
from agentshield.storage.store import Store


class TimelineEntry(BaseModel):
    ts: float = Field(default_factory=now)
    kind: str  # context | decision | anomaly | action
    title: str
    detail: str = ""
    severity: Risk = Risk.LOW
    ref: str | None = None


class PlannedAction(BaseModel):
    id: str = Field(default_factory=lambda: new_id("act"))
    action: Literal[
        "quarantine_agent", "revoke_tool", "block_source", "rotate_credentials", "notify_owner"
    ]
    target: str
    rationale: str
    reversible: bool = True
    mode: Literal["executed", "simulated"] = "executed"
    status: Literal["proposed", "applied"] = "proposed"
    applied_at: float | None = None


class Incident(BaseModel):
    id: str
    session_id: str
    agent_id: str
    goal: str = ""
    title: str = "Suspicious agent activity"
    severity: Risk = Risk.LOW
    score: int = 0
    status: Literal["open", "contained", "resolved"] = "open"
    narrative: str = ""
    timeline: list[TimelineEntry] = Field(default_factory=list)
    actions: list[PlannedAction] = Field(default_factory=list)
    blocked: int = 0
    approvals: int = 0
    hostile_sources: list[str] = Field(default_factory=list)
    blocked_tools: list[str] = Field(default_factory=list)
    secrets_seen: bool = False
    max_anomaly: float = 0.0
    created_at: float = Field(default_factory=now)
    updated_at: float = Field(default_factory=now)


class IncidentService:
    COLLECTION = "incidents"

    def __init__(self, store: Store, agents: AgentRegistry, llm: LLM) -> None:
        self.store, self.agents, self.llm = store, agents, llm

    # ------------------------------------------------------------------ queries
    def get(self, incident_id: str) -> Incident | None:
        raw = self.store.get(self.COLLECTION, incident_id)
        return Incident(**raw) if raw else None

    def list(self, status: str | None = None) -> list[Incident]:
        items = [Incident(**d) for d in self.store.list(self.COLLECTION)]
        return [i for i in items if status is None or i.status == status]

    def _for_session(self, session_id: str, agent_id: str, goal: str) -> Incident:
        inc = self.get(f"inc_{session_id}")
        if inc:
            return inc
        inc = Incident(id=f"inc_{session_id}", session_id=session_id, agent_id=agent_id, goal=goal)
        self.store.append_event(
            "incident.opened", {"incident_id": inc.id}, session_id=session_id, agent_id=agent_id
        )
        return inc

    # ------------------------------------------------------------------ ingestion
    def ingest_context(
        self, session_id: str, agent_id: str, goal: str, item: ContextItem
    ) -> Incident | None:
        if item.trust != Trust.HOSTILE:
            return None
        inc = self._for_session(session_id, agent_id, goal)
        if item.source not in inc.hostile_sources:
            inc.hostile_sources.append(item.source)
        top = ", ".join(s.name for s in sorted(item.signals, key=lambda s: -s.weight)[:3])
        inc.timeline.append(
            TimelineEntry(
                kind="context",
                title=f"Hostile content entered the agent's context: {item.source}",
                detail=f"Risk {item.risk_score:.2f}. Signals: {top}",
                severity=Risk.MEDIUM,
                ref=item.id,
            )
        )
        return self._finish(inc)

    def ingest_decision(self, d: GuardDecision, goal: str) -> Incident | None:
        notable_anomaly = any(a.score >= 0.6 for a in d.anomalies)
        serious = d.verdict == Verdict.BLOCK or (
            d.verdict == Verdict.REQUIRE_APPROVAL and RISK_ORDER[d.risk] >= 3
        )
        if not (serious or notable_anomaly):
            return None
        inc = self._for_session(d.session_id, d.agent_id, goal)
        if d.verdict == Verdict.BLOCK:
            inc.blocked += 1
            if d.tool not in inc.blocked_tools:
                inc.blocked_tools.append(d.tool)
        elif d.verdict == Verdict.REQUIRE_APPROVAL:
            inc.approvals += 1
        for s in d.taint.control_sources:
            if s.trust == Trust.HOSTILE and s.source not in inc.hostile_sources:
                inc.hostile_sources.append(s.source)
        if any(f.rule == "R-DLP-001" for f in d.findings):
            inc.secrets_seen = True
        label = {"block": "Blocked", "require_approval": "Held for approval", "allow": "Allowed"}[
            d.verdict.value
        ]
        sev = max((f.severity for f in d.findings), key=lambda r: RISK_ORDER[r], default=d.risk)
        inc.timeline.append(
            TimelineEntry(
                kind="decision",
                title=f"{label}: {d.tool}",
                severity=sev,
                ref=d.id,
                detail=" • ".join(d.reasons) or "Flagged by policy",
            )
        )
        for a in d.anomalies:
            inc.max_anomaly = max(inc.max_anomaly, a.score)
            inc.timeline.append(
                TimelineEntry(
                    kind="anomaly",
                    title=f"Anomaly: {a.kind}",
                    detail=a.detail,
                    severity=Risk.MEDIUM,
                )
            )
        d.incident_id = inc.id
        return self._finish(inc)

    # ------------------------------------------------------------------ scoring & narrative
    def _finish(self, inc: Incident) -> Incident:
        inc.score = self._score(inc)
        inc.severity = (
            Risk.CRITICAL
            if inc.score >= 75
            else Risk.HIGH
            if inc.score >= 50
            else Risk.MEDIUM
            if inc.score >= 25
            else Risk.LOW
        )
        inc.title = self._title(inc)
        inc.narrative = self._narrative(inc)
        self._plan(inc)
        inc.updated_at = now()
        self.store.put(self.COLLECTION, inc.id, inc.model_dump(mode="json"))
        return inc

    @staticmethod
    def _score(inc: Incident) -> int:
        s = 0.0
        if inc.blocked:
            crit = any(e.kind == "decision" and e.severity == Risk.CRITICAL for e in inc.timeline)
            s += 30 if crit else 15
            s += 5 * min(inc.blocked - 1, 3)
        if inc.hostile_sources:
            s += 15
        s += 10 * min(inc.approvals, 2)
        s += 25 * inc.max_anomaly
        if len(inc.blocked_tools) > 1:
            s += 10
        if inc.secrets_seen:
            s += 15
        return int(min(100, s))

    @staticmethod
    def _title(inc: Incident) -> str:
        if inc.hostile_sources and inc.blocked:
            return "Prompt-injection attempt blocked"
        if inc.secrets_seen:
            return "Credential exfiltration attempt blocked"
        if inc.blocked:
            return "Unauthorised agent action blocked"
        if inc.max_anomaly:
            return "Anomalous agent behaviour"
        if inc.hostile_sources:
            return "Hostile content reached an agent"
        return "Suspicious agent activity"

    def _narrative(self, inc: Incident) -> str:
        parts = [f"Agent “{inc.agent_id}” was working on: “{inc.goal}”."]
        if inc.hostile_sources:
            parts.append(f"Hostile content arrived via {', '.join(inc.hostile_sources)}.")
        if inc.blocked:
            parts.append(
                f"{inc.blocked} action(s) were blocked ({', '.join(inc.blocked_tools)}) before any side effect occurred."
            )
        if inc.approvals:
            parts.append(f"{inc.approvals} action(s) were held for human approval.")
        if inc.max_anomaly:
            parts.append("Behaviour also deviated from this agent's learned baseline.")
        if inc.secrets_seen:
            parts.append(
                "An outbound call carried credentials; treat those secrets as exposed-in-intent and rotate them."
            )
        base = " ".join(parts)
        if not inc.blocked:
            return base
        polished = self.llm.complete(
            "You write concise incident summaries for a SOC analyst. Rewrite the facts in 2-3 plain sentences. "
            "Do not add facts, speculation or advice.",
            base,
            max_tokens=250,
        )
        return polished or base

    def _plan(self, inc: Incident) -> None:
        have = {(a.action, a.target) for a in inc.actions}

        def add(
            action: str, target: str, why: str, *, reversible: bool = True, mode: str = "executed"
        ) -> None:
            if (action, target) not in have:
                inc.actions.append(
                    PlannedAction(
                        action=action,
                        target=target,
                        rationale=why,
                        reversible=reversible,
                        mode=mode,
                    )
                )  # type: ignore[arg-type]

        if inc.blocked and (inc.hostile_sources or RISK_ORDER[inc.severity] >= 3):
            add(
                "quarantine_agent",
                inc.agent_id,
                "Stop the agent from acting until an analyst reviews the session.",
            )
        for src in inc.hostile_sources:
            add(
                "block_source",
                src,
                "Treat everything from this source as hostile in future sessions.",
            )
        for tool in inc.blocked_tools:
            if tool in {
                "run_shell",
                "transfer_funds",
                "change_permissions",
                "forward_email",
                "send_email",
            }:
                add(
                    "revoke_tool",
                    tool,
                    f"Remove '{tool}' from this agent until the root cause is fixed.",
                )
        if inc.secrets_seen:
            add(
                "rotate_credentials",
                inc.agent_id,
                "Credentials appeared in an outbound payload.",
                reversible=False,
                mode="simulated",
            )
        add(
            "notify_owner",
            inc.agent_id,
            "Tell the agent's owner what was attempted and what was stopped.",
            mode="simulated",
        )

    # ------------------------------------------------------------------ actions
    def apply_action(
        self, incident_id: str, action_id: str, actor: str = "analyst"
    ) -> Incident | None:
        inc = self.get(incident_id)
        if not inc:
            return None
        act = next((a for a in inc.actions if a.id == action_id), None)
        if not act or act.status == "applied":
            return inc
        if act.mode == "executed":
            if act.action == "quarantine_agent":
                self.agents.quarantine(act.target)
                inc.status = "contained"
            elif act.action == "revoke_tool":
                self.agents.revoke_tool(inc.agent_id, act.target)
            elif act.action == "block_source":
                self.agents.block_source(inc.agent_id, act.target)
        act.status, act.applied_at = "applied", now()
        inc.timeline.append(
            TimelineEntry(
                kind="action",
                title=f"{actor} applied: {act.action.replace('_', ' ')} → {act.target}",
                detail="simulated (integration stub)" if act.mode == "simulated" else "executed",
                severity=Risk.LOW,
            )
        )
        inc.updated_at = now()
        self.store.put(self.COLLECTION, inc.id, inc.model_dump(mode="json"))
        self.store.append_event(
            "incident.action",
            {
                "incident_id": inc.id,
                "action": act.action,
                "target": act.target,
                "mode": act.mode,
                "actor": actor,
            },
            session_id=inc.session_id,
            agent_id=inc.agent_id,
        )
        return inc

    def resolve(self, incident_id: str) -> Incident | None:
        inc = self.get(incident_id)
        if not inc:
            return None
        inc.status = "resolved"
        inc.updated_at = now()
        self.store.put(self.COLLECTION, inc.id, inc.model_dump(mode="json"))
        self.store.append_event(
            "incident.resolved",
            {"incident_id": inc.id},
            session_id=inc.session_id,
            agent_id=inc.agent_id,
        )
        return inc
