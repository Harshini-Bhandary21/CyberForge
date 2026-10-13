"""GuardService: the single choke point every agent tool call passes through."""

from __future__ import annotations

import json
import time

from agentshield.config import Settings
from agentshield.core import dlp, taint
from agentshield.core.agents import AgentRegistry
from agentshield.core.approvals import ApprovalService, args_hash
from agentshield.core.dlp import redact_value
from agentshield.core.models import (
    Finding,
    GuardDecision,
    Risk,
    ToolCallRequest,
    Verdict,
)
from agentshield.core.policy import PolicyConfig, PolicyInput, evaluate
from agentshield.core.sessions import SessionService
from agentshield.core.tools import get_spec
from agentshield.core.verifier import IntentVerifier
from agentshield.modules.anomaly.engine import AnomalyEngine
from agentshield.modules.fraud.engine import FraudEngine
from agentshield.modules.incidents.service import IncidentService
from agentshield.storage.store import Store


class GuardService:
    COLLECTION = "decisions"

    def __init__(
        self,
        store: Store,
        settings: Settings,
        sessions: SessionService,
        agents: AgentRegistry,
        approvals: ApprovalService,
        verifier: IntentVerifier,
        anomaly: AnomalyEngine,
        fraud: FraudEngine,
        incidents: IncidentService,
        config: PolicyConfig | None = None,
    ) -> None:
        self.store, self.settings = store, settings
        self.sessions, self.agents, self.approvals = sessions, agents, approvals
        self.verifier, self.anomaly, self.fraud, self.incidents = (
            verifier,
            anomaly,
            fraud,
            incidents,
        )
        self.config = config or PolicyConfig()

    def evaluate(self, session_id: str, req: ToolCallRequest) -> GuardDecision | None:
        t0 = time.perf_counter()
        session = self.sessions.get(session_id)
        if not session:
            return None
        spec = get_spec(req.tool)
        agent = self.agents.get(session.agent_id)

        trace = taint.trace(spec, req.args, session.user_goal, session.context, req.influenced_by)
        hits = dlp.scan_args(req.args) if spec and spec.egress else []
        verdict_intent = (
            self.verifier.verify(session.user_goal, req.tool, req.args, spec)
            if self.config.intent
            else None
        )

        fraud_verdict, fraud_reasons = None, []
        if spec and spec.category == "financial" and self.config.fraud:
            amount = _to_float(req.args.get("amount"))
            payee = str(req.args.get("payee") or req.args.get("account") or "")
            fa = self.fraud.assess(
                session.agent_id,
                amount=amount,
                payee=payee,
                taint=trace,
                hour=self.settings.fixed_hour,
            )
            fraud_verdict, fraud_reasons = fa.verdict, fa.reasons
            self.store.append_event(
                "fraud.assessed",
                {
                    "score": fa.score,
                    "verdict": fa.verdict,
                    "amount": amount,
                    "payee": payee,
                    "signals": [s.name for s in fa.signals],
                },
                session_id=session.id,
                agent_id=session.agent_id,
            )

        verdict, risk, findings = evaluate(
            PolicyInput(
                tool=req.tool,
                spec=spec,
                capabilities=session.capabilities,
                taint=trace,
                dlp=hits,
                verifier=verdict_intent,
                fraud_verdict=fraud_verdict,
                fraud_reasons=fraud_reasons,
                agent_quarantined=agent.status == "quarantined",
                revoked=req.tool in agent.revoked_tools,
                outbound_text=json.dumps(req.args, default=str) if spec and spec.egress else "",
                identity_unverified_and_required=self.settings.require_agent_identity
                and not session.identity_verified,
            ),
            self.config,
        )

        # A human may release an action held for approval, never one that was blocked outright.
        approval_id = None
        if verdict == Verdict.REQUIRE_APPROVAL:
            prior = self.approvals.get(req.approval_id) if req.approval_id else None
            if (
                prior
                and prior.status == "approved"
                and prior.args_hash == args_hash(req.tool, req.args)
                and prior.session_id == session.id
            ):
                verdict = Verdict.ALLOW
                findings.append(
                    Finding(
                        rule="R-APPROVAL-001",
                        severity=Risk.LOW,
                        verdict=Verdict.ALLOW,
                        message=f"Released by human approval {prior.id} ({prior.reviewer}).",
                    )
                )
            else:
                reasons = [f.message for f in findings if f.verdict != Verdict.ALLOW]
                approval_id = self.approvals.create(
                    session_id=session.id,
                    agent_id=session.agent_id,
                    tool=req.tool,
                    args=redact_value(req.args),
                    args_hash=args_hash(req.tool, req.args),
                    risk=risk,
                    reasons=reasons,
                ).id

        session.call_count += 1
        if verdict == Verdict.BLOCK:
            session.blocked_count += 1

        anomalies = self.anomaly.observe(session, spec, req, verdict, hour=self.settings.fixed_hour)
        if verdict == Verdict.ALLOW:
            self.anomaly.learn_call(session.agent_id, spec, req)
            if spec and spec.category == "financial":
                self.fraud.learn(
                    session.agent_id,
                    _to_float(req.args.get("amount")),
                    str(req.args.get("payee") or ""),
                )

        decision = GuardDecision(
            session_id=session.id,
            agent_id=session.agent_id,
            tool=req.tool,
            args=redact_value(req.args),  # never persist secrets, even from blocked calls
            verdict=verdict,
            risk=risk,
            findings=findings,
            taint=trace,
            verifier=verdict_intent,
            anomalies=anomalies,
            approval_id=approval_id,
        )
        for a in anomalies:
            self.store.append_event(
                "anomaly.detected", a.model_dump(), session_id=session.id, agent_id=session.agent_id
            )
        self.incidents.ingest_decision(decision, session.user_goal)
        decision.latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        self.sessions.save(session)
        self.store.put(self.COLLECTION, decision.id, decision.model_dump(mode="json"))
        self.store.append_event(
            "guard.decision",
            {
                "decision_id": decision.id,
                "tool": req.tool,
                "verdict": verdict,
                "risk": risk,
                "rules": [f.rule for f in findings if f.verdict != Verdict.ALLOW],
                "tainted": trace.tainted,
                "latency_ms": decision.latency_ms,
            },
            session_id=session.id,
            agent_id=session.agent_id,
        )
        return decision

    def recent(self, limit: int = 100) -> list[GuardDecision]:
        return [GuardDecision(**d) for d in self.store.list(self.COLLECTION, limit)]


def _to_float(v: object) -> float:
    try:
        return float(str(v).replace(",", "").replace("₹", ""))
    except (TypeError, ValueError):
        return 0.0
