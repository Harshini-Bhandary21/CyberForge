"""Cross-module roll-up: the organisation's AI Risk Score and headline metrics."""

from __future__ import annotations

from typing import Any

from agentshield.container import Container
from agentshield.core.models import RISK_ORDER, Risk
from agentshield.modules.compliance.autopilot import generate


def overview(c: Container) -> dict[str, Any]:
    store = c.store
    decisions = [e["payload"] for e in store.events(types=["guard.decision"], limit=5000)]
    by_verdict = {"allow": 0, "require_approval": 0, "block": 0}
    for d in decisions:
        by_verdict[d["verdict"]] = by_verdict.get(d["verdict"], 0) + 1
    incidents = c.incidents.list()
    open_inc = [i for i in incidents if i.status == "open"]
    pending = c.approvals.list("pending")
    anomalies = store.count_events("anomaly.detected")
    runs = store.list("redteam_runs", 1)
    redteam = runs[0] if runs else None
    comp = generate(store)
    hostile = sum(
        1
        for e in store.events(types=["context.ingested"], limit=5000)
        if e["payload"].get("trust") == "hostile"
    )

    # AI Risk Score (0 = best, 100 = worst). Transparent, additive, capped per component.
    parts = {
        "open_incidents": min(35.0, sum(i.score for i in open_inc) * 0.35),
        "pending_approvals": min(10.0, len(pending) * 3.0),
        "anomaly_rate": min(15.0, (anomalies / max(len(decisions), 1)) * 60),
        "red_team_exposure": (100 * redteam["summary"]["asr_protected"]) * 0.25
        if redteam
        else 12.0,
        "compliance_gaps": (100 - comp.coverage_pct) * 0.15,
    }
    risk = int(min(100, round(sum(parts.values()))))
    label = (
        "critical" if risk >= 70 else "high" if risk >= 45 else "moderate" if risk >= 20 else "low"
    )

    top: Risk = max((i.severity for i in open_inc), key=lambda r: RISK_ORDER[r], default=Risk.LOW)
    return {
        "risk_score": risk,
        "risk_label": label,
        "risk_breakdown": {k: round(v, 1) for k, v in parts.items()},
        "counts": {
            "sessions": store.count_events("session.created"),
            "decisions": len(decisions),
            "blocked": by_verdict["block"],
            "held_for_approval": by_verdict["require_approval"],
            "allowed": by_verdict["allow"],
            "hostile_context": hostile,
            "anomalies": anomalies,
            "open_incidents": len(open_inc),
            "pending_approvals": len(pending),
            "quarantined_agents": sum(1 for a in c.agents.list() if a.status == "quarantined"),
        },
        "top_open_severity": top,
        "resistance_score": redteam["summary"]["resistance_score"] if redteam else None,
        "compliance_coverage": comp.coverage_pct,
        "audit_chain": comp.chain,
        "engine": {
            "llm": c.llm.enabled,
            "providers": c.llm.provider_names,
            "database": "postgresql" if type(c.store).__name__ == "PostgresStore" else "sqlite",
        },
    }
