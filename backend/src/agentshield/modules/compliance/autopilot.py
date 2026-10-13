"""Evidence Autopilot: turns the tamper-evident audit log into control-mapped compliance evidence.

Every status is *computed from recorded events* and carries citations (event ids), so an auditor
can trace any claim to a specific log entry. The mapping is indicative support for an audit, not a
certification; controls AgentShield cannot evidence are reported as gaps, not hidden.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, Field

from agentshield.core.models import now
from agentshield.storage.store import Store

Status = Literal["satisfied", "partial", "gap"]


class ControlResult(BaseModel):
    id: str
    framework: str
    title: str
    requirement: str
    status: Status
    evidence: str
    citations: list[str] = Field(default_factory=list)
    recommendation: str = ""


class ComplianceReport(BaseModel):
    generated_at: float
    coverage_pct: int
    totals: dict[str, int]
    chain: dict[str, Any]
    controls: list[ControlResult]
    disclaimer: str = (
        "Indicative mapping generated from AgentShield's audit log to support an audit. "
        "It is not a certification and does not replace assessor judgement."
    )


@dataclass
class Ctx:
    store: Store

    def ev(self, *types: str, limit: int = 2000) -> list[dict[str, Any]]:
        return self.store.events(types=list(types), limit=limit)

    @staticmethod
    def cite(events: list[dict[str, Any]], n: int = 5) -> list[str]:
        return [f"evt#{e['id']}" for e in events[:n]]


@dataclass
class Control:
    id: str
    framework: str
    title: str
    requirement: str
    check: Callable[[Ctx], tuple[Status, str, list[str], str]]


def _decisions(c: Ctx) -> list[dict[str, Any]]:
    return c.ev("guard.decision")


def _latest_redteam(c: Ctx) -> dict[str, Any] | None:
    runs = c.store.list("redteam_runs", 1)
    return runs[0] if runs else None


def _llm01(c: Ctx):  # prompt injection
    dec = _decisions(c)
    taint_blocks = [
        d
        for d in dec
        if any(
            r.startswith("R-TAINT") or r.startswith("R-INTENT")
            for r in d["payload"].get("rules", [])
        )
    ]
    rt = _latest_redteam(c)
    asr = rt["summary"]["asr_protected"] if rt else None
    if taint_blocks and rt and asr <= 0.1:
        return (
            "satisfied",
            f"{len(taint_blocks)} injection-driven actions stopped; latest red-team attack success {asr:.0%}.",
            c.cite(taint_blocks),
            "",
        )
    if taint_blocks or rt:
        return (
            "partial",
            f"{len(taint_blocks)} injection-driven actions stopped; red-team {'ASR ' + format(asr, '.0%') if rt else 'not yet run'}.",
            c.cite(taint_blocks),
            "Run the red-team suite and drive attack success below 10%.",
        )
    return (
        "gap",
        "No injection controls exercised yet.",
        [],
        "Route agent tool calls through the guard and run a red-team campaign.",
    )


def _llm02(c: Ctx):  # sensitive info disclosure
    dec = [
        d
        for d in _decisions(c)
        if any(r.startswith("R-DLP") for r in d["payload"].get("rules", []))
    ]
    n_guarded = len(_decisions(c))
    if dec:
        return (
            "satisfied",
            f"DLP stopped or escalated {len(dec)} outbound calls containing secrets/PII.",
            c.cite(dec),
            "",
        )
    if n_guarded:
        return (
            "partial",
            f"DLP active across {n_guarded} guarded calls; no leakage attempts observed to evidence it.",
            c.cite(_decisions(c)),
            "Include a DLP test case in the red-team corpus.",
        )
    return "gap", "No guarded outbound calls recorded.", [], "Enable the guard on egress tools."


def _llm03(c: Ctx):  # supply chain
    scans = c.ev("codeguard.scan")
    if scans:
        flagged = sum(1 for s in scans if s["payload"].get("dependency_findings"))
        return (
            "satisfied",
            f"{len(scans)} code/dependency scans run; {flagged} flagged risky dependencies.",
            c.cite(scans),
            "",
        )
    return (
        "gap",
        "No dependency or agent-config scans recorded.",
        [],
        "Add Code Guard to the CI pipeline for agent-written code.",
    )


def _llm06(c: Ctx):  # excessive agency
    created = c.ev("session.created")
    cap_blocks = [d for d in _decisions(c) if "R-CAP-001" in d["payload"].get("rules", [])]
    hitl = [d for d in _decisions(c) if "R-HITL-001" in d["payload"].get("rules", [])]
    if created and (cap_blocks or hitl):
        return (
            "satisfied",
            f"{len(created)} sessions ran with least-privilege capabilities; {len(cap_blocks)} out-of-scope calls blocked; {len(hitl)} critical actions routed to a human.",
            c.cite(cap_blocks + hitl),
            "",
        )
    if created:
        return (
            "partial",
            f"{len(created)} sessions used least-privilege capabilities; no out-of-scope attempts observed yet.",
            c.cite(created),
            "",
        )
    return "gap", "No sessions recorded.", [], "Create sessions with derived capabilities."


def _log(c: Ctx):
    chain = c.store.verify_chain()
    if chain["length"] and chain["valid"]:
        return (
            "satisfied",
            f"Hash-chained audit log intact over {chain['length']} events (head {str(chain['head'])[:12]}…).",
            [f"chain:{chain['length']}"],
            "",
        )
    if chain["length"]:
        return (
            "gap",
            f"Audit chain BROKEN at event {chain['broken_at']}.",
            [f"evt#{chain['broken_at']}"],
            "Investigate tampering; restore from backup.",
        )
    return "gap", "No events logged.", [], ""


def _oversight(c: Ctx):
    req, res = c.ev("approval.requested"), c.ev("approval.resolved")
    if req and res:
        return (
            "satisfied",
            f"{len(req)} approvals requested; {len(res)} resolved by named reviewers.",
            c.cite(res),
            "",
        )
    if req:
        return (
            "partial",
            f"{len(req)} approvals requested; none resolved yet.",
            c.cite(req),
            "Resolve pending approvals in the queue.",
        )
    return (
        "partial",
        "Human-oversight workflow is deployed but has not been exercised.",
        [],
        "Exercise the approval path (e.g. the demo scenario).",
    )


def _robustness(c: Ctx):
    rt = _latest_redteam(c)
    if rt:
        s = rt["summary"]
        st: Status = (
            "satisfied" if s["asr_protected"] <= 0.1 and s["false_block_rate"] <= 0.1 else "partial"
        )
        return (
            st,
            f"Red-team: attack success {s['asr_baseline']:.0%} → {s['asr_protected']:.0%} with shield; false-block rate {s['false_block_rate']:.0%}.",
            [f"redteam:{rt['id']}"],
            "" if st == "satisfied" else "Tune policy to reduce attack success / false blocks.",
        )
    return "gap", "No robustness testing evidence.", [], "Run a red-team campaign."


def _monitoring(c: Ctx):
    an, inc = c.ev("anomaly.detected"), c.ev("incident.opened")
    if an or inc:
        return (
            "satisfied",
            f"Continuous monitoring produced {len(an)} anomaly detections and {len(inc)} incidents.",
            c.cite(an + inc),
            "",
        )
    if c.ev("guard.decision"):
        return (
            "partial",
            "Monitoring active; no anomalies or incidents occurred to evidence response.",
            [],
            "",
        )
    return "gap", "No monitoring data.", [], ""


def _incident_resp(c: Ctx):
    actions, opened = c.ev("incident.action"), c.ev("incident.opened")
    if actions:
        return (
            "satisfied",
            f"{len(opened)} incidents opened; {len(actions)} response actions executed and logged.",
            c.cite(actions),
            "",
        )
    if opened:
        return (
            "partial",
            f"{len(opened)} incidents opened; no response actions applied.",
            c.cite(opened),
            "Apply containment actions from the Incident Copilot.",
        )
    return "gap", "No incident handling evidence.", [], ""


CONTROLS: list[Control] = [
    Control(
        "LLM01",
        "OWASP LLM Top 10 (2025)",
        "Prompt Injection",
        "Constrain model behaviour and validate actions driven by untrusted input.",
        _llm01,
    ),
    Control(
        "LLM02",
        "OWASP LLM Top 10 (2025)",
        "Sensitive Information Disclosure",
        "Prevent leakage of confidential data in model outputs and actions.",
        _llm02,
    ),
    Control(
        "LLM03",
        "OWASP LLM Top 10 (2025)",
        "Supply Chain",
        "Vet third-party components and generated dependencies.",
        _llm03,
    ),
    Control(
        "LLM06",
        "OWASP LLM Top 10 (2025)",
        "Excessive Agency",
        "Limit tool permissions and require human approval for high-impact actions.",
        _llm06,
    ),
    Control(
        "MEASURE-2.7",
        "NIST AI RMF",
        "Security & resilience evaluated",
        "AI system security and resilience are evaluated and documented.",
        _robustness,
    ),
    Control(
        "MANAGE-4.1",
        "NIST AI RMF",
        "Post-deployment monitoring",
        "Post-deployment monitoring plans are implemented, incl. incident response.",
        _monitoring,
    ),
    Control(
        "ART-12",
        "EU AI Act",
        "Record-keeping",
        "Automatic recording of events over the system's lifetime.",
        _log,
    ),
    Control(
        "ART-14",
        "EU AI Act",
        "Human oversight",
        "Systems can be effectively overseen by natural persons.",
        _oversight,
    ),
    Control(
        "ART-15",
        "EU AI Act",
        "Accuracy, robustness, cybersecurity",
        "Resilience against attempts to alter use or performance.",
        _robustness,
    ),
    Control(
        "A.8.15",
        "ISO/IEC 27001:2022",
        "Logging",
        "Logs recording activities and events are produced, protected and reviewed.",
        _log,
    ),
    Control(
        "A.8.16",
        "ISO/IEC 27001:2022",
        "Monitoring activities",
        "Networks, systems and applications are monitored for anomalous behaviour.",
        _monitoring,
    ),
    Control(
        "A.5.26",
        "ISO/IEC 27001:2022",
        "Response to incidents",
        "Information security incidents are responded to per documented procedures.",
        _incident_resp,
    ),
]


def generate(store: Store) -> ComplianceReport:
    ctx = Ctx(store)
    results: list[ControlResult] = []
    for ctl in CONTROLS:
        status, evidence, cites, rec = ctl.check(ctx)
        results.append(
            ControlResult(
                id=ctl.id,
                framework=ctl.framework,
                title=ctl.title,
                requirement=ctl.requirement,
                status=status,
                evidence=evidence,
                citations=cites,
                recommendation=rec,
            )
        )
    totals = {s: sum(1 for r in results if r.status == s) for s in ("satisfied", "partial", "gap")}
    coverage = round(100 * (totals["satisfied"] + 0.5 * totals["partial"]) / len(results))
    return ComplianceReport(
        generated_at=now(),
        coverage_pct=coverage,
        totals=totals,
        chain=store.verify_chain(),
        controls=results,
    )


def to_markdown(report: ComplianceReport) -> str:
    icon = {"satisfied": "✅", "partial": "🟡", "gap": "❌"}
    out = [
        "# AgentShield compliance evidence report",
        "",
        f"- Coverage: **{report.coverage_pct}%** ({report.totals['satisfied']} satisfied, {report.totals['partial']} partial, {report.totals['gap']} gaps)",
        f"- Audit chain: {'intact' if report.chain['valid'] else 'BROKEN'} ({report.chain['length']} events)",
        "",
    ]
    frameworks: dict[str, list[ControlResult]] = {}
    for r in report.controls:
        frameworks.setdefault(r.framework, []).append(r)
    for fw, rows in frameworks.items():
        out += [f"## {fw}", ""]
        for r in rows:
            out += [
                f"### {icon[r.status]} {r.id} — {r.title}",
                f"*Requirement:* {r.requirement}",
                f"*Evidence:* {r.evidence}",
            ]
            if r.citations:
                out.append(f"*Citations:* {', '.join(r.citations)}")
            if r.recommendation:
                out.append(f"*Recommendation:* {r.recommendation}")
            out.append("")
    out += ["---", report.disclaimer]
    return "\n".join(out)
