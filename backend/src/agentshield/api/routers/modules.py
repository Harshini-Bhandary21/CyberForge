"""Module APIs: scanner, anomaly, incidents, fraud, code guard, compliance, red team, dojo."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from agentshield.api.deps import AdminAccess, Analyst, C
from agentshield.core.models import Trust
from agentshield.modules.anomaly.engine import Profile
from agentshield.modules.codeguard import scanner as cg
from agentshield.modules.compliance import autopilot
from agentshield.modules.dojo.service import AttemptResult, DojoService
from agentshield.modules.fraud.engine import FraudAssessment, bot_score
from agentshield.modules.incidents.service import Incident
from agentshield.modules.phishing.scanner import EmailInput, ScanResult, scan_email
from agentshield.modules.redteam.runner import run_campaign

router = APIRouter()

# ------------------------------------------------------------------ phishing
phishing = APIRouter(prefix="/scan", tags=["phishing"])


@phishing.post("/email", response_model=ScanResult)
def scan_mail(body: EmailInput, c: C) -> ScanResult:
    res = scan_email(body)
    c.store.append_event(
        "scan.email", {"verdict": res.verdict, "score": res.score, "tactics": res.tactics}
    )
    return res


# ------------------------------------------------------------------ anomaly / agents
agents = APIRouter(prefix="/agents", tags=["anomaly"])


@agents.get("")
def list_agents(c: C) -> list[dict[str, Any]]:
    out = []
    for a in c.agents.list():
        p: Profile = c.anomaly.profile(a.id)
        out.append(
            {
                **a.model_dump(),
                "baseline": {
                    "sessions": p.sessions,
                    "calls_mean": round(p.calls_mean, 2),
                    "calls_std": round(p.calls_std, 2),
                    "mature": p.mature,
                    "tools": p.tools,
                    "destinations": p.destinations[:20],
                },
            }
        )
    return out


@agents.post("/{agent_id}/quarantine")
def quarantine(agent_id: str, c: C, who: Analyst) -> dict[str, Any]:
    c.store.append_event("agent.quarantined", {"by": who.id}, agent_id=agent_id)
    return c.agents.quarantine(agent_id).model_dump()


@agents.post("/{agent_id}/release")
def release(agent_id: str, c: C, who: Analyst) -> dict[str, Any]:
    c.store.append_event("agent.released", {"by": who.id}, agent_id=agent_id)
    return c.agents.release(agent_id).model_dump()


@agents.get("/{agent_id}/credential", dependencies=[AdminAccess])
def credential(agent_id: str, c: C) -> dict[str, str]:
    """Demo helper: issue the signed identity an enrolled agent would present."""
    return {"agent_id": agent_id, "signature": c.agents.sign(agent_id)}


anomalies = APIRouter(prefix="/anomalies", tags=["anomaly"])


@anomalies.get("")
def list_anomalies(c: C, limit: int = 100) -> list[dict[str, Any]]:
    return [
        {
            "id": e["id"],
            "ts": e["ts"],
            "agent_id": e["agent_id"],
            "session_id": e["session_id"],
            **e["payload"],
        }
        for e in c.store.events(types=["anomaly.detected"], limit=limit)
    ]


# ------------------------------------------------------------------ incidents
incidents = APIRouter(prefix="/incidents", tags=["soc"])


@incidents.get("", response_model=list[Incident])
def list_incidents(c: C, status: str | None = None) -> list[Incident]:
    return c.incidents.list(status)


@incidents.get("/{incident_id}", response_model=Incident)
def get_incident(incident_id: str, c: C) -> Incident:
    inc = c.incidents.get(incident_id)
    if not inc:
        raise HTTPException(404, "incident not found")
    return inc


@incidents.post("/{incident_id}/actions/{action_id}", response_model=Incident)
def apply_action(incident_id: str, action_id: str, c: C, who: Analyst) -> Incident:
    inc = c.incidents.apply_action(incident_id, action_id, actor=who.id)
    if not inc:
        raise HTTPException(404, "incident not found")
    return inc


@incidents.post("/{incident_id}/resolve", response_model=Incident)
def resolve(incident_id: str, c: C) -> Incident:
    inc = c.incidents.resolve(incident_id)
    if not inc:
        raise HTTPException(404, "incident not found")
    return inc


# ------------------------------------------------------------------ fraud
fraud = APIRouter(prefix="/fraud", tags=["fraud"])


class FraudIn(BaseModel):
    agent_id: str
    amount: float
    payee: str = ""
    hour: int | None = Field(default=None, ge=0, le=23)
    untrusted_origin: bool = False


@fraud.post("/assess", response_model=FraudAssessment)
def assess(body: FraudIn, c: C) -> FraudAssessment:
    from agentshield.core.models import TaintSource, TaintTrace

    taint = (
        TaintTrace(
            tainted=True,
            sources=[
                TaintSource(
                    item_id="n/a",
                    source="declared",
                    trust=Trust.UNTRUSTED,
                    matched=["payee"],
                    via="control_arg",
                )
            ],
        )
        if body.untrusted_origin
        else None
    )
    res = c.fraud.assess(
        body.agent_id, amount=body.amount, payee=body.payee, taint=taint, hour=body.hour
    )
    c.store.append_event(
        "fraud.assessed",
        {
            "score": res.score,
            "verdict": res.verdict,
            "amount": body.amount,
            "payee": body.payee,
            "signals": [s.name for s in res.signals],
        },
        agent_id=body.agent_id,
    )
    return res


class BotIn(BaseModel):
    timestamps_ms: list[float]


@fraud.post("/bot-score")
def bot(body: BotIn) -> dict[str, Any]:
    return bot_score(body.timestamps_ms)


class IdentityIn(BaseModel):
    agent_id: str
    signature: str | None = None


@fraud.post("/verify-identity")
def verify_identity(body: IdentityIn, c: C) -> dict[str, Any]:
    return {"agent_id": body.agent_id, "verified": c.agents.verify(body.agent_id, body.signature)}


# ------------------------------------------------------------------ code guard
code = APIRouter(prefix="/codeguard", tags=["vulnerability"])


class CodeIn(BaseModel):
    code: str
    language: Literal["python", "javascript", "typescript"] = "python"


class DepsIn(BaseModel):
    manifest: str
    ecosystem: Literal["python", "npm"] = "python"


class ConfigIn(BaseModel):
    config: dict[str, Any]


def _log(c: Any, report: cg.ScanReport, kind: str) -> None:
    dep = sum(1 for f in report.findings if f.rule in {"typosquat-suspect", "hallucinated-package"})
    c.store.append_event(
        "codeguard.scan",
        {
            "kind": kind,
            "gate": report.gate,
            "findings": len(report.findings),
            "dependency_findings": dep,
        },
    )


@code.post("/scan", response_model=cg.ScanReport)
def scan_code(body: CodeIn, c: C) -> cg.ScanReport:
    r = cg.scan_code(body.code, body.language)
    _log(c, r, "code")
    return r


@code.post("/dependencies", response_model=cg.ScanReport)
def scan_deps(body: DepsIn, c: C) -> cg.ScanReport:
    r = cg.scan_requirements(body.manifest, body.ecosystem)
    _log(c, r, "dependencies")
    return r


@code.post("/agent-config", response_model=cg.ScanReport)
def scan_config(body: ConfigIn, c: C) -> cg.ScanReport:
    r = cg.audit_agent_config(body.config)
    _log(c, r, "agent-config")
    return r


# ------------------------------------------------------------------ compliance
compliance = APIRouter(prefix="/compliance", tags=["compliance"])


@compliance.get("/report", response_model=autopilot.ComplianceReport)
def report(c: C) -> autopilot.ComplianceReport:
    return autopilot.generate(c.store)


@compliance.get("/report.md", response_class=PlainTextResponse)
def report_md(c: C) -> str:
    return autopilot.to_markdown(autopilot.generate(c.store))


# ------------------------------------------------------------------ red team
redteam = APIRouter(prefix="/redteam", tags=["redteam"])


class CampaignIn(BaseModel):
    max_cases: int = Field(default=200, ge=10, le=1500)
    seed: int = 7
    categories: list[str] | None = None
    mutators: list[str] | None = None


@redteam.post("/run")
def run(body: CampaignIn, c: C) -> dict[str, Any]:
    result = run_campaign(
        c.settings,
        max_cases=body.max_cases,
        seed=body.seed,
        categories=body.categories,
        mutators=body.mutators,
    )
    c.store.put("redteam_runs", result["id"], result)
    c.store.append_event(
        "redteam.run", {"run_id": result["id"], **result["summary"]}, agent_id="redteam-agent"
    )
    return result


@redteam.get("/runs")
def runs(c: C) -> list[dict[str, Any]]:
    return c.store.list("redteam_runs", 20)


# ------------------------------------------------------------------ dojo
dojo = APIRouter(prefix="/dojo", tags=["awareness"])


class AttemptIn(BaseModel):
    level: int = Field(ge=1, le=5)
    text: str = Field(min_length=1, max_length=4000)


class PhishNewIn(BaseModel):
    name: str = "Alex"
    role: str = "analyst"
    org: str = "Acme Corp"
    difficulty: Literal["easy", "medium", "hard"] = "medium"


class PhishGradeIn(BaseModel):
    sim_id: str
    says_phish: bool
    selected_flags: list[str] = Field(default_factory=list)


def _dojo(c: C) -> DojoService:
    return DojoService(c.settings, c.store)


@dojo.get("/challenges")
def challenges(c: C) -> list[dict[str, Any]]:
    return _dojo(c).challenges()


@dojo.post("/attempt", response_model=AttemptResult)
def attempt(body: AttemptIn, c: C) -> AttemptResult:
    return _dojo(c).attempt(body.level, body.text)


@dojo.post("/phish/new")
def phish_new(body: PhishNewIn, c: C) -> dict[str, Any]:
    return _dojo(c).new_phish(
        name=body.name, role=body.role, org=body.org, difficulty=body.difficulty
    )


@dojo.post("/phish/grade")
def phish_grade(body: PhishGradeIn, c: C) -> dict[str, Any]:
    res = _dojo(c).grade_phish(body.sim_id, body.says_phish, body.selected_flags)
    if res is None:
        raise HTTPException(404, "simulation not found")
    return res


for r in (phishing, agents, anomalies, incidents, fraud, code, compliance, redteam, dojo):
    router.include_router(r)
