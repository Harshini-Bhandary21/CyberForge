"""Policy engine: turns evidence (taint, DLP, intent, fraud, capabilities) into a verdict.

Rules are small, named and independently switchable (``PolicyConfig``), which is what lets the
red-team harness run ablations and report how much each defence layer contributes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from agentshield.core.dlp import DlpHit
from agentshield.core.models import (
    RISK_ORDER,
    VERDICT_ORDER,
    Finding,
    Risk,
    TaintTrace,
    Trust,
    Verdict,
    VerifierResult,
)
from agentshield.core.tools import ToolSpec


@dataclass(frozen=True)
class PolicyConfig:
    capabilities: bool = True
    taint: bool = True
    dlp: bool = True
    intent: bool = True
    fraud: bool = True
    human_in_the_loop: bool = True  # critical tools always need a human
    quarantine: bool = True


@dataclass
class PolicyInput:
    tool: str
    spec: ToolSpec | None
    capabilities: list[str]
    taint: TaintTrace
    dlp: list[DlpHit]
    verifier: VerifierResult | None
    fraud_verdict: Verdict | None = None
    fraud_reasons: list[str] = field(default_factory=list)
    outbound_text: str = ""
    agent_quarantined: bool = False
    revoked: bool = False
    identity_unverified_and_required: bool = False


_PAYMENT_INSTRUCTION = re.compile(
    r"(?:account|acct|a/c)\D{0,15}\d{8,}|\bIFSC\b|\bUPI\b|\b(?:wire|transfer)\b.{0,40}\d",
    re.I | re.S,
)


def _f(
    rule: str, sev: Risk, verdict: Verdict, msg: str, evidence: list[str] | None = None
) -> Finding:
    return Finding(rule=rule, severity=sev, verdict=verdict, message=msg, evidence=evidence or [])


def evaluate(inp: PolicyInput, cfg: PolicyConfig) -> tuple[Verdict, Risk, list[Finding]]:
    findings: list[Finding] = []
    spec = inp.spec
    risk = spec.risk if spec else Risk.HIGH

    if cfg.quarantine and (inp.agent_quarantined or inp.revoked):
        why = (
            "Agent is quarantined"
            if inp.agent_quarantined
            else f"Tool '{inp.tool}' was revoked for this agent"
        )
        findings.append(
            _f(
                "R-AGENT-001",
                Risk.CRITICAL,
                Verdict.BLOCK,
                f"{why} by an incident response action.",
            )
        )

    if cfg.capabilities and (spec is None or inp.tool not in inp.capabilities):
        findings.append(
            _f(
                "R-CAP-001",
                Risk.HIGH,
                Verdict.BLOCK,
                f"'{inp.tool}' is outside this session's least-privilege capabilities.",
            )
        )

    if inp.identity_unverified_and_required and risk in (Risk.HIGH, Risk.CRITICAL):
        findings.append(
            _f(
                "R-ID-001",
                Risk.HIGH,
                Verdict.REQUIRE_APPROVAL,
                "Agent identity is not cryptographically verified.",
            )
        )

    if cfg.taint and inp.taint.control_sources and spec:
        srcs = inp.taint.control_sources
        hostile = any(s.trust == Trust.HOSTILE for s in srcs)
        matched = sorted({m for s in srcs for m in s.matched})[:5]
        names = ", ".join(sorted({s.source for s in srcs}))
        msg = f"Untrusted content from {names} chose the action's target ({', '.join(matched)})."
        if RISK_ORDER[risk] >= RISK_ORDER[Risk.HIGH]:
            verdict = (
                Verdict.BLOCK if (hostile or risk == Risk.CRITICAL) else Verdict.REQUIRE_APPROVAL
            )
            findings.append(
                _f("R-TAINT-001", Risk.CRITICAL if hostile else Risk.HIGH, verdict, msg, matched)
            )
        elif risk == Risk.MEDIUM:
            # Following a plain link found in content is normal browsing; it only becomes an
            # exfiltration channel when the URL carries a query string or the source is hostile.
            if spec.category == "network" and not hostile and not any("?" in m for m in matched):
                findings.append(
                    _f(
                        "R-TAINT-003",
                        Risk.LOW,
                        Verdict.ALLOW,
                        "Fetching a link found in content (no data in URL).",
                        matched,
                    )
                )
            else:
                findings.append(
                    _f(
                        "R-TAINT-002",
                        Risk.MEDIUM,
                        Verdict.BLOCK if hostile else Verdict.REQUIRE_APPROVAL,
                        msg,
                        matched,
                    )
                )

    if cfg.taint and spec and spec.category == "egress":
        reused = [s for s in inp.taint.sources if s.via == "data_arg"]
        if reused and _PAYMENT_INSTRUCTION.search(inp.outbound_text):
            findings.append(
                _f(
                    "R-TAINT-004",
                    Risk.HIGH,
                    Verdict.REQUIRE_APPROVAL,
                    "Outbound message relays payment instructions copied from untrusted content (typical business-email-compromise).",
                    sorted({s.source for s in reused}),
                )
            )

    if cfg.dlp and inp.dlp and spec and spec.egress:
        secrets = [h for h in inp.dlp if h.category == "secret"]
        pii = [h for h in inp.dlp if h.category == "pii"]
        if secrets:
            findings.append(
                _f(
                    "R-DLP-001",
                    Risk.CRITICAL,
                    Verdict.BLOCK,
                    "Outbound call contains credentials/secrets.",
                    sorted({h.kind for h in secrets}),
                )
            )
        elif pii:
            findings.append(
                _f(
                    "R-DLP-002",
                    Risk.HIGH,
                    Verdict.REQUIRE_APPROVAL,
                    "Outbound call contains personal data.",
                    sorted({h.kind for h in pii}),
                )
            )

    v = inp.verifier
    if cfg.intent and v and spec:
        if (
            v.aligned == "no"
            and v.confidence >= 0.6
            and RISK_ORDER[risk] >= RISK_ORDER[Risk.MEDIUM]
        ):
            findings.append(
                _f(
                    "R-INTENT-001",
                    Risk.HIGH,
                    Verdict.BLOCK,
                    f"Action is not justified by the user's goal: {v.reasoning}",
                )
            )
        elif v.aligned == "uncertain" and RISK_ORDER[risk] >= RISK_ORDER[Risk.HIGH]:
            findings.append(
                _f(
                    "R-INTENT-002",
                    Risk.MEDIUM,
                    Verdict.REQUIRE_APPROVAL,
                    f"Cannot confirm the action matches the goal: {v.reasoning}",
                )
            )

    if cfg.fraud and inp.fraud_verdict in (Verdict.REQUIRE_APPROVAL, Verdict.BLOCK):
        sev = Risk.CRITICAL if inp.fraud_verdict == Verdict.BLOCK else Risk.HIGH
        findings.append(
            _f(
                "R-FRAUD-001",
                sev,
                inp.fraud_verdict,
                "Transaction risk: " + "; ".join(inp.fraud_reasons[:3]),
            )
        )

    if (
        cfg.human_in_the_loop
        and risk == Risk.CRITICAL
        and not any(f.verdict == Verdict.BLOCK for f in findings)
    ):
        findings.append(
            _f(
                "R-HITL-001",
                Risk.MEDIUM,
                Verdict.REQUIRE_APPROVAL,
                "Critical-risk tool requires human approval (human oversight).",
            )
        )

    verdict = max(
        (f.verdict for f in findings), key=lambda x: VERDICT_ORDER[x], default=Verdict.ALLOW
    )
    return verdict, risk, findings
