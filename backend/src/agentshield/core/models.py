"""Core domain models shared by every AgentShield module."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def now() -> float:
    return time.time()


class Trust(StrEnum):
    TRUSTED = "trusted"  # user / operator authored
    UNTRUSTED = "untrusted"  # emails, web pages, tool output
    HOSTILE = "hostile"  # untrusted *and* flagged as an attack


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


RISK_ORDER = {Risk.LOW: 1, Risk.MEDIUM: 2, Risk.HIGH: 3, Risk.CRITICAL: 4}


class Verdict(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


VERDICT_ORDER = {Verdict.ALLOW: 0, Verdict.REQUIRE_APPROVAL: 1, Verdict.BLOCK: 2}


class Signal(BaseModel):
    """One piece of evidence from a detector."""

    name: str
    weight: float = Field(ge=0, le=1)
    detail: str = ""


class ContextKind(StrEnum):
    USER = "user"
    EMAIL = "email"
    WEB = "web"
    DOCUMENT = "document"
    TOOL_OUTPUT = "tool_output"


class ContextItem(BaseModel):
    id: str = Field(default_factory=lambda: new_id("ctx"))
    kind: ContextKind = ContextKind.DOCUMENT
    source: str
    trust: Trust = Trust.UNTRUSTED
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0
    signals: list[Signal] = Field(default_factory=list)
    created_at: float = Field(default_factory=now)


class Session(BaseModel):
    id: str = Field(default_factory=lambda: new_id("ses"))
    agent_id: str
    user_goal: str
    capabilities: list[str] = Field(default_factory=list)
    identity_verified: bool = False
    status: Literal["active", "closed"] = "active"
    context: list[ContextItem] = Field(default_factory=list)
    call_count: int = 0
    blocked_count: int = 0
    created_at: float = Field(default_factory=now)


class ToolCallRequest(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    # Optional: context item ids the agent says influenced this call. The shield
    # does not trust it; it derives provenance independently from the arguments.
    influenced_by: list[str] | None = None
    approval_id: str | None = None


class TaintSource(BaseModel):
    item_id: str
    source: str
    trust: Trust
    matched: list[str]
    via: Literal["control_arg", "data_arg", "declared"]


class TaintTrace(BaseModel):
    tainted: bool = False
    sources: list[TaintSource] = Field(default_factory=list)

    @property
    def control_sources(self) -> list[TaintSource]:
        return [s for s in self.sources if s.via != "data_arg"]


class VerifierResult(BaseModel):
    aligned: Literal["yes", "no", "uncertain"]
    confidence: float = Field(ge=0, le=1)
    reasoning: str
    engine: Literal["heuristic", "llm"] = "heuristic"
    provider: str | None = None  # which LLM provider answered, when engine == "llm"


class Finding(BaseModel):
    rule: str
    severity: Risk
    message: str
    verdict: Verdict = Verdict.ALLOW
    evidence: list[str] = Field(default_factory=list)


class AnomalyRecord(BaseModel):
    kind: str
    score: float
    detail: str


class GuardDecision(BaseModel):
    id: str = Field(default_factory=lambda: new_id("dec"))
    session_id: str
    agent_id: str
    tool: str
    args: dict[str, Any]
    verdict: Verdict
    risk: Risk
    findings: list[Finding] = Field(default_factory=list)
    taint: TaintTrace = Field(default_factory=TaintTrace)
    verifier: VerifierResult | None = None
    anomalies: list[AnomalyRecord] = Field(default_factory=list)
    approval_id: str | None = None
    incident_id: str | None = None
    latency_ms: float = 0.0
    created_at: float = Field(default_factory=now)

    @property
    def reasons(self) -> list[str]:
        return [f.message for f in self.findings if f.verdict != Verdict.ALLOW]
