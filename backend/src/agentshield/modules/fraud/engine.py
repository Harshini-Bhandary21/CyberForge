"""Fraud Guard: transaction risk scoring for agent-initiated money movement, plus bot detection."""

from __future__ import annotations

import statistics
import time
from typing import Any

from pydantic import BaseModel, Field

from agentshield.config import Settings
from agentshield.core.detectors import noisy_or
from agentshield.core.models import Signal, TaintTrace, Verdict
from agentshield.storage.store import Store


class FraudAssessment(BaseModel):
    score: float
    verdict: Verdict
    signals: list[Signal] = Field(default_factory=list)

    @property
    def reasons(self) -> list[str]:
        return [s.detail for s in self.signals]


class FraudEngine:
    COLLECTION = "fraud_profiles"

    def __init__(self, store: Store, settings: Settings) -> None:
        self.store = store
        self.settings = settings

    # ------------------------------------------------------------ profiles
    def _profile(self, agent_id: str) -> dict[str, Any]:
        return self.store.get(self.COLLECTION, agent_id) or {
            "amounts": [],
            "payees": [],
            "recent": [],
        }

    def learn(
        self, agent_id: str, amount: float, payee: str, *, record_recent: bool = True
    ) -> None:
        p = self._profile(agent_id)
        p["amounts"] = (p["amounts"] + [amount])[-200:]
        if payee and payee not in p["payees"]:
            p["payees"] = (p["payees"] + [payee])[-500:]
        if record_recent:
            p["recent"] = [t for t in p["recent"] if time.time() - t < 600] + [time.time()]
        self.store.put(self.COLLECTION, agent_id, p)

    # ------------------------------------------------------------ assessment
    def assess(
        self,
        agent_id: str,
        *,
        amount: float,
        payee: str,
        taint: TaintTrace | None = None,
        hour: int | None = None,
    ) -> FraudAssessment:
        p = self._profile(agent_id)
        sig: list[Signal] = []
        hour = time.localtime().tm_hour if hour is None else hour

        amounts = p["amounts"]
        if len(amounts) >= 5:
            mean, sd = (
                statistics.fmean(amounts),
                max(statistics.pstdev(amounts), mean_floor(amounts)),
            )
            z = (amount - mean) / sd
            if z > 3:
                sig.append(
                    Signal(
                        name="amount_outlier",
                        weight=min(0.8, 0.3 + z / 20),
                        detail=f"Amount ₹{amount:,.0f} is {min(z, 99):.0f}σ above this agent's norm (₹{mean:,.0f})",
                    )
                )
        elif amount >= self.settings.approval_amount_inr:
            sig.append(
                Signal(
                    name="large_amount_no_history",
                    weight=0.45,
                    detail=f"₹{amount:,.0f} exceeds the approval threshold and the agent has little history",
                )
            )

        if amount >= self.settings.block_amount_inr:
            sig.append(
                Signal(
                    name="amount_over_hard_limit",
                    weight=0.9,
                    detail=f"₹{amount:,.0f} exceeds the hard per-transaction limit",
                )
            )

        if payee and payee not in p["payees"]:
            sig.append(Signal(name="new_payee", weight=0.3, detail=f"First payment to '{payee}'"))

        recent = [t for t in p["recent"] if time.time() - t < 600]
        if len(recent) >= 3:
            sig.append(
                Signal(
                    name="velocity",
                    weight=0.4,
                    detail=f"{len(recent)} payments in the last 10 minutes",
                )
            )

        thr = self.settings.approval_amount_inr
        if thr * 0.9 <= amount < thr:
            sig.append(
                Signal(
                    name="structuring",
                    weight=0.35,
                    detail="Amount sits just under the approval threshold",
                )
            )

        if hour < 5 or hour >= 23:
            sig.append(
                Signal(name="off_hours", weight=0.2, detail=f"Payment at {hour:02d}:00 local time")
            )

        if taint and taint.control_sources:
            sig.append(
                Signal(
                    name="untrusted_instruction",
                    weight=0.7,
                    detail="Payee or amount originated in untrusted content",
                )
            )

        score = noisy_or([s.weight for s in sig])
        verdict = (
            Verdict.BLOCK
            if score >= 0.85
            else Verdict.REQUIRE_APPROVAL
            if score >= 0.4
            else Verdict.ALLOW
        )
        return FraudAssessment(score=score, verdict=verdict, signals=sig)


def mean_floor(amounts: list[float]) -> float:
    """Avoid a near-zero deviation making every payment an outlier."""
    return max(statistics.fmean(amounts) * 0.25, 1.0)


# ---------------------------------------------------------------------- bot detection
def bot_score(timestamps_ms: list[float]) -> dict[str, Any]:
    """Score request-timing regularity. Humans are bursty; scripts are metronomic or superhuman."""
    if len(timestamps_ms) < 6:
        return {"score": 0.0, "verdict": "insufficient_data", "signals": []}
    gaps = [b - a for a, b in zip(timestamps_ms, timestamps_ms[1:], strict=False)]
    mean = statistics.fmean(gaps)
    cv = statistics.pstdev(gaps) / mean if mean > 0 else 0.0
    sig: list[Signal] = []
    if cv < 0.15:
        sig.append(
            Signal(
                name="metronomic_timing",
                weight=0.7,
                detail=f"Inter-request gaps vary only {cv:.0%} (humans typically >50%)",
            )
        )
    if mean < 150:
        sig.append(
            Signal(
                name="superhuman_speed",
                weight=0.6,
                detail=f"Mean gap {mean:.0f} ms is faster than human interaction",
            )
        )
    score = noisy_or([s.weight for s in sig])
    return {
        "score": score,
        "verdict": "bot" if score >= 0.6 else "human_like",
        "signals": [s.model_dump() for s in sig],
    }
