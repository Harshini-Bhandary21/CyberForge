"""Behavioural Anomaly Engine: per-agent baselines, drift detection (UEBA for agents)."""

from __future__ import annotations

import json
import math
import time
from typing import Any

from pydantic import BaseModel, Field

from agentshield.core.models import AnomalyRecord, Session, ToolCallRequest, Verdict
from agentshield.core.tools import ToolSpec
from agentshield.storage.store import Store

MATURE_SESSIONS = 5
HISTORY = 100  # recent observations kept for robust statistics
MAD_SCALE = 1.4826  # makes MAD comparable to a standard deviation for normal data


def median(xs: list[float]) -> float:
    s = sorted(xs)
    n = len(s)
    return 0.0 if not n else (s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2)


def robust_z(x: float, history: list[float], floor: float = 1.0) -> float:
    """Modified z-score: median/MAD instead of mean/std, so past outliers cannot hide new ones."""
    med = median(history)
    mad = median([abs(v - med) for v in history]) * MAD_SCALE
    return (x - med) / max(mad, floor)


class Profile(BaseModel):
    agent_id: str
    sessions: int = 0
    calls_mean: float = 0.0
    calls_m2: float = 0.0  # Welford accumulator
    tools: dict[str, int] = Field(default_factory=dict)
    destinations: list[str] = Field(default_factory=list)
    hours: list[int] = Field(default_factory=lambda: [0] * 24)
    arg_bytes_mean: float = 0.0
    arg_bytes_n: int = 0
    call_history: list[int] = Field(default_factory=list)  # calls per session, recent
    size_history: list[int] = Field(default_factory=list)  # argument bytes per call, recent

    @property
    def calls_std(self) -> float:
        return math.sqrt(self.calls_m2 / (self.sessions - 1)) if self.sessions > 1 else 0.0

    @property
    def mature(self) -> bool:
        return self.sessions >= MATURE_SESSIONS


def _destination(spec: ToolSpec | None, args: dict[str, Any]) -> str | None:
    if not spec or not spec.egress:
        return None
    for key in ("to", "url"):
        v = args.get(key)
        if isinstance(v, list):
            v = v[0] if v else None
        if isinstance(v, str) and v:
            v = v.lower()
            return v.split("@")[-1] if "@" in v else v.split("//")[-1].split("/")[0]
    return None


class AnomalyEngine:
    COLLECTION = "profiles"

    def __init__(self, store: Store) -> None:
        self.store = store

    def profile(self, agent_id: str) -> Profile:
        raw = self.store.get(self.COLLECTION, agent_id)
        return Profile(**raw) if raw else Profile(agent_id=agent_id)

    def _save(self, p: Profile) -> None:
        self.store.put(self.COLLECTION, p.agent_id, p.model_dump())

    # ------------------------------------------------------------ learning
    def learn_call(
        self, agent_id: str, spec: ToolSpec | None, req: ToolCallRequest, hour: int | None = None
    ) -> None:
        """Only *allowed* calls teach the baseline, so an attacker cannot poison it."""
        p = self.profile(agent_id)
        p.tools[req.tool] = p.tools.get(req.tool, 0) + 1
        dest = _destination(spec, req.args)
        if dest and dest not in p.destinations:
            p.destinations = (p.destinations + [dest])[-300:]
        h = time.localtime().tm_hour if hour is None else hour
        p.hours[h] += 1
        size = len(json.dumps(req.args, default=str))
        p.arg_bytes_n += 1
        p.arg_bytes_mean += (size - p.arg_bytes_mean) / p.arg_bytes_n
        p.size_history = (p.size_history + [size])[-HISTORY:]
        self._save(p)

    def learn_session(self, agent_id: str, call_count: int) -> None:
        p = self.profile(agent_id)
        p.sessions += 1
        p.call_history = (p.call_history + [call_count])[-HISTORY:]
        delta = call_count - p.calls_mean
        p.calls_mean += delta / p.sessions
        p.calls_m2 += delta * (call_count - p.calls_mean)
        self._save(p)

    # ------------------------------------------------------------ detection
    def observe(
        self,
        session: Session,
        spec: ToolSpec | None,
        req: ToolCallRequest,
        verdict: Verdict,
        hour: int | None = None,
    ) -> list[AnomalyRecord]:
        p = self.profile(session.agent_id)
        out: list[AnomalyRecord] = []
        if p.mature:
            if req.tool not in p.tools:
                out.append(
                    AnomalyRecord(
                        kind="new_tool",
                        score=0.7,
                        detail=f"'{req.tool}' has never been used by this agent",
                    )
                )
            dest = _destination(spec, req.args)
            if dest and dest not in p.destinations:
                out.append(
                    AnomalyRecord(
                        kind="new_destination", score=0.8, detail=f"First-ever egress to '{dest}'"
                    )
                )
            hist = p.call_history or [round(p.calls_mean)]
            z = max(
                robust_z(session.call_count, [float(h) for h in hist]),
                (session.call_count - p.calls_mean) / max(p.calls_std, 1.0)
                if len(p.call_history) < MATURE_SESSIONS
                else 0.0,
            )
            if z > 3.5 and session.call_count > median([float(h) for h in hist]) + 3:
                out.append(
                    AnomalyRecord(
                        kind="call_burst",
                        score=min(0.95, 0.5 + z / 20),
                        detail=f"{session.call_count} calls this session vs a median of {median([float(h) for h in hist]):.0f} (robust z={z:.1f})",
                    )
                )
            size = len(json.dumps(req.args, default=str))
            typical = (
                median([float(v) for v in p.size_history]) if p.size_history else p.arg_bytes_mean
            )
            if p.arg_bytes_n >= 10 and size > max(typical * 8, 2000):
                out.append(
                    AnomalyRecord(
                        kind="data_volume",
                        score=0.65,
                        detail=f"Argument payload {size} B vs typical {typical:.0f} B",
                    )
                )
            h = time.localtime().tm_hour if hour is None else hour
            total = sum(p.hours)
            if total >= 30 and p.hours[h] / total < 0.01:
                out.append(
                    AnomalyRecord(
                        kind="off_hours",
                        score=0.4,
                        detail=f"Agent is almost never active at {h:02d}:00",
                    )
                )
        if verdict == Verdict.BLOCK and session.blocked_count >= 3:
            out.append(
                AnomalyRecord(
                    kind="repeated_blocks",
                    score=0.85,
                    detail=f"{session.blocked_count} blocked actions in one session (probing for a bypass)",
                )
            )
        return out
