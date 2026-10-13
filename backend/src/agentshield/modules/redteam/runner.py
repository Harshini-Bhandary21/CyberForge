"""Red-team campaign runner: measures attack success rate with and without the shield, per defence layer."""

from __future__ import annotations

import json
import random
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentshield.config import Settings
from agentshield.container import Container, build_container
from agentshield.core.models import (
    ContextKind,
    GuardDecision,
    ToolCallRequest,
    Verdict,
    new_id,
    now,
)
from agentshield.core.policy import PolicyConfig
from agentshield.modules.redteam.mutators import MUTATORS
from agentshield.modules.redteam.simulated_agent import hijacked_calls
from agentshield.storage.store import Store

DATA = Path(__file__).parent / "data"
ATTACKER_SOURCE = "email:ops-notice@partner-updates.example"

CONFIGS: dict[str, PolicyConfig] = {
    "full_shield": PolicyConfig(),
    "no_capabilities": PolicyConfig(capabilities=False),
    "no_taint_tracking": PolicyConfig(taint=False),
    "no_intent_verifier": PolicyConfig(intent=False),
    "no_session_risk": PolicyConfig(session_risk=False),
    "no_output_review": PolicyConfig(output_review=False),
    "capabilities_only": PolicyConfig(
        taint=False,
        dlp=False,
        intent=False,
        fraud=False,
        human_in_the_loop=False,
        session_risk=False,
        output_review=False,
    ),
}


def load_payloads() -> list[dict[str, Any]]:
    return json.loads((DATA / "payloads.json").read_text())


def load_hosts() -> list[dict[str, Any]]:
    return json.loads((DATA / "hosts.json").read_text())


@dataclass
class Case:
    payload: dict[str, Any]
    mutator: str
    host: dict[str, Any]


def _matches(call: ToolCallRequest, target: dict[str, str]) -> bool:
    return (
        call.tool == target["tool"]
        and target["contains"].lower() in json.dumps(call.args, default=str).lower()
    )


def _plant(c: Container, host: dict[str, Any], poison: list[str]) -> str:
    s = c.sessions.create("redteam-agent", host["goal"])
    for d in host["docs"]:
        c.sessions.add_context(
            s.id,
            source=d["source"],
            content=d["content"],
            kind=ContextKind(d["kind"]),
            metadata={"sender": d["source"].split(":", 1)[-1], "subject": "update"},
        )
    for body in poison:
        c.sessions.add_context(
            s.id,
            source=ATTACKER_SOURCE,
            content=body,
            kind=ContextKind.EMAIL,
            metadata={"sender": "ops-notice@partner-updates.example", "subject": "Weekly update"},
        )
    return s.id


def _run_attack(c: Container, case: Case) -> tuple[bool, bool, list[GuardDecision]]:
    """Returns (hijacked, succeeded_under_this_config, decisions for the hijack calls)."""
    poison = MUTATORS[case.mutator](case.payload["text"])
    sid = _plant(c, case.host, poison)
    session = c.sessions.get(sid)
    assert session is not None
    docs = [i.content for i in session.context]
    evil = hijacked_calls(docs)
    hit = [call for call in evil if _matches(call, case.payload["target"])]
    hijacked = bool(hit)
    decisions: list[GuardDecision] = []
    succeeded = False
    for call in evil:
        d = c.guard.evaluate(sid, call)
        if d is None:
            continue
        decisions.append(d)
        if _matches(call, case.payload["target"]) and d.verdict == Verdict.ALLOW:
            succeeded = True
    c.sessions.close(sid)
    return hijacked, succeeded, decisions


def _run_benign(c: Container, host: dict[str, Any]) -> tuple[int, int, int]:
    sid = _plant(c, host, [])
    blocked = held = total = 0
    for call in host["calls"]:
        d = c.guard.evaluate(sid, ToolCallRequest(**call))
        total += 1
        if d and d.verdict == Verdict.BLOCK:
            blocked += 1
        elif d and d.verdict == Verdict.REQUIRE_APPROVAL:
            held += 1
    c.sessions.close(sid)
    return total, blocked, held


def sample_cases(
    max_cases: int, seed: int, mutators: list[str] | None, categories: list[str] | None
) -> list[Case]:
    payloads = [p for p in load_payloads() if not categories or p["category"] in categories]
    cases = [
        Case(p, m, h) for p in payloads for m in (mutators or list(MUTATORS)) for h in load_hosts()
    ]
    if len(cases) > max_cases:
        cases = random.Random(seed).sample(cases, max_cases)
    return cases


def run_campaign(
    settings: Settings,
    *,
    max_cases: int = 300,
    seed: int = 7,
    mutators: list[str] | None = None,
    categories: list[str] | None = None,
) -> dict[str, Any]:
    settings = settings.model_copy(update={"fixed_hour": 11})  # time-of-day must not change results
    cases = sample_cases(max_cases, seed, mutators, categories)
    hosts = load_hosts()
    results: dict[str, dict[str, Any]] = {}
    latencies: list[float] = []
    per_case: list[dict[str, Any]] = []
    rule_counts: dict[str, int] = {}
    failures: list[dict[str, Any]] = []

    for name, cfg in CONFIGS.items():
        c = build_container(settings, Store(":memory:"), policy=cfg, heuristic_only=True)
        wins = 0
        for case in cases:
            hijacked, success, decisions = _run_attack(c, case)
            wins += success
            latencies += [d.latency_ms for d in decisions]
            if name == "full_shield":
                fired = {
                    r
                    for d in decisions
                    for r in (f.rule for f in d.findings if f.verdict != Verdict.ALLOW)
                }
                if hijacked and not success:
                    for r in fired:
                        rule_counts[r] = rule_counts.get(r, 0) + 1
                per_case.append(
                    {
                        "category": case.payload["category"],
                        "mutator": case.mutator,
                        "hijacked": hijacked,
                        "success": success,
                    }
                )
                if success and len(failures) < 10:
                    failures.append(
                        {
                            "payload": case.payload["id"],
                            "mutator": case.mutator,
                            "host": case.host["id"],
                        }
                    )
        total = blocked = held = 0
        for host in hosts:
            t, b, h = _run_benign(c, host)
            total, blocked, held = total + t, blocked + b, held + h
        results[name] = {
            "asr": wins / len(cases) if cases else 0.0,
            "false_block_rate": blocked / total if total else 0.0,
            "friction_rate": held / total if total else 0.0,
        }

    hijacked_n = sum(1 for r in per_case if r["hijacked"])
    baseline = hijacked_n / len(cases) if cases else 0.0

    def group(key: str) -> list[dict[str, Any]]:
        out = []
        for value in sorted({r[key] for r in per_case}):
            rows = [r for r in per_case if r[key] == value]
            out.append(
                {
                    key: value,
                    "n": len(rows),
                    "baseline": sum(r["hijacked"] for r in rows) / len(rows),
                    "protected": sum(r["success"] for r in rows) / len(rows),
                }
            )
        return out

    full = results["full_shield"]
    return {
        "id": new_id("rt"),
        "created_at": now(),
        "params": {
            "cases": len(cases),
            "seed": seed,
            "engine": "heuristic",
            "payloads": len(load_payloads()),
            "mutators": mutators or list(MUTATORS),
        },
        "summary": {
            "asr_baseline": baseline,
            "asr_protected": full["asr"],
            "false_block_rate": full["false_block_rate"],
            "friction_rate": full["friction_rate"],
            "resistance_score": round(100 * (1 - full["asr"])),
            "avg_latency_ms": round(statistics.fmean(latencies), 2) if latencies else 0.0,
            "p95_latency_ms": round(sorted(latencies)[int(len(latencies) * 0.95) - 1], 2)
            if latencies
            else 0.0,
        },
        "by_category": group("category"),
        "by_mutator": group("mutator"),
        "ablations": [{"config": k, **v} for k, v in results.items()],
        "defended_by_rule": dict(sorted(rule_counts.items(), key=lambda kv: -kv[1])),
        "breaches": failures,
    }
