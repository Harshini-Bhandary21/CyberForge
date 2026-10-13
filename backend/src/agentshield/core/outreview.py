"""Outbound claim review: which facts in an outgoing message came only from untrusted content?

Action-level checks cover *where* a message goes. They cannot see an attacker persuading the agent
to relay a false claim to a legitimate recipient ("the meeting moved to Monday", "use the new
account"). This module extracts checkable *claim atoms* (numbers, money, dates, times, links,
addresses, identifiers) from the outgoing text and checks provenance, like taint tracking but for
data: an atom the user never wrote and that appears only in a suspicious untrusted source is a
relayed claim. Exact, set-based, no model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agentshield.core.intent import EMAIL_RE, URL_RE
from agentshield.core.models import ContextItem, Trust
from agentshield.core.normalize import normalize
from agentshield.core.tools import ToolSpec

_DAY = r"(?:mon|tues?|wed(?:nes)?|thu(?:rs)?|fri|sat(?:ur)?|sun)(?:day)?"
_MONTH = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*"
_ATOMS = [
    ("money", re.compile(r"(?:₹|rs\.?|inr|\$|usd|eur)\s?\d[\d,]*(?:\.\d+)?", re.I)),
    (
        "date",
        re.compile(
            rf"\b{_DAY}\b|\b{_MONTH}\s+\d{{1,2}}\b|\b\d{{1,2}}[/-]\d{{1,2}}(?:[/-]\d{{2,4}})?\b",
            re.I,
        ),
    ),
    ("time", re.compile(r"\b\d{1,2}:\d{2}\s?(?:am|pm)?\b|\b\d{1,2}\s?(?:am|pm)\b", re.I)),
    ("id", re.compile(r"\b(?:\d[ -]?){8,}\b|\b[A-Z]{4}0[A-Z0-9]{6}\b")),
]
_NUM = re.compile(r"\b\d[\d,]{2,}(?:\.\d+)?\b")

# Items scoring at least this on the injection/phishing detectors are worth relaying scrutiny.
SUSPICIOUS = 0.25


@dataclass
class RelayedClaim:
    kind: str
    value: str
    source: str


@dataclass
class OutputReview:
    relayed: list[RelayedClaim] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return bool(self.relayed)


def _atoms(text: str) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    t = text.lower()
    for kind, rx in _ATOMS:
        for m in rx.finditer(t):
            out.add((kind, re.sub(r"[\s,.-]", "", m.group(0))))
    out.update(("email", e.lower()) for e in EMAIL_RE.findall(t))
    out.update(
        ("link", re.sub(r"^https?://", "", u.lower().rstrip(".,"))) for u in URL_RE.findall(t)
    )
    out.update(("number", n.replace(",", "")) for n in _NUM.findall(t))
    return out


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _strings(v)]
    return []


def review(
    spec: ToolSpec | None, args: dict[str, Any], goal: str, items: list[ContextItem]
) -> OutputReview:
    if not spec or spec.category != "egress":
        return OutputReview()
    control = set(spec.control_args)
    body = "\n".join(s for k, v in args.items() if k not in control for s in _strings(v))
    out_atoms = _atoms(normalize(body).text)
    if not out_atoms:
        return OutputReview()

    trusted_atoms = _atoms(goal)
    for i in items:
        if i.trust == Trust.TRUSTED:
            trusted_atoms |= _atoms(normalize(i.content).text)
    suspicious = [
        i
        for i in items
        if i.trust != Trust.TRUSTED and (i.risk_score >= SUSPICIOUS or i.trust == Trust.HOSTILE)
    ]
    source_atoms = [(i, _atoms(normalize(i.content).text)) for i in suspicious]

    relayed: list[RelayedClaim] = []
    for atom in sorted(out_atoms - trusted_atoms):
        for item, atoms in source_atoms:
            if atom in atoms:
                relayed.append(RelayedClaim(atom[0], atom[1], item.source))
                break
    return OutputReview(relayed)
