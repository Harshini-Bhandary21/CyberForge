"""Argument provenance: which untrusted content is *driving* this tool call?

The agent's own account of why it acted cannot be trusted (it may be hijacked), so the shield
derives provenance independently. For each *control* argument (recipient, URL, command, amount...)
we extract the concrete values and ask: does this value appear in untrusted content but **not** in
anything the user or operator wrote? If so, untrusted content chose it. That is the signature of
an indirect prompt injection that reached a side-effecting tool.
"""

from __future__ import annotations

import re
from typing import Any

from agentshield.core.intent import EMAIL_RE, URL_RE
from agentshield.core.models import ContextItem, TaintSource, TaintTrace, Trust
from agentshield.core.normalize import normalize
from agentshield.core.tools import ToolSpec

_NUM_RE = re.compile(r"\d[\d,]*(?:\.\d+)?")
_PATH_RE = re.compile(r"(?:~|\.{0,2})/[\w./-]+|[\w-]+\.(?:env|pem|key)\b", re.I)
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _flatten(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _flatten(v)]
    if isinstance(value, (list, tuple, set)):
        return [s for v in value for s in _flatten(v)]
    if value is None:
        return []
    return [str(value)]


def _candidates(value: str) -> set[str]:
    """Concrete, checkable values inside one argument string."""
    out: set[str] = set()
    v = value.strip()
    out.update(e.lower() for e in EMAIL_RE.findall(v))
    for u in URL_RE.findall(v):
        u = u.lower().rstrip(".,")
        out.add(u)
        out.add(re.sub(r"^https?://", "", u).split("/")[0])
    out.update(p.lower() for p in _PATH_RE.findall(v))
    for n in _NUM_RE.findall(v):
        digits = n.replace(",", "")
        if len(digits.split(".")[0]) >= 3:
            out.add(digits)
    if not out and len(v) >= 4:  # opaque value such as a shell command or username
        out.add(v.lower())
    return out


def _contains(haystack: str, needle: str) -> bool:
    if needle.isdigit() or re.fullmatch(r"\d+\.\d+", needle):
        return (
            re.search(rf"(?<![\d.]){re.escape(needle)}(?![\d])", haystack.replace(",", ""))
            is not None
        )
    return needle in haystack


def _shingles(text: str, n: int = 5) -> set[tuple[str, ...]]:
    toks = _TOKEN_RE.findall(text.lower())
    return {tuple(toks[i : i + n]) for i in range(len(toks) - n + 1)}


def trace(
    spec: ToolSpec | None,
    args: dict[str, Any],
    goal: str,
    items: list[ContextItem],
    declared: list[str] | None = None,
) -> TaintTrace:
    trusted_text = (
        goal.lower()
        + "\n"
        + "\n".join(normalize(i.content).text.lower() for i in items if i.trust == Trust.TRUSTED)
    )
    untrusted = [(i, normalize(i.content).text.lower()) for i in items if i.trust != Trust.TRUSTED]
    sources: dict[tuple[str, str], TaintSource] = {}

    control_names = set(spec.control_args) if spec else set(args)
    for name, value in args.items():
        is_control = name in control_names
        for text in _flatten(value):
            if is_control:
                for cand in _candidates(text):
                    if _contains(trusted_text, cand):
                        continue  # the user supplied it; not attacker-chosen
                    for item, content in untrusted:
                        if _contains(content, cand):
                            key = (item.id, "control_arg")
                            src = sources.setdefault(
                                key,
                                TaintSource(
                                    item_id=item.id,
                                    source=item.source,
                                    trust=item.trust,
                                    matched=[],
                                    via="control_arg",
                                ),
                            )
                            if cand not in src.matched:
                                src.matched.append(cand)
            elif len(text) > 40:  # data argument: record verbatim reuse of untrusted text
                sh = _shingles(text)
                if not sh:
                    continue
                for item, content in untrusted:
                    if sh & _shingles(content):
                        key = (item.id, "data_arg")
                        sources.setdefault(
                            key,
                            TaintSource(
                                item_id=item.id,
                                source=item.source,
                                trust=item.trust,
                                matched=[f"{name} (text reuse)"],
                                via="data_arg",
                            ),
                        )

    by_id = {i.id: i for i in items}
    for item_id in declared or []:
        item = by_id.get(item_id)
        if item and item.trust != Trust.TRUSTED and (item.id, "control_arg") not in sources:
            sources[(item.id, "declared")] = TaintSource(
                item_id=item.id,
                source=item.source,
                trust=item.trust,
                matched=["declared by agent"],
                via="declared",
            )

    srcs = list(sources.values())
    return TaintTrace(tainted=any(s.via != "data_arg" for s in srcs), sources=srcs)
