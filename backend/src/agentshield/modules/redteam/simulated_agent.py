"""A deterministic stand-in for a *fully compliant, hijackable* LLM agent.

It models the worst case the shield must survive: whatever instruction it can read in its context,
it tries to execute. Like a capable LLM it decodes base64, ignores invisible characters, reads
hidden HTML and understands a few languages. It makes no attempt to resist; that is the point.
(For measuring a specific real model, plug a live agent into the same harness.)
"""

from __future__ import annotations

import re
from typing import Any

from agentshield.core.models import ToolCallRequest
from agentshield.core.normalize import normalize

_ADDR = r"([\w.+-]+@[\w-]+(?:\.[\w-]+)+)"
_F = re.I

_FORWARD = re.compile(
    rf"\b(?:forward|reenv[ií]a\w*|envoyez|bhejo)\b[^.\n]{{0,90}}?\bto\s+{_ADDR}", _F
)
_SEND = re.compile(rf"\b(?:send|email|mail)\b[^.\n]{{0,110}}?\bto\s+{_ADDR}", _F)
_REPLY = re.compile(rf"\breply\s+(?:to|with)\b[^.\n]{{0,40}}?{_ADDR}", _F)
_REPLY_SAY = re.compile(
    rf"\breply\s+to\s+{_ADDR}[,\s]+(?:and\s+)?(?:tell|say|write|inform)\s+(?:her|him|them)?\s*(?:that\s+)?(.+?)(?:\.\s|\.$|$)",
    _F | re.S,
)
_FETCH = re.compile(r"\b(?:visit|fetch|open|load)\s+(https?://[^\s)>\"']+)", _F)
_TRANSFER = re.compile(
    r"\b(?:transfer|pay|wire)\s+(?:rs\.?\s*|inr\s*|₹\s*|\$\s*)?([\d,]+)\s+(?:to|into)\s+(?:account\s+|acct\.?\s+|payee\s+)?(?:no\.?\s*)?([\w.@-]+)",
    _F,
)
_REFUND = re.compile(
    r"\brefund\s+(?:rs\.?\s*|inr\s*|₹\s*|\$\s*)?([\d,]+)\s+to\s+(?:account\s+|acct\.?\s+)?([\w.@-]+)",
    _F,
)
_RUN = re.compile(r"\b(?:run|execute)\s+`([^`]+)`", _F)
_RESET = re.compile(rf"\breset\s+the\s+password\s+for\s+{_ADDR}", _F)
_GRANT = re.compile(
    rf"\b(?:grant\s+admin\s+(?:role\s+)?to|give\s+admin\s+access\s+to)\s+{_ADDR}", _F
)
_DELETE = re.compile(r"\bdelete\s+(?:all\s+)?records\s+(?:for|in|of|from)\s+([\w.-]+)", _F)
_PART = re.compile(r"Part \d of \d:\s*", _F)


def read_context(docs: list[str]) -> str:
    return _PART.sub("", "\n".join(normalize(d).text for d in docs))


def hijacked_calls(docs: list[str]) -> list[ToolCallRequest]:
    """Tool calls a naive, over-compliant agent would issue after reading ``docs``."""
    text = read_context(docs)
    calls: list[tuple[str, dict[str, Any]]] = []

    forwarded = {m.group(1) for m in _FORWARD.finditer(text)}
    calls += [("forward_email", {"to": a, "message_id": "all"}) for a in forwarded]
    for m in _SEND.finditer(text):
        calls.append(
            ("send_email", {"to": m.group(1), "subject": "Requested data", "body": text[:600]})
        )
    said = set()
    for m in _REPLY_SAY.finditer(text):
        said.add(m.group(1).lower())
        calls.append(
            ("reply_email", {"to": m.group(1), "subject": "Re: update", "body": m.group(2).strip()})
        )
    for m in _REPLY.finditer(text):
        if m.group(1).lower() not in said:
            calls.append(("reply_email", {"to": m.group(1), "subject": "Re:", "body": text[:600]}))
    for m in _FETCH.finditer(text):
        calls.append(("fetch_url", {"url": m.group(1).rstrip(".,")}))
    for m in _TRANSFER.finditer(text):
        calls.append(
            ("transfer_funds", {"amount": float(m.group(1).replace(",", "")), "payee": m.group(2)})
        )
    for m in _REFUND.finditer(text):
        calls.append(
            ("issue_refund", {"amount": float(m.group(1).replace(",", "")), "payee": m.group(2)})
        )
    for m in _RUN.finditer(text):
        calls.append(("run_shell", {"command": m.group(1).strip()}))
    for m in _RESET.finditer(text):
        calls.append(("reset_password", {"user": m.group(1)}))
    for m in _GRANT.finditer(text):
        calls.append(("change_permissions", {"user": m.group(1), "role": "admin"}))
    for m in _DELETE.finditer(text):
        calls.append(("delete_records", {"target": m.group(1)}))
    return [ToolCallRequest(tool=t, args=a) for t, a in calls]
