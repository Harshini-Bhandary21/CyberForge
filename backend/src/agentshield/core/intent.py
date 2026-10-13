"""Goal analysis: what did the *user* actually ask for?

Used twice: to derive a least-privilege capability set when a session starts, and by the
heuristic intent verifier to judge proposed actions against that goal.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from agentshield.core.tools import READ_ONLY

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
URL_RE = re.compile(r"https?://[^\s)>\"']+", re.I)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)

_INTENTS: dict[str, re.Pattern[str]] = {
    "forward": re.compile(r"\bforward\b", re.I),
    "reply": re.compile(r"\b(reply|respond|write back|get back to)\b", re.I),
    "send": re.compile(r"\b(send|notify|message|e-?mail (?:to|him|her|them|\S+@))\b", re.I),
    "refund": re.compile(r"\b(refund|reimburse)\b", re.I),
    "pay": re.compile(r"\b(pay|transfer|payout|wire)\b", re.I),
    "exec": re.compile(r"\b(run|execute|deploy|install|restart|build)\b", re.I),
    "write": re.compile(r"\b(write|save|create|update|edit|fix|modify|draft|log)\b", re.I),
    "commit": re.compile(r"\b(commit|push)\b", re.I),
    "reset": re.compile(r"\breset\b.{0,20}\bpassword\b", re.I),
    "permissions": re.compile(r"\b(grant|revoke|permissions?|role|access rights)\b", re.I),
    "browse": re.compile(r"\b(search|research|browse|look up|lookup|fetch|visit)\b", re.I),
    "delete": re.compile(r"\b(delete|remove|purge|erase)\b", re.I),
}

_CAPS: dict[str, list[str]] = {
    "forward": ["forward_email"],
    "reply": ["reply_email"],
    "send": ["send_email"],
    "refund": ["issue_refund"],
    "pay": ["transfer_funds"],
    "exec": ["run_shell"],
    "write": ["write_file"],
    "commit": ["commit_code"],
    "reset": ["reset_password"],
    "permissions": ["change_permissions"],
    "browse": ["fetch_url"],
    "delete": ["delete_records"],
}


class GoalProfile(BaseModel):
    intents: set[str] = Field(default_factory=set)
    emails: set[str] = Field(default_factory=set)
    domains: set[str] = Field(default_factory=set)
    urls: set[str] = Field(default_factory=set)


def analyze_goal(goal: str) -> GoalProfile:
    emails = {e.lower() for e in EMAIL_RE.findall(goal)}
    urls = {u.lower().rstrip(".,") for u in URL_RE.findall(goal)}
    without = EMAIL_RE.sub(" ", goal)
    domains = {d.lower() for d in _DOMAIN_RE.findall(without)} | {
        e.split("@", 1)[1] for e in emails
    }
    domains |= {re.sub(r"^https?://", "", u).split("/")[0] for u in urls}
    intents = {name for name, pat in _INTENTS.items() if pat.search(goal)}
    return GoalProfile(intents=intents, emails=emails, domains=domains, urls=urls)


def derive_capabilities(goal: str) -> list[str]:
    """Least privilege: read-only by default, plus only the side effects the goal calls for."""
    caps = list(READ_ONLY)
    for intent in analyze_goal(goal).intents:
        for tool in _CAPS.get(intent, []):
            if tool not in caps:
                caps.append(tool)
    return caps
