"""Data-loss-prevention checks applied to arguments of outbound tool calls."""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel

from agentshield.core.models import Risk


class DlpHit(BaseModel):
    kind: str
    category: str  # "secret" | "pii"
    severity: Risk
    sample: str  # redacted


_RULES: list[tuple[str, str, Risk, re.Pattern[str]]] = [
    ("aws_access_key", "secret", Risk.CRITICAL, re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "private_key",
        "secret",
        Risk.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "api_key",
        "secret",
        Risk.CRITICAL,
        re.compile(r"\b(?:sk|pk|ghp|xox[bp])[-_][A-Za-z0-9_-]{16,}\b"),
    ),
    (
        "jwt",
        "secret",
        Risk.HIGH,
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    (
        "password_assignment",
        "secret",
        Risk.HIGH,
        re.compile(r"(?i)\b(password|passwd|pwd|secret|token)\s*[:=]\s*\S{6,}"),
    ),
    ("pan_card", "pii", Risk.HIGH, re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")),
    ("aadhaar", "pii", Risk.HIGH, re.compile(r"\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b")),
]
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn(digits: str) -> bool:
    total, flip = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if flip:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
        flip = not flip
    return total % 10 == 0


def _redact(s: str) -> str:
    return s[:3] + "…" + s[-2:] if len(s) > 8 else "…"


def scan_text(text: str) -> list[DlpHit]:
    hits: list[DlpHit] = []
    for kind, cat, sev, pat in _RULES:
        for m in pat.finditer(text):
            hits.append(DlpHit(kind=kind, category=cat, severity=sev, sample=_redact(m.group(0))))
    for m in _CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits):
            hits.append(
                DlpHit(
                    kind="payment_card", category="pii", severity=Risk.HIGH, sample=_redact(digits)
                )
            )
    return hits


def scan_args(args: dict[str, Any]) -> list[DlpHit]:
    return scan_text(json.dumps(args, default=str, ensure_ascii=False))


def redact_text(text: str) -> str:
    """Replace every secret / personal-data match with ``[REDACTED:<kind>]``."""
    for kind, _cat, _sev, pat in _RULES:
        text = pat.sub(f"[REDACTED:{kind}]", text)

    def card(m: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        return (
            "[REDACTED:payment_card]" if 13 <= len(digits) <= 19 and _luhn(digits) else m.group(0)
        )

    return _CARD.sub(card, text)


def redact_value(value: Any) -> Any:
    """Recursively redact strings inside dicts / lists (used before persisting or sending data out)."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    return value
