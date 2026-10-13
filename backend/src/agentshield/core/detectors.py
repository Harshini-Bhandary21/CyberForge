"""Prompt-injection and indirect-instruction detectors (the Injection Firewall's input side).

These are deliberately *advisory*: they label context as ``hostile`` so policy tightens, but the
decisive controls are action-level (taint, capabilities, intent). A miss here is not a breach.
"""

from __future__ import annotations

import re

from agentshield.core.models import Signal
from agentshield.core.normalize import normalize

_F = re.I | re.S

# (name, pattern, weight, explanation)
_PATTERNS: list[tuple[str, re.Pattern[str], float, str]] = [
    (
        "override_instructions",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|any)\b.{0,30}\b(instructions?|prompts?|rules?|directions?)",
            _F,
        ),
        0.55,
        "Tries to override the assistant's existing instructions",
    ),
    (
        "role_reassignment",
        re.compile(
            r"\byou are (now|no longer)\b|\bnew (system )?(instructions|persona|role)\b|\bact as\b.{0,30}\b(admin|root|developer|dan)\b",
            _F,
        ),
        0.4,
        "Attempts to reassign the assistant's role",
    ),
    (
        "system_prompt_probe",
        re.compile(
            r"\b(reveal|print|show|repeat|leak)\b.{0,30}\b(system prompt|hidden prompt|instructions|api keys?|secrets?|credentials)\b",
            _F,
        ),
        0.5,
        "Probes for the system prompt or secrets",
    ),
    (
        "agent_directive",
        re.compile(
            r"\b(assistant|ai agent|agent|ai model|language model|claude|gpt|llm|ai)\b.{0,25}\b(must|should|need to|has to|please|are required to)\b.{0,45}\b(forward|send|email|transfer|pay|run|execute|delete|fetch|visit|reset|grant|upload)\b",
            _F,
        ),
        0.5,
        "Addresses the AI agent directly and instructs a side-effecting action",
    ),
    (
        "exfil_instruction",
        re.compile(
            r"\b(forward|send|email|upload|post|exfiltrate|leak|share)\b.{0,50}\b(all|every|last \d+|entire|full|recent)\b.{0,40}\b(emails?|messages?|files?|inbox|contacts|credentials|documents?|data|conversations?)\b",
            _F,
        ),
        0.6,
        "Instructs bulk disclosure of mailbox or file content",
    ),
    (
        "secrecy",
        re.compile(
            r"\b(do not|don't|never)\b.{0,30}\b(tell|inform|notify|mention|alert|show)\b.{0,20}\b(the )?(user|human|owner|anyone)\b",
            _F,
        ),
        0.5,
        "Asks the agent to hide actions from the user",
    ),
    (
        "command_execution",
        re.compile(
            r"\b(run|execute)\b.{0,15}(`[^`]+`|\bcurl\b|\bwget\b|\bbash\b|\bpowershell\b|\brm -rf\b)",
            _F,
        ),
        0.5,
        "Instructs command execution",
    ),
    (
        "payment_directive",
        re.compile(
            r"\b(transfer|wire|pay|refund)\b.{0,30}(?:₹|rs\.?|inr|\$|usd|eur)\s?\d[\d,]*", _F
        ),
        0.3,
        "Directs a payment",
    ),
    (
        "fake_authority_marker",
        re.compile(
            r"\[(system|admin|developer|assistant)\]|<\s*(system|instructions?)\s*>|#{2,}\s*(system|instruction)",
            _F,
        ),
        0.45,
        "Imitates a system or developer message boundary",
    ),
    (
        "markdown_exfil",
        re.compile(r"!\[[^\]]*\]\(https?://[^)\s]*[?&][^)\s]*=", _F),
        0.5,
        "Markdown image that can leak data through its URL",
    ),
    (
        "multilingual_directive",
        re.compile(
            r"\b(reenv[ií]a|env[ií]a|envoyez|transf[eé]rez|leiten sie|senden sie|bhejo|forward kar)\b",
            _F,
        ),
        0.4,
        "Imperative send/forward verb in another language",
    ),
]


def noisy_or(weights: list[float]) -> float:
    p = 1.0
    for w in weights:
        p *= 1 - w
    return round(1 - p, 4)


def scan_injection(text: str) -> tuple[float, list[Signal]]:
    """Return ``(risk_score, signals)`` for text that is about to enter an agent's context."""
    norm = normalize(text)
    signals: list[Signal] = []
    for name, pattern, weight, detail in _PATTERNS:
        m = pattern.search(norm.text)
        if m:
            snippet = m.group(0)[:90].replace("\n", " ")
            signals.append(Signal(name=name, weight=weight, detail=f"{detail}: “{snippet}”"))
    if norm.invisible_chars >= 3:
        signals.append(
            Signal(
                name="invisible_characters",
                weight=0.35,
                detail=f"{norm.invisible_chars} zero-width / tag characters hide content",
            )
        )
    if norm.hidden_html:
        signals.append(
            Signal(
                name="hidden_html_text",
                weight=0.4,
                detail="Text styled to be invisible to humans (display:none, white-on-white, font-size:0)",
            )
        )
    if norm.decoded_blobs and any(s.name != "payment_directive" for s in signals):
        signals.append(
            Signal(
                name="encoded_payload",
                weight=0.4,
                detail="Instruction-bearing content was base64-encoded",
            )
        )
    return noisy_or([s.weight for s in signals]), signals
