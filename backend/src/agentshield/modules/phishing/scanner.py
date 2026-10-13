"""Social-Engineering Scanner: phishing, business-email-compromise and AI-written lure detection.

Signals are interpretable and combined with a noisy-OR. Stylometric "AI-written" cues are weak by
design (no reliable detector exists); the strong signals are structural: sender/domain mismatch,
look-alike domains, credential or payment requests, pressure, and link deception.
"""

from __future__ import annotations

import re
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from agentshield.core.detectors import noisy_or, scan_injection
from agentshield.core.intent import EMAIL_RE, URL_RE
from agentshield.core.models import Signal

BRANDS = {
    "microsoft": "microsoft.com",
    "office365": "office.com",
    "google": "google.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "sbi": "sbi.co.in",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "linkedin": "linkedin.com",
    "dropbox": "dropbox.com",
    "docusign": "docusign.com",
    "github": "github.com",
    "slack": "slack.com",
    "zoom": "zoom.us",
}
FREE_MAIL = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "proton.me",
    "protonmail.com",
    "rediffmail.com",
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}
RISKY_TLDS = {
    "zip",
    "mov",
    "xyz",
    "top",
    "click",
    "country",
    "gq",
    "tk",
    "ml",
    "cf",
    "support",
    "work",
}

_URGENCY = re.compile(
    r"\b(urgent(ly)?|immediately|right away|asap|within \d+ (hours?|minutes?)|expires? (today|soon|in)|final notice|last warning|account (will be )?(suspended|locked|closed)|act now|time[- ]sensitive)\b",
    re.I,
)
_AUTHORITY = re.compile(
    r"\b(ceo|cfo|chief executive|managing director|director|it (support|department|helpdesk)|security team|hr department|payroll|compliance officer|bank|tax department|legal department)\b",
    re.I,
)
_CREDENTIAL = re.compile(
    r"\b(verify your (account|identity|password)|confirm your (password|credentials|login)|log ?in (here|now|to (verify|confirm|restore))|update your (password|payment|billing)|enter your (password|otp|pin)|re-?authenticate|share (the )?otp|one[- ]time (password|code))\b",
    re.I,
)
_PAYMENT = re.compile(
    r"\b(wire transfer|gift cards?|bitcoin|crypto(currency)?|change (of )?bank (details|account)|new bank account|invoice (attached|overdue)|urgent payment|pay(ment)? (today|now|immediately)|upi)\b",
    re.I,
)
_SECRECY = re.compile(
    r"\b(confidential|keep (this|it) (between us|private|secret)|do not (share|discuss|tell)|don't (share|discuss|tell)|i('m| am) (in a meeting|unavailable)|can('|’)t talk)\b",
    re.I,
)
_THREAT = re.compile(
    r"\b(legal action|penalt(y|ies)|suspend(ed)?|terminated?|arrest|fine of|compromised|unauthori[sz]ed (access|login|activity))\b",
    re.I,
)
_LLM_STYLE = re.compile(
    r"\b(i hope this (message|email) finds you well|please (do )?not hesitate to|kindly (find|note|review|confirm)|at your earliest convenience|rest assured|i am writing to (inform|notify|urgently))\b",
    re.I,
)
_ANCHOR = re.compile(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)


class EmailInput(BaseModel):
    sender: str = ""
    reply_to: str = ""
    subject: str = ""
    body: str = ""
    headers: dict[str, str] = Field(
        default_factory=dict
    )  # e.g. {"spf":"fail","dkim":"none","dmarc":"fail"}


class ScanResult(BaseModel):
    score: float
    verdict: Literal["benign", "suspicious", "malicious"]
    signals: list[Signal]
    recommended_action: str
    injection_score: float = 0.0
    tactics: list[str] = Field(default_factory=list)


def _lev(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment): a swapped pair of letters costs one edit."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def _deconfuse(s: str) -> str:
    return s.replace("rn", "m").replace("0", "o").replace("1", "l").replace("vv", "w")


def _registrable(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "ac", "gov"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _lookalike(domain: str) -> tuple[str, str] | None:
    reg = _registrable(domain)
    label = reg.split(".")[0]
    for brand, real in BRANDS.items():
        if reg == real:
            return None
        if label == brand:
            if reg.split(".")[-1] in RISKY_TLDS:  # paypal.xyz
                return brand, real
            continue  # same brand on another legitimate TLD (amazon.in)
        if _deconfuse(label) == brand or (len(brand) >= 5 and _lev(label, brand) == 1):
            return brand, real  # paypa1.com, micros0ft.com
        if brand in label:  # paypal-secure-login.com
            return brand, real
    return None


def scan_email(mail: EmailInput) -> ScanResult:
    text = f"{mail.subject}\n{mail.body}"
    sig: list[Signal] = []
    tactics: set[str] = set()

    def add(name: str, w: float, detail: str, tactic: str | None = None) -> None:
        sig.append(Signal(name=name, weight=w, detail=detail))
        if tactic:
            tactics.add(tactic)

    sender_match = EMAIL_RE.search(mail.sender)
    sender_domain = sender_match.group(0).split("@")[-1].lower() if sender_match else ""
    display = re.sub(r"<.*?>", "", mail.sender).strip().lower()

    # --- sender analysis
    if sender_domain:
        look = _lookalike(sender_domain)
        if look:
            add(
                "lookalike_sender_domain",
                0.75,
                f"Sender domain '{sender_domain}' imitates {look[1]}",
                "impersonation",
            )
        for brand, real in BRANDS.items():
            if brand in display and _registrable(sender_domain) != real and not look:
                add(
                    "display_name_spoof",
                    0.65,
                    f"Display name claims '{brand}' but mail comes from {sender_domain}",
                    "impersonation",
                )
                break
        if sender_domain in FREE_MAIL and _AUTHORITY.search(display + " " + mail.subject):
            add(
                "authority_from_freemail",
                0.5,
                "Executive/department identity sent from a free mail provider",
                "impersonation",
            )
        if sender_domain.startswith("xn--") or ".xn--" in sender_domain:
            add(
                "punycode_domain",
                0.6,
                "Sender domain uses punycode (possible homograph attack)",
                "impersonation",
            )
    reply_match = EMAIL_RE.search(mail.reply_to)
    if reply_match:
        rt = reply_match.group(0).split("@")[-1].lower()
        if sender_domain and _registrable(rt) != _registrable(sender_domain):
            add(
                "reply_to_mismatch",
                0.55,
                f"Replies are routed to a different domain ({rt})",
                "redirection",
            )
    for mech in ("spf", "dkim", "dmarc"):
        if mail.headers.get(mech, "").lower() in {"fail", "softfail", "none"}:
            add(
                f"{mech}_{mail.headers[mech].lower()}",
                0.3 if mech != "dmarc" else 0.4,
                f"{mech.upper()} check: {mail.headers[mech]}",
                "authentication",
            )

    # --- link analysis
    urls = list(dict.fromkeys(URL_RE.findall(mail.body)))
    for href, label in _ANCHOR.findall(mail.body):
        shown = URL_RE.search(label)
        if shown and urlparse(shown.group(0)).hostname != urlparse(href).hostname:
            add(
                "link_text_mismatch",
                0.8,
                f"Link text shows {urlparse(shown.group(0)).hostname} but goes to {urlparse(href).hostname}",
                "link_deception",
            )
        urls.append(href)
    for u in dict.fromkeys(urls):
        host = (urlparse(u).hostname or "").lower()
        if not host:
            continue
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            add(
                "ip_address_url", 0.6, f"Link points to a raw IP address ({host})", "link_deception"
            )
        elif host in SHORTENERS:
            add(
                "url_shortener",
                0.35,
                f"Shortened link hides destination ({host})",
                "link_deception",
            )
        elif look := _lookalike(host):
            add(
                "lookalike_link_domain",
                0.7,
                f"Link domain '{host}' imitates {look[1]}",
                "link_deception",
            )
        elif host.split(".")[-1] in RISKY_TLDS:
            add(
                "risky_tld",
                0.25,
                f"Link uses a high-abuse TLD (.{host.split('.')[-1]})",
                "link_deception",
            )
        if host.count(".") >= 4:
            add("excess_subdomains", 0.3, f"Deeply nested subdomain ({host})", "link_deception")

    # --- content analysis
    for name, rx, w, tactic, label in (
        ("urgency", _URGENCY, 0.3, "pressure", "Pressure / artificial deadline"),
        ("authority_claim", _AUTHORITY, 0.15, "authority", "Claims organisational authority"),
        (
            "credential_request",
            _CREDENTIAL,
            0.55,
            "credential_theft",
            "Asks the reader to verify or enter credentials",
        ),
        (
            "payment_request",
            _PAYMENT,
            0.5,
            "payment_fraud",
            "Unusual payment / bank-detail request",
        ),
        ("secrecy", _SECRECY, 0.35, "isolation", "Asks for confidentiality or avoids verification"),
        ("threat", _THREAT, 0.3, "fear", "Threat or consequence language"),
    ):
        m = rx.search(text)
        if m:
            add(name, w, f"{label}: “{m.group(0)[:60]}”", tactic)
    style_hits = len(_LLM_STYLE.findall(text))
    if style_hits >= 2:
        add(
            "llm_style_phrasing",
            0.12,
            f"{style_hits} boilerplate phrases typical of machine-written lures (weak signal)",
            "ai_generated",
        )

    inj_score, inj_signals = scan_injection(text)
    if inj_score >= 0.4:
        add(
            "agent_targeted_instructions",
            min(0.8, inj_score),
            "Contains instructions aimed at an AI assistant reading this mail",
            "agent_hijack",
        )
        sig.extend(
            s for s in inj_signals if s.weight >= 0.4 and s.name not in {x.name for x in sig}
        )

    score = noisy_or([s.weight for s in sig])
    verdict = "malicious" if score >= 0.75 else "suspicious" if score >= 0.45 else "benign"
    action = {
        "malicious": "Quarantine the message, mark all content as hostile for agents, and notify the SOC.",
        "suspicious": "Deliver with a warning banner; require human approval for any agent action it influences.",
        "benign": "No action required.",
    }[verdict]
    return ScanResult(
        score=score,
        verdict=verdict,
        signals=sig,
        recommended_action=action,
        injection_score=inj_score,
        tactics=sorted(tactics),
    )
