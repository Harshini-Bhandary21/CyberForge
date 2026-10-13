"""Session risk: Bayesian evidence accumulation across a whole session.

Per-call rules judge one action at a time, so a slow attack (read poisoned content, read private
data, then exfiltrate in a later, innocuous-looking call) can slip under each individual
threshold. Here every observation is a log-likelihood ratio (LLR) for the hypothesis "this session
is being steered by an attacker". Evidence is summed in log-odds space on top of a low prior, with
older evidence decayed, and the posterior probability gates risky actions.

Pure arithmetic over data already in the session: deterministic, explainable, no model involved.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from agentshield.core.models import Session, Trust

PRIOR_LOG_ODDS = math.log(0.04 / 0.96)  # ~4% of sessions are attacked
DECAY = 0.97  # per later observation: recent evidence counts a little more
PRIVATE_READ_TOOLS = frozenset({"read_inbox", "read_file"})

APPROVAL_P = 0.5
BLOCK_P = 0.93


@dataclass
class RiskAssessment:
    probability: float
    log_odds: float
    reasons: list[str] = field(default_factory=list)


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def assess(session: Session) -> RiskAssessment:
    terms: list[tuple[float, str]] = []
    untrusted = [i for i in session.context if i.trust != Trust.TRUSTED]

    for item in untrusted:
        # A clean item is mild evidence of safety; a suspicious one grows fast with its score.
        llr = 4.0 * (item.risk_score - 0.25)
        if item.trust == Trust.HOSTILE:
            llr += 2.0
        if llr > 0.3:
            terms.append((llr, f"suspicious content from {item.source} ({item.risk_score:.2f})"))
        else:
            terms.append((llr, ""))

    if session.blocked_count:
        terms.append(
            (min(1.5 * session.blocked_count, 4.5), f"{session.blocked_count} action(s) blocked")
        )

    read_private = any(t in PRIVATE_READ_TOOLS for t in session.tool_history)
    if untrusted and read_private:
        # Untrusted input + access to private data: the precondition for exfiltration.
        terms.append((0.8, "untrusted content and private data in the same session"))

    n = len(terms)
    total = PRIOR_LOG_ODDS
    reasons: list[str] = []
    for i, (llr, why) in enumerate(terms):
        total += llr * DECAY ** (n - 1 - i)
        if why:
            reasons.append(why)
    return RiskAssessment(round(_sigmoid(total), 4), round(total, 3), reasons)
