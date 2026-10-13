# Threat model

## Assets
Mailbox and documents the agent can read; money the agent can move; systems it can change (shell, permissions, records); credentials in its environment; the audit log.

## Adversaries
1. **External attacker** who can place content in front of the agent (email, web page, shared doc, ticket, tool output) but cannot talk to the agent directly.
2. **Malicious or compromised insider/vendor** feeding poisoned data.
3. **Curious or erroneous agent** exceeding its remit without any attacker at all.

## In scope (and the control)

| Threat | Control |
|---|---|
| Indirect prompt injection triggers exfiltration (forward/send/fetch with data) | Taint trace + intent verifier + capability tokens + DLP |
| Injection triggers payments, refunds, permission changes, shell, deletes | Capabilities, taint, intent, fraud scoring, mandatory human approval for critical tools |
| Obfuscated payloads (base64, zero-width, hidden HTML, other languages, fragmented across documents) | Normalisation before analysis; value-based taint is language- and encoding-independent |
| Business-email-compromise relayed by the agent (bank-detail changes) | R-TAINT-004: payment instructions copied from untrusted text into an outbound message need approval |
| Secrets leaking in outbound payloads | DLP (keys, tokens, JWT, private keys, card numbers with Luhn, PAN/Aadhaar) |
| Phishing aimed at humans or agents | Social-engineering scanner (structural signals; stylometry is a weak signal only) |
| Slow drift / compromised agent | Behaviour engine (new tool/destination, bursts, volume, off-hours); baselines resist poisoning |
| Agent impersonation | HMAC-signed agent identity (optional enforcement) |
| Tampering with evidence | SHA-256 hash-chained audit log with verification |
| Insecure code / dependencies produced by coding agents | Code & Config Guard (patterns, secrets, typosquat and hallucinated packages) |

## Out of scope / known gaps (be explicit)

- **Semantic manipulation inside an authorised action.** If the user asked the agent to reply to Priya and an attacker persuades it to say "the meeting moved to Monday", every action-level control sees a legitimate reply to a legitimate recipient. The red-team report lists these as residual breaches. Mitigations are output review, approval for external communication, and provenance-aware UX; not something this layer can decide.
- **Compromise of the guard, its host or the store.** The hash chain is tamper-*evident*, not tamper-*proof*; anchor the head hash externally for stronger guarantees.
- **An agent that bypasses the guard** (calls tools directly). AgentShield only governs calls routed through it; deployments must make it the only path to credentials and tools (network egress controls, credential brokering).
- **Model-level attacks** (jailbreaks that change the model's outputs but not its actions) and training-data poisoning.
- **Heuristic coverage.** Detectors are interpretable rules; novel phrasing can evade the *input scan*. That is why decisive controls are action-level.
- **Denial of service** beyond basic size and rate limits (OWASP LLM10 is only partly addressed).
- **Multi-tenant isolation and user accounts/SSO** are not implemented (role-scoped API keys only); see [security.md](security.md).
- **Third-party LLM providers** see the goal and control arguments (secrets redacted, free text omitted); disable with `AGENTSHIELD_USE_LLM=false` if that is unacceptable.

## Trust boundaries
`untrusted content → [normalise, scan, label] → agent context`  ·  `agent → [guard] → tools`  ·  `guard → [audit log]`. The intent verifier sits on the guard side of the boundary and never receives untrusted content.
