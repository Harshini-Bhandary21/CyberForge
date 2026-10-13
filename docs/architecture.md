# Architecture

## Principle: judge actions, not text

An agent that reads attacker-controlled text will sometimes obey it. Detecting that text is a losing arms race; **constraining what the agent can do as a result** is tractable. So AgentShield is a *policy decision point* that every tool call must pass through, and the decision is built from evidence that does not depend on classifying the attacker's prose.

## Request flow

1. **Session start** (`POST /sessions`): the user's goal is analysed (`core/intent.py`) and a **least-privilege capability set** is derived (read-only unless the goal asks for a side effect). A signed agent identity may be verified.
2. **Context ingestion** (`POST /sessions/{id}/context`): every item the agent will read is normalised (`core/normalize.py`: strip invisible characters, flatten HTML including hidden text, decode base64) and scanned (`core/detectors.py`, plus `modules/phishing` for email). Items score as `untrusted` or `hostile`. The scan is advisory: it tightens policy but is never the only barrier.
3. **Guard** (`POST /sessions/{id}/guard`, `core/guard.py`) runs, for one proposed tool call:
   - **Taint trace** (`core/taint.py`): for each *control argument* (recipient, URL, command, amount…) extract concrete values and test whether they appear in untrusted content but **not** in anything the user wrote. If so, untrusted content chose the target. Free-text *data* arguments are checked for verbatim reuse of untrusted text.
   - **Intent verifier** (`core/verifier.py`): "would a faithful assistant doing only what the user asked take this action?" The judge receives the goal and the action only, **never untrusted content**, so it cannot itself be injected. LLM judge (Claude Haiku 5.5) when a key is configured, deterministic heuristic otherwise; the stricter verdict wins.
   - **DLP** (`core/dlp.py`) for secrets and PII in outbound calls; **Fraud Guard** (`modules/fraud`) for money movement.
   - **Policy engine** (`core/policy.py`): small named rules (`R-CAP-001`, `R-TAINT-001`, `R-INTENT-001`, `R-DLP-001`, `R-FRAUD-001`, `R-HITL-001`…) emit findings; the verdict is the most severe finding. Each rule can be toggled, which is how the red-team harness ablates layers.
   - **Approvals** (`core/approvals.py`): `require_approval` creates a pending request bound to the exact arguments. An approval can release a held action, never a blocked one.
4. **Side effects of a decision:** behavioural anomaly detection, incident correlation, and an append-only audit event.

## Components

| Component | Path | Notes |
|---|---|---|
| Domain models | `core/models.py` | Pydantic; `Trust`, `Verdict`, `Risk`, `GuardDecision` |
| Tool registry | `core/tools.py` | Category, risk, and which args are *control* args per tool |
| Storage | `storage/store.py` | SQLite (WAL). Generic document collections + `events` table with a SHA-256 hash chain; `verify_chain()` detects tampering |
| Wiring | `container.py` | One `Container` per `Store`. The red-team harness builds throw-away containers over `:memory:` stores so campaigns never touch real data |
| API | `api/`, `main.py` | FastAPI, versioned under `/api/v1`, optional `X-API-Key` |
| Dashboard | `frontend/` | React + TanStack Query; polls the API |

## Design decisions

- **Provenance beats classification.** "Did untrusted text choose this recipient?" is a structural question with a precise answer, and works across languages and encodings because values (addresses, URLs) are language-independent.
- **Isolation for the judge.** The verifier is the only LLM in the decision path and is architecturally prevented from seeing attacker text.
- **Fail closed, degrade gracefully.** LLM errors return "no opinion" and the heuristic verdict stands; an LLM outage can never open a hole.
- **Baselines learn only from allowed calls.** An attacker cannot teach the anomaly or fraud engines that their behaviour is normal.
- **Evidence is a by-product.** Because every decision is a hash-chained event, compliance reports are computed from the log with citations rather than written by hand.
- **Explainable rules over opaque scores.** Every block names the rule, the evidence and the value that triggered it.

## Scaling notes (out of scope for the demo)

SQLite → Postgres (the `Store` interface is small); the guard is stateless apart from the store and horizontally scalable; ship events to a SIEM; put the guard in-process as a library or as a sidecar to remove a network hop (measured guard latency is well under a millisecond).
