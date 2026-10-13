# AgentShield

**Runtime security for AI agents.** AgentShield sits between an AI agent and the tools it can call. Every action is judged on *who chose its target*, *whether the user asked for it*, *what data it carries* and *how risky it is*. Everything is written to a tamper-evident audit log that doubles as compliance evidence.

> Built for the *AI & Cybersecurity* challenge. One core (the Injection Firewall) with the other themes as modules that read from and write to the same action stream.

## The problem

Organisations are giving LLM agents inboxes, ticket queues, code repos and payment tools. **Indirect prompt injection** (instructions hidden in an email, web page or document the agent reads) turns those agents into insiders. Input classifiers ("does this text look malicious?") are easy to evade and noisy. AgentShield judges **actions, not text**.

## How it works

```
 untrusted input ─► Phishing / injection scanner ─┐ labels context trusted · untrusted · hostile
                                                  ▼
 user goal ─────────────────────────────►  GUARD (one choke point per tool call)
                                              1. Provenance (taint): did untrusted content choose the recipient / URL / command / amount?
                                              2. Intent verifier: isolated judge sees ONLY goal + action (never untrusted text)
                                              3. Capability tokens: least-privilege tools derived from the goal
                                              4. DLP (secrets, PII) + Fraud scoring (amount, payee, velocity, off-hours)
                                              5. Human-in-the-loop for critical tools; blocks can never be approved away
                                                  │ allow · require approval · block
                                                  ▼
                                    Hash-chained audit log ─► Anomaly engine · Incident copilot · Compliance autopilot
```

## Modules (the challenge themes)

| Theme | Module | What it does |
|---|---|---|
| AI Security | **Injection Firewall** (core) | Taint tracking, isolated intent verifier, capability tokens, approvals |
| Phishing Detection | **Social-Engineering Scanner** | Look-alike domains, display-name spoofing, link deception, BEC / credential / payment lures, agent-targeted instructions |
| Threat Detection | **Behaviour Engine** | Per-agent baselines (UEBA for agents): new tool, new destination, bursts, data volume, off-hours; baselines learn only from allowed calls |
| AI-assisted SecOps | **Incident Copilot** | Correlates events into one scored incident with a narrative, timeline and one-click containment (quarantine, revoke tool, block source) |
| Vulnerability Detection | **Code & Config Guard** | Insecure code patterns, hard-coded secrets, typosquatted / hallucinated packages, over-permissive agent configs |
| Compliance Automation | **Evidence Autopilot** | Maps the audit log to OWASP LLM Top 10, NIST AI RMF, EU AI Act and ISO 27001 controls with citations to log entries |
| Fraud Detection | **Fraud Guard** | Transaction risk scoring and step-up approval, bot-timing detection, signed agent identity |
| Security Awareness | **Injection Dojo** | Five-level "hack the agent" game and graded phishing simulations |
| (measurement) | **Red-team harness** | Replays 28 attack payloads × 9 evasion techniques × 6 tasks, with and without the shield, and ablates each defence layer |

## Quick start

Requirements: Python 3.11+, Node 20+. No key needed: with none, everything runs on offline heuristics. Optional: `GROQ_API_KEY`, `GEMINI_API_KEY` and/or `ANTHROPIC_API_KEY` enable an LLM-backed isolated verifier (first available provider wins, with failover); `DATABASE_URL` switches SQLite to PostgreSQL. Copy `.env.example` to `.env`, then `make doctor ARGS=--live` verifies your keys.

```bash
make install        # backend venv + frontend deps
make dev            # API on :8000, dashboard on :5173
# open http://localhost:5173 and click "Run demo scenario"
```

Or without the UI: `make demo` (prints the scripted scenario) and `make redteam` (attack campaign). Docker (Postgres + API + dashboard): set `POSTGRES_PASSWORD` in `.env`, run `make docker`, open http://localhost:8080 (the login is printed on first run).

## Using it from your own agent

```python
import httpx
api = httpx.Client(base_url="http://localhost:8000/api/v1")

sid = api.post("/sessions", json={"agent_id": "my-agent", "user_goal": "Summarize my unread emails."}).json()["id"]
api.post(f"/sessions/{sid}/context", json={"source": "email:x@y.com", "kind": "email", "content": email_body})

# before executing ANY tool the model asked for:
d = api.post(f"/sessions/{sid}/guard", json={"tool": "forward_email", "args": {"to": "x@evil.example"}}).json()
if d["verdict"] != "allow":   # "block" or "require_approval" (poll /approvals, retry with approval_id)
    ...                       # do not execute
```

Interactive API docs: http://localhost:8000/docs.

## Results (reproducible: `make redteam`)

On the bundled corpus (heuristic verifier, 900 sampled cases): attack success **~85% without the shield → <1% with it**, **0% false blocks** and **~0.2 ms** added per call. Ablations show which layer matters, and the report lists the breaches that remain. See [docs/evaluation.md](docs/evaluation.md) for what these numbers do and do not prove.

## Repository layout

```
backend/            FastAPI service (Python 3.11+)
  src/agentshield/
    core/           models · tools registry · taint · intent · verifier · dlp · policy · guard · sessions · approvals
    modules/        phishing · anomaly · incidents · fraud · codeguard · compliance · redteam · dojo
    storage/        SQLite document store + hash-chained audit log
    api/            routers (guard, modules, system) and dependencies
    services/       cross-module roll-ups (risk score)
    demo/           scripted end-to-end scenario
  tests/            pytest suite (guard, modules, API)
frontend/           React + TypeScript + Tailwind dashboard (Vite)
docs/               architecture · threat model · evaluation · demo script
```

## Documentation

- [Architecture](docs/architecture.md): components, data flow, design decisions
- [Security & configuration](docs/security.md): database, Gemini/Groq/Anthropic providers, auth roles, hardening, production checklist
- [Threat model](docs/threat-model.md): what is defended, and what is not
- [Evaluation](docs/evaluation.md): method, results, honest limitations
- [Demo script](docs/demo-script.md): a 4-minute walkthrough
- [Contributing](CONTRIBUTING.md)

## Honest scope

This is a hackathon-grade reference implementation. The detectors are heuristic and interpretable by design; the LLM verifier is optional. It does not replace sandboxing, network egress controls or identity management, and it cannot judge *semantic* manipulation inside an action the user authorised. See the threat model.

## License

Apache-2.0
