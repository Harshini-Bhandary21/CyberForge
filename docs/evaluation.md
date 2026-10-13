# Evaluation

Reproduce with `make redteam` (CLI) or the **Red Team** page. Deterministic given the seed.

## Method

- **Corpus**: 28 attack payloads in 9 categories (email/URL exfiltration, financial fraud, code execution, privilege escalation, data destruction, credential theft, social engineering, in-scope abuse), in `backend/src/agentshield/modules/redteam/data/payloads.json`.
- **Evasion techniques (9)**: plain, base64, zero-width characters, hidden HTML, HTML comment, fake system tags, role-play framing, multilingual framing, payload fragmented across two documents.
- **Hosts (6)**: realistic tasks (summarise inbox, reply to a named colleague, issue a refund, web research, fix-and-commit, forward an invoice), each with its own goal, documents and legitimate tool calls.
- **Attacker model**: a deterministic *fully compliant* agent (`simulated_agent.py`) that tries to execute any instruction it can read after decoding, de-obfuscating and understanding a few languages. It does not resist, so it measures the worst case the shield must survive.
- **Metrics**: *attack success rate* (ASR: an attacker-targeted tool call receives `allow`); baseline ASR = the agent got hijacked with no shield; *false-block rate* on the legitimate tool calls of all hosts; approval friction; per-call latency.
- **Ablations**: full shield, without capability tokens, without taint tracking, without the intent verifier, capabilities only.

## Typical result (900 cases, heuristic engine)

| | ASR | False blocks |
|---|---|---|
| Unprotected agent | ~85% | n/a |
| Full shield | <1% | 0% |
| Capabilities only | ~9% | 0% |
| Without taint tracking | ~2% | 0% |

Guard overhead is ~0.15 ms per call (p95 ~0.2 ms) on a laptop.

## What this does and does not show

- It shows the layers are **complementary** (capabilities alone leave a gap; taint and intent close it) and that the policy **does not break legitimate tasks** in the bundled hosts.
- Layers are partly **redundant** on this corpus (most attacks introduce an attacker-chosen recipient, which several layers catch). Redundancy is a feature in production but means single-layer ablations understate each layer's value.
- The corpus and the attacker model are **self-authored**. Treat the numbers as a **regression benchmark** for this codebase, not as a claim of absolute security or of performance against a particular production LLM. The harness is designed so a live-LLM agent can be substituted for the simulated one.
- The remaining breaches are **semantic manipulation through an authorised channel** (see threat model). They are shown deliberately.
- The false-block rate is measured on six hosts; broaden it with real workloads before trusting it.

## Unit and integration tests

`cd backend && .venv/bin/pytest`: 31 tests covering policy rules, taint, approvals, quarantine, audit-chain tamper detection, phishing, fraud, anomaly, code guard, compliance, the red-team harness, Dojo grading and the HTTP API.
