# Demo script (about 4 minutes)

Setup: `make dev`, open http://localhost:5173. Optional: `make demo` first to rehearse the story in the terminal.

1. **Frame it (20 s).** "Agents now read our email and can send mail, move money and run commands. An attacker doesn't need to hack us. They just email the agent."
2. **The attack (60 s).** *Live Guard → preset "Hijack: forward inbox".* Show the hidden instruction in a normal-looking email, the context flagged **hostile** with its signals, then the agent's proposed `forward_email` to the attacker. Verdict **Blocked**: point at the taint trace ("the recipient came from this email, not from you"), the isolated verifier ("not in the user's goal") and the capability rule.
3. **No collateral damage (20 s).** Preset "Legit reply": the same agent replies to the person the user named; **Allowed**.
4. **Money (30 s).** *Fraud Guard*: ₹499 refund passes; ₹2.5 lakh to a new payee at 3 am is blocked, with each signal listed.
5. **SOC view (40 s).** *Incidents*: one scored incident with a plain-language narrative, a timeline, and a response plan. Click **Quarantine agent**; show the agent is now blocked everywhere (Agent Behaviour page).
6. **Audit and compliance (30 s).** *Compliance*: controls mapped to OWASP LLM Top 10 / NIST AI RMF / EU AI Act / ISO 27001, each backed by citations to log entries; the audit chain verifies as intact. Download the report.
7. **Measured, not claimed (40 s).** *Red Team → Run campaign*: attack success drops from ~85% to under 1%; show the per-layer ablation and the **honest breaches** that remain.
8. **Awareness (20 s).** *Injection Dojo*: try to beat level 5; spot-the-phish simulation.

Closing line: "One shield, every tool call, evidence by default."

## If something breaks
- Backend not reachable → `make api`; the header shows the status.
- Empty dashboard → click **Run demo scenario** in the top bar (idempotent; reset with `POST /api/v1/demo/reset`).
- No API key → everything runs on the offline heuristic verifier (the sidebar shows which engine is active).
