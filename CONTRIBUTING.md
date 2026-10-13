# Contributing

## Workflow
```bash
make install
make test      # pytest + frontend typecheck
make lint      # ruff check + format check
```
Backend style: ruff (line length 100), type hints everywhere, Pydantic models at module boundaries. Frontend: strict TypeScript, Tailwind semantic tokens only (no hard-coded colours), status always shown as icon + label.

## Adding a detection rule
1. Put it in the relevant module (`core/detectors.py`, `modules/phishing/scanner.py`, `modules/codeguard/scanner.py`).
2. Give it a stable name and a human-readable explanation; signals must be explainable.
3. Add a positive **and** a negative test (benign input that must not fire).

## Adding a policy rule
Add a rule id (`R-<AREA>-NNN`) in `core/policy.py`, gate it behind a `PolicyConfig` flag so the red-team ablations can switch it off, and add the new id to the rule descriptions in `frontend/src/pages/RedTeam.tsx`.

## Adding a red-team payload
Append to `modules/redteam/data/payloads.json` with a `target` (`tool` + `contains`). If the simulated agent cannot parse the phrasing, extend `simulated_agent.py`. Report breaches honestly; do not tune the corpus to hide them.

## Adding a tool
Register it in `core/tools.py` with category, risk and **control args**. Control args are the ones untrusted content must never choose.
