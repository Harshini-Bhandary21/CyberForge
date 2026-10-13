# Security, database and LLM-provider configuration

## 1. Database

| Backend | When | Configure |
|---|---|---|
| SQLite (default) | demos, tests, single node | `AGENTSHIELD_DB_PATH=data/agentshield.db` (or `:memory:`) |
| PostgreSQL | anything shared or long-lived | `DATABASE_URL=postgresql://user:pass@host:5432/agentshield` |

Both implement the same interface (`backend/src/agentshield/storage/`), selected by `open_store()`.

- **Schema** is created on start (`CREATE TABLE IF NOT EXISTS`): `docs` (collections of JSON documents) and `events` (the audit log). For schema evolution adopt a migration tool (Alembic) before changing tables.
- **Audit chain on Postgres**: each event is appended inside a transaction holding a Postgres advisory lock, so several API workers cannot fork the SHA-256 chain. Covered by a concurrency test (4 threads × 15 appends → one valid chain).
- **Pooling**: `psycopg_pool` (1–10 connections). All SQL is parameterised.
- **Docker Compose** runs Postgres 17 on a private network (port not published) with a persistent volume; `POSTGRES_PASSWORD` is mandatory.
- Verify: `make doctor`.
- Run the Postgres tests: `TEST_DATABASE_URL=postgresql://user@localhost:5432/test_db pytest` (skipped when unset).
- Not covered: encryption at rest (use disk/volume or managed-database encryption), backups and retention.

## 2. LLM providers (Groq, Gemini, Anthropic)

The LLM is used for exactly two things: the **isolated intent verifier** and short **incident narratives**. Every decision also has a deterministic heuristic fallback, so the product works with no key.

```
AGENTSHIELD_LLM_PROVIDERS=["groq","gemini","anthropic"]   # priority order
GROQ_API_KEY=...        AGENTSHIELD_GROQ_MODEL=llama-3.3-70b-versatile
GEMINI_API_KEY=...      AGENTSHIELD_GEMINI_MODEL=gemini-2.5-flash
ANTHROPIC_API_KEY=...   AGENTSHIELD_JUDGE_MODEL=claude-haiku-5-5
```

- Put keys in `.env` (git-ignored). Keys are held as `SecretStr` (never in logs, reprs or `/overview`) and sent only in request headers (the Gemini key goes in `x-goog-api-key`, never the URL).
- **Order and failover**: the first provider that answers wins; a failing provider is skipped for 30 s (circuit breaker); if all fail, heuristics decide. The verifier records which provider answered (`verifier.provider`), shown in the dashboard.
- **Verify your keys and model names**: `make doctor ARGS=--live` makes one tiny real call per configured provider. Model names change over time; override them with the `*_MODEL` variables if a provider rejects the default.
- **Stricter-of-two**: when the LLM and the heuristic disagree, the stricter verdict wins, so a fooled or manipulated model can only make AgentShield *more* cautious.
- **Data minimisation toward third parties**: the judge receives the user's goal and the action's *control* arguments only (recipient, URL, command, amount…), secrets redacted. Free-text arguments (message bodies) are replaced by their length. No untrusted context ever leaves the process, which is also what keeps the judge unmanipulable.
- Cost/latency: one short call per non-read tool call; reads never call the LLM.

## 3. Security measures

**Authentication & authorisation** (`api/deps.py`)
- `AGENTSHIELD_API_KEYS='{"key":"role"}'` with roles `agent` (create sessions, push context, ask the guard), `analyst` (dashboard: approvals, incidents, scans, campaigns) and `admin` (also demo reset and agent credential issuing).
- Keys are compared in constant time against every candidate; failures return `401` / `403` without revealing which part failed. Keys are identified in logs by a short SHA-256 fingerprint, never by value.
- Approvals and incident actions are attributed to the authenticated key, so a reviewer cannot impersonate another.
- No keys configured = open access (development only). With `AGENTSHIELD_ENV=production` the app **refuses to start** without keys, with the default signing secret, or with wildcard CORS.

**Hardening** (`api/middleware.py`, `main.py`)
- Security headers on every response (`nosniff`, `X-Frame-Options: DENY`, `no-referrer`, strict CSP, `Cache-Control: no-store`, HSTS on HTTPS).
- Request-size cap (413) and rejection of chunked uploads; Pydantic length/pattern limits on user-supplied fields.
- Per-key / per-IP rate limiting (429 + `Retry-After`; in-process, front it with a gateway when you run several replicas).
- CORS restricted to the configured origins and to `GET`/`POST`; OpenAPI docs and the demo endpoints are off in production.

**Data protection**
- **Secrets are never persisted.** The storage layer redacts API keys, tokens, private keys, JWTs, card numbers (Luhn), PAN/Aadhaar and `password=` assignments before anything is written (documents *and* audit events), and before the audit hash is computed. Approvals still bind to the *original* arguments via a hash.
- Outbound DLP blocks calls that carry credentials (`R-DLP-001`).

**Deployment**
- Docker: API container is read-only, drops all capabilities and sets `no-new-privileges`; Postgres is not exposed; the dashboard is served by nginx with basic auth, and the API key is injected by the proxy so it never appears in the browser bundle. For real use, put the dashboard behind SSO/VPN.
- `make docker` creates `deploy/htpasswd` with a random dashboard password on first run.

## 4. Production checklist
1. `AGENTSHIELD_ENV=production`; generate keys with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`; set `AGENTSHIELD_API_KEYS` (one `agent` key per integration, one `analyst` key for the dashboard proxy, one `admin` key kept offline).
2. Set `AGENTSHIELD_AGENT_SIGNING_SECRET` (≥32 random chars) and `AGENTSHIELD_REQUIRE_AGENT_IDENTITY=true` if agents are enrolled.
3. Use PostgreSQL; back it up; anchor the audit head hash externally (e.g. periodically write `GET /events/verify → head` to a write-once store).
4. Terminate TLS in front; restrict CORS to the dashboard origin; run `make doctor`.
5. Rotate provider keys on a schedule; use provider-side spend limits.

## 5. Known gaps
No user accounts/SSO inside the app (API keys + proxy auth only), in-process rate limiter, no encryption at rest, no migration tooling, and secrets in *free text the model invents* are only caught by DLP patterns.
