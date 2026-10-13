# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private reporting:
**Security → Report a vulnerability** on this repository. Include what you found, how to reproduce
it and the impact. You will get an acknowledgement within a few days.

## Supported versions

Only the latest commit on `main` receives fixes.

## Scope and design

How AgentShield defends itself, what it assumes and what it does not cover is documented in
[docs/security.md](docs/security.md) and [docs/threat-model.md](docs/threat-model.md).

## Deploying safely

- Set `AGENTSHIELD_ENV=production`; the API then refuses to start without API keys, with the
  default signing secret, or with wildcard CORS.
- Use distinct keys per role (agent, analyst, admin) and at least two reviewer keys.
- Serve the dashboard over HTTPS (reverse proxy / load balancer) and keep it behind SSO or a VPN.
- Keep `.env` and `deploy/htpasswd` out of version control (already in `.gitignore`).
