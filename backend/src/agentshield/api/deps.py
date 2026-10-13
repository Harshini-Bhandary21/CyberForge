"""Dependencies: container access, API-key authentication and role-based authorisation.

Roles
  agent    an AI agent integration: may create sessions, push context and ask the guard for verdicts
  analyst  a human operator: everything an agent can, plus approvals, incidents, scans and campaigns
  admin    everything, including destructive demo reset and issuing agent identity credentials

When no key is configured (local development only) every caller is an anonymous admin; production
start-up refuses that configuration.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request

from agentshield.config import Role
from agentshield.container import Container


def get_container(request: Request) -> Container:
    return request.app.state.container


C = Annotated[Container, Depends(get_container)]


@dataclass(frozen=True)
class Principal:
    id: str
    role: Role


def _fingerprint(key: str) -> str:
    return "key:" + hashlib.sha256(key.encode()).hexdigest()[:8]


def get_principal(request: Request, x_api_key: Annotated[str | None, Header()] = None) -> Principal:
    settings = request.app.state.container.settings
    if not settings.auth_configured:
        return Principal("anonymous", "admin")

    candidates: dict[str, Role] = dict(settings.api_keys)
    if settings.api_key:
        candidates[settings.api_key.get_secret_value()] = "admin"

    match: tuple[str, Role] | None = None
    supplied = (x_api_key or "").encode()
    for key, role in candidates.items():  # compare against all keys: no early exit
        if hmac.compare_digest(supplied, key.encode()) and supplied:
            match = (key, role)
    if match is None:
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid X-API-Key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return Principal(_fingerprint(match[0]), match[1])


def require_role(*roles: Role):
    def dep(principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
        if principal.role not in roles:
            raise HTTPException(
                status_code=403, detail=f"Role '{principal.role}' may not call this endpoint"
            )
        return principal

    return dep


AGENT_ROLES: tuple[Role, ...] = ("agent", "analyst", "admin")
ANALYST_ROLES: tuple[Role, ...] = ("analyst", "admin")

AgentAccess = Depends(require_role(*AGENT_ROLES))
AnalystAccess = Depends(require_role(*ANALYST_ROLES))
AdminAccess = Depends(require_role("admin"))

Analyst = Annotated[Principal, Depends(require_role(*ANALYST_ROLES))]
