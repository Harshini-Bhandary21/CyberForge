"""Registry of tools an agent may call, with their risk classification.

Every tool the shield mediates is classified by *category* (what kind of side effect it has) and
*risk*. ``control_args`` are the arguments that decide *where* or *how much* an action acts
(recipient, URL, command, amount...). Those are the arguments untrusted content must never
silently dictate; free-text ``data`` arguments (message bodies) are checked by DLP instead.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from agentshield.core.models import Risk

Category = Literal["read", "write", "egress", "network", "exec", "financial", "admin"]


class ToolSpec(BaseModel):
    name: str
    category: Category
    risk: Risk
    control_args: tuple[str, ...] = ()
    description: str = ""

    @property
    def egress(self) -> bool:
        """True when the call can move data out of the organisation."""
        return self.category in {"egress", "network"}


_SPECS = [
    ToolSpec(
        name="read_inbox", category="read", risk=Risk.LOW, description="Read mailbox messages"
    ),
    ToolSpec(
        name="read_file",
        category="read",
        risk=Risk.LOW,
        control_args=("path",),
        description="Read a local file",
    ),
    ToolSpec(
        name="search_web", category="read", risk=Risk.LOW, description="Search the public web"
    ),
    ToolSpec(
        name="summarize", category="read", risk=Risk.LOW, description="Summarise provided text"
    ),
    ToolSpec(
        name="fetch_url",
        category="network",
        risk=Risk.MEDIUM,
        control_args=("url",),
        description="HTTP GET a URL",
    ),
    ToolSpec(
        name="write_file",
        category="write",
        risk=Risk.MEDIUM,
        control_args=("path",),
        description="Write a file",
    ),
    ToolSpec(
        name="commit_code",
        category="write",
        risk=Risk.MEDIUM,
        control_args=("repo", "branch"),
        description="Commit code",
    ),
    ToolSpec(
        name="send_email",
        category="egress",
        risk=Risk.HIGH,
        control_args=("to", "cc", "bcc"),
        description="Send an email",
    ),
    ToolSpec(
        name="reply_email",
        category="egress",
        risk=Risk.HIGH,
        control_args=("to", "cc", "bcc"),
        description="Reply to an email",
    ),
    ToolSpec(
        name="forward_email",
        category="egress",
        risk=Risk.HIGH,
        control_args=("to", "cc", "bcc"),
        description="Forward email(s)",
    ),
    ToolSpec(
        name="issue_refund",
        category="financial",
        risk=Risk.HIGH,
        control_args=("payee", "amount", "account"),
        description="Refund a customer",
    ),
    ToolSpec(
        name="reset_password",
        category="admin",
        risk=Risk.HIGH,
        control_args=("user",),
        description="Reset a user's password",
    ),
    ToolSpec(
        name="transfer_funds",
        category="financial",
        risk=Risk.CRITICAL,
        control_args=("payee", "amount", "account"),
        description="Move money",
    ),
    ToolSpec(
        name="run_shell",
        category="exec",
        risk=Risk.CRITICAL,
        control_args=("command",),
        description="Run a shell command",
    ),
    ToolSpec(
        name="change_permissions",
        category="admin",
        risk=Risk.CRITICAL,
        control_args=("user", "role"),
        description="Change access rights",
    ),
    ToolSpec(
        name="delete_records",
        category="write",
        risk=Risk.CRITICAL,
        control_args=("target",),
        description="Delete records",
    ),
]

REGISTRY: dict[str, ToolSpec] = {s.name: s for s in _SPECS}

READ_ONLY = ["read_inbox", "read_file", "search_web", "summarize"]


def get_spec(name: str) -> ToolSpec | None:
    return REGISTRY.get(name)


def all_specs() -> list[ToolSpec]:
    return list(REGISTRY.values())
