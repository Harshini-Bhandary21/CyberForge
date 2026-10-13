"""Storage backends and the factory that selects one from configuration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentshield.storage.store import Store

if TYPE_CHECKING:
    from agentshield.storage.postgres import PostgresStore


def open_store(database_url: str | None, sqlite_path: str = ":memory:") -> Store | PostgresStore:
    """``postgresql://…`` → PostgreSQL; ``sqlite:///path`` or a bare path → SQLite."""
    url = (database_url or "").strip()
    if url.startswith(("postgresql://", "postgres://")):
        from agentshield.storage.postgres import PostgresStore

        return PostgresStore(url)
    if url.startswith("sqlite:///"):
        return Store(url.removeprefix("sqlite:///") or ":memory:")
    return Store(url or sqlite_path)
