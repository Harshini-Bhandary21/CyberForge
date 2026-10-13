"""PostgreSQL backend with the same interface as the SQLite ``Store``.

Production notes: connections come from a pool; the audit chain is appended under a
transaction-scoped advisory lock so concurrent API workers cannot fork the hash chain; all
statements are parameterised.
"""

from __future__ import annotations

import json
import time
from typing import Any

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from agentshield.core.dlp import redact_value
from agentshield.storage.store import GENESIS, _canonical, event_hash

_CHAIN_LOCK_KEY = 0x41534844  # "ASHD": arbitrary, stable advisory-lock id for the audit chain

_SCHEMA = """
CREATE TABLE IF NOT EXISTS docs (
    collection TEXT NOT NULL,
    id         TEXT NOT NULL,
    body       TEXT NOT NULL,
    updated    DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (collection, id)
);
CREATE INDEX IF NOT EXISTS idx_docs_collection_updated ON docs(collection, updated DESC);
CREATE TABLE IF NOT EXISTS events (
    id         BIGSERIAL PRIMARY KEY,
    ts         DOUBLE PRECISION NOT NULL,
    type       TEXT NOT NULL,
    session_id TEXT,
    agent_id   TEXT,
    payload    TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_type    ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_agent   ON events(agent_id);
"""


class PostgresStore:
    def __init__(self, url: str, *, min_size: int = 1, max_size: int = 10) -> None:
        self._pool = ConnectionPool(
            url, min_size=min_size, max_size=max_size, kwargs={"row_factory": dict_row}, open=True
        )
        self._pool.wait(timeout=15)
        with self._pool.connection() as conn:
            conn.execute(_SCHEMA)

    def close(self) -> None:
        self._pool.close()

    # ------------------------------------------------------------------ documents
    def put(self, collection: str, doc_id: str, doc: dict[str, Any]) -> None:
        doc = redact_value(doc)  # defence in depth: secrets are never persisted
        with self._pool.connection() as conn:
            conn.execute(
                "INSERT INTO docs(collection,id,body,updated) VALUES(%s,%s,%s,%s) "
                "ON CONFLICT(collection,id) DO UPDATE SET body=EXCLUDED.body, updated=EXCLUDED.updated",
                (collection, doc_id, _canonical(doc), time.time()),
            )

    def get(self, collection: str, doc_id: str) -> dict[str, Any] | None:
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT body FROM docs WHERE collection=%s AND id=%s", (collection, doc_id)
            ).fetchone()
        return json.loads(row["body"]) if row else None

    def list(self, collection: str, limit: int = 200) -> list[dict[str, Any]]:
        with self._pool.connection() as conn:
            rows = conn.execute(
                "SELECT body FROM docs WHERE collection=%s ORDER BY updated DESC LIMIT %s",
                (collection, limit),
            ).fetchall()
        return [json.loads(r["body"]) for r in rows]

    def delete(self, collection: str, doc_id: str) -> None:
        with self._pool.connection() as conn:
            conn.execute("DELETE FROM docs WHERE collection=%s AND id=%s", (collection, doc_id))

    # ------------------------------------------------------------------ audit log
    def append_event(
        self,
        type_: str,
        payload: dict[str, Any],
        *,
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        payload = redact_value(payload)
        with self._pool.connection() as conn, conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (_CHAIN_LOCK_KEY,))
            last = conn.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
            prev = last["hash"] if last else GENESIS
            ts = time.time()
            digest = event_hash(prev, ts, type_, session_id, agent_id, payload)
            row = conn.execute(
                "INSERT INTO events(ts,type,session_id,agent_id,payload,prev_hash,hash) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (ts, type_, session_id, agent_id, _canonical(payload), prev, digest),
            ).fetchone()
        return {
            "id": row["id"],
            "ts": ts,
            "type": type_,
            "session_id": session_id,
            "agent_id": agent_id,
            "payload": payload,
            "hash": digest,
        }

    def events(
        self,
        *,
        session_id: str | None = None,
        agent_id: str | None = None,
        types: list[str] | None = None,
        limit: int = 200,
        oldest_first: bool = False,
    ) -> list[dict[str, Any]]:
        where, args = [], []
        if session_id:
            where.append("session_id=%s")
            args.append(session_id)
        if agent_id:
            where.append("agent_id=%s")
            args.append(agent_id)
        if types:
            where.append("type = ANY(%s)")
            args.append(list(types))
        sql = "SELECT * FROM events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += f" ORDER BY id {'ASC' if oldest_first else 'DESC'} LIMIT %s"
        args.append(limit)
        with self._pool.connection() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [self._to_event(r) for r in rows]

    def count_events(self, type_: str | None = None) -> int:
        with self._pool.connection() as conn:
            if type_:
                row = conn.execute(
                    "SELECT COUNT(*) AS c FROM events WHERE type=%s", (type_,)
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
        return int(row["c"])

    def verify_chain(self) -> dict[str, Any]:
        with self._pool.connection() as conn:
            rows = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
        prev = GENESIS
        for r in rows:
            expected = event_hash(
                prev, r["ts"], r["type"], r["session_id"], r["agent_id"], json.loads(r["payload"])
            )
            if r["prev_hash"] != prev or r["hash"] != expected:
                return {"valid": False, "length": len(rows), "broken_at": r["id"]}
            prev = r["hash"]
        return {
            "valid": True,
            "length": len(rows),
            "head": prev if rows else None,
            "broken_at": None,
        }

    def reset(self) -> None:
        with self._pool.connection() as conn:
            conn.execute("TRUNCATE docs, events RESTART IDENTITY")

    @staticmethod
    def _to_event(r: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": r["id"],
            "ts": r["ts"],
            "type": r["type"],
            "session_id": r["session_id"],
            "agent_id": r["agent_id"],
            "payload": json.loads(r["payload"]),
            "hash": r["hash"],
        }
