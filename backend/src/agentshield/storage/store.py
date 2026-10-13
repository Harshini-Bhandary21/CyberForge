"""SQLite persistence: a generic document store plus a hash-chained, append-only audit log."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from agentshield.core.dlp import redact_value

GENESIS = "0" * 64


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def event_hash(
    prev: str, ts: float, type_: str, session_id: str | None, agent_id: str | None, payload: Any
) -> str:
    """SHA-256 link of the audit chain. Shared by every storage backend."""
    body = _canonical(
        {
            "ts": ts,
            "type": type_,
            "session_id": session_id,
            "agent_id": agent_id,
            "payload": payload,
        }
    )
    return hashlib.sha256((prev + body).encode()).hexdigest()


class Store:
    """Thread-safe SQLite wrapper. Use ``":memory:"`` for ephemeral stores (tests, red-team)."""

    def __init__(self, path: str = ":memory:") -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS docs (
                    collection TEXT NOT NULL,
                    id         TEXT NOT NULL,
                    body       TEXT NOT NULL,
                    updated    REAL NOT NULL,
                    PRIMARY KEY (collection, id)
                );
                CREATE TABLE IF NOT EXISTS events (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts         REAL NOT NULL,
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
            )

    # ------------------------------------------------------------------ documents
    def put(self, collection: str, doc_id: str, doc: dict[str, Any]) -> None:
        doc = redact_value(doc)  # defence in depth: secrets are never persisted
        with self._lock:
            self._db.execute(
                "INSERT INTO docs(collection,id,body,updated) VALUES(?,?,?,?) "
                "ON CONFLICT(collection,id) DO UPDATE SET body=excluded.body, updated=excluded.updated",
                (collection, doc_id, _canonical(doc), time.time()),
            )
            self._db.commit()

    def get(self, collection: str, doc_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT body FROM docs WHERE collection=? AND id=?", (collection, doc_id)
            ).fetchone()
        return json.loads(row["body"]) if row else None

    def list(self, collection: str, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT body FROM docs WHERE collection=? ORDER BY updated DESC LIMIT ?",
                (collection, limit),
            ).fetchall()
        return [json.loads(r["body"]) for r in rows]

    def delete(self, collection: str, doc_id: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM docs WHERE collection=? AND id=?", (collection, doc_id))
            self._db.commit()

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
        with self._lock:
            last = self._db.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
            prev = last["hash"] if last else GENESIS
            ts = time.time()
            digest = event_hash(prev, ts, type_, session_id, agent_id, payload)
            cur = self._db.execute(
                "INSERT INTO events(ts,type,session_id,agent_id,payload,prev_hash,hash) VALUES(?,?,?,?,?,?,?)",
                (ts, type_, session_id, agent_id, _canonical(payload), prev, digest),
            )
            self._db.commit()
            return {
                "id": cur.lastrowid,
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
            where.append("session_id=?")
            args.append(session_id)
        if agent_id:
            where.append("agent_id=?")
            args.append(agent_id)
        if types:
            where.append(f"type IN ({','.join('?' * len(types))})")
            args.extend(types)
        sql = "SELECT * FROM events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += f" ORDER BY id {'ASC' if oldest_first else 'DESC'} LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._db.execute(sql, args).fetchall()
        return [self._row_to_event(r) for r in rows]

    def count_events(self, type_: str | None = None) -> int:
        with self._lock:
            if type_:
                row = self._db.execute(
                    "SELECT COUNT(*) c FROM events WHERE type=?", (type_,)
                ).fetchone()
            else:
                row = self._db.execute("SELECT COUNT(*) c FROM events").fetchone()
        return int(row["c"])

    def verify_chain(self) -> dict[str, Any]:
        """Recompute every hash; report the first broken link, if any."""
        with self._lock:
            rows = self._db.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
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
        with self._lock:
            self._db.execute("DELETE FROM docs")
            self._db.execute("DELETE FROM events")
            self._db.commit()

    @staticmethod
    def _row_to_event(r: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": r["id"],
            "ts": r["ts"],
            "type": r["type"],
            "session_id": r["session_id"],
            "agent_id": r["agent_id"],
            "payload": json.loads(r["payload"]),
            "hash": r["hash"],
        }
