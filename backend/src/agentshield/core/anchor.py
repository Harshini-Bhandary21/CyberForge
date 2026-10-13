"""Merkle checkpoints for the audit log: from tamper-evident to tamper-resistant.

The hash chain proves internal consistency, but an attacker with write access to the store can
rewrite history and recompute every hash. A signed checkpoint (size, Merkle root over all event
hashes so far, HMAC with a key the store does not hold) breaks that: rewriting or truncating the
log changes the root of the committed prefix, and the signature cannot be forged. Checkpoints can
also be appended to a file you ship to write-once storage, so the *evidence* lives off-host.

Tree construction follows RFC 6962 (distinct leaf/node prefixes defeat second-preimage attacks),
and inclusion proofs let anyone prove one event belongs to a signed checkpoint in O(log n).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path
from typing import Any

from agentshield.storage.store import Store

COLLECTION = "anchors"


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _leaf(event_hash: str) -> bytes:
    return _h(b"\x00" + bytes.fromhex(event_hash))


def _node(left: bytes, right: bytes) -> bytes:
    return _h(b"\x01" + left + right)


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return _h(b"")
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return _node(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_proof(leaves: list[bytes], index: int) -> list[tuple[str, str]]:
    """Sibling path from the leaf up: [("L"|"R", hex)] where the side is the sibling's side."""
    if len(leaves) <= 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return inclusion_proof(leaves[:k], index) + [("R", merkle_root(leaves[k:]).hex())]
    return inclusion_proof(leaves[k:], index - k) + [("L", merkle_root(leaves[:k]).hex())]


def verify_inclusion(event_hash: str, proof: list[tuple[str, str]], root_hex: str) -> bool:
    cur = _leaf(event_hash)
    for side, sib in proof:
        cur = _node(cur, bytes.fromhex(sib)) if side == "R" else _node(bytes.fromhex(sib), cur)
    return hmac.compare_digest(cur.hex(), root_hex)


class Anchors:
    def __init__(self, store: Store, secret: str, export_path: str | None = None) -> None:
        self.store, self._key, self.export_path = store, secret.encode(), export_path

    def _events(self) -> list[dict[str, Any]]:
        return self.store.events(limit=10**9, oldest_first=True)

    def _sign(self, size: int, root: str, head: str | None, ts: float) -> str:
        msg = json.dumps({"size": size, "root": root, "head": head, "ts": ts}, sort_keys=True)
        return hmac.new(self._key, msg.encode(), hashlib.sha256).hexdigest()

    def checkpoint(self) -> dict[str, Any]:
        events = self._events()
        leaves = [_leaf(e["hash"]) for e in events]
        root = merkle_root(leaves).hex()
        head = events[-1]["hash"] if events else None
        ts = round(time.time(), 3)
        cp = {
            "id": f"{len(events):012d}-{int(ts)}",
            "size": len(events),
            "root": root,
            "head": head,
            "ts": ts,
            "sig": self._sign(len(events), root, head, ts),
        }
        self.store.put(COLLECTION, cp["id"], cp)
        if self.export_path:
            p = Path(self.export_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a") as f:
                f.write(json.dumps(cp, sort_keys=True) + "\n")
        return cp

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        return sorted(self.store.list(COLLECTION, limit), key=lambda c: c["size"], reverse=True)

    def verify(self, checkpoints: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Check every checkpoint (or externally supplied ones) against the live log."""
        cps = checkpoints if checkpoints is not None else self.list(10_000)
        events = self._events()
        leaves = [_leaf(e["hash"]) for e in events]
        bad: list[dict[str, Any]] = []
        for cp in sorted(cps, key=lambda c: c["size"]):
            good_sig = hmac.compare_digest(
                self._sign(cp["size"], cp["root"], cp["head"], cp["ts"]), cp.get("sig", "")
            )
            if not good_sig:
                bad.append({"id": cp["id"], "problem": "signature invalid (checkpoint forged)"})
            elif cp["size"] > len(events):
                bad.append(
                    {"id": cp["id"], "problem": "log is shorter than the checkpoint (truncated)"}
                )
            elif merkle_root(leaves[: cp["size"]]).hex() != cp["root"]:
                bad.append(
                    {"id": cp["id"], "problem": "history before this checkpoint was altered"}
                )
        return {"valid": not bad, "checkpoints": len(cps), "problems": bad}

    def prove(self, event_id: int, checkpoint: dict[str, Any]) -> dict[str, Any] | None:
        events = self._events()[: checkpoint["size"]]
        idx = next((i for i, e in enumerate(events) if e["id"] == event_id), None)
        if idx is None:
            return None
        leaves = [_leaf(e["hash"]) for e in events]
        return {
            "event_id": event_id,
            "event_hash": events[idx]["hash"],
            "checkpoint": checkpoint["id"],
            "root": checkpoint["root"],
            "proof": inclusion_proof(leaves, idx),
        }
