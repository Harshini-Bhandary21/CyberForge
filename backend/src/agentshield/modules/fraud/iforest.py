"""Isolation Forest (Liu et al., 2008), pure Python and deterministic.

Unsupervised: learns what *this agent's* normal payments look like (log-amount, hour of day) from
its own allowed history and scores how easily a new payment is isolated by random splits. Short
average path = anomalous. Needs no labelled fraud data, which a per-agent deployment never has.
"""

from __future__ import annotations

import math
import random

EULER = 0.5772156649


def _c(n: int) -> float:
    """Average path length of an unsuccessful BST search over n points."""
    if n <= 1:
        return 0.0
    return 2.0 * (math.log(n - 1) + EULER) - 2.0 * (n - 1) / n


class _Node:
    __slots__ = ("feat", "split", "left", "right", "size", "lo", "hi")

    def __init__(self) -> None:
        self.feat = -1
        self.split = 0.0
        self.left: _Node | None = None
        self.right: _Node | None = None
        self.size = 0
        self.lo: list[float] = []
        self.hi: list[float] = []


def _grow(rows: list[list[float]], depth: int, limit: int, rng: random.Random) -> _Node:
    node = _Node()
    node.size = len(rows)
    dims = len(rows[0])
    node.lo = [min(r[f] for r in rows) for f in range(dims)]
    node.hi = [max(r[f] for r in rows) for f in range(dims)]
    if depth >= limit or len(rows) <= 1:
        return node
    for _ in range(dims * 2):  # retry on constant features
        f = rng.randrange(dims)
        lo, hi = min(r[f] for r in rows), max(r[f] for r in rows)
        if hi > lo:
            node.feat, node.split = f, rng.uniform(lo, hi)
            node.left = _grow([r for r in rows if r[node.feat] < node.split], depth + 1, limit, rng)
            node.right = _grow(
                [r for r in rows if r[node.feat] >= node.split], depth + 1, limit, rng
            )
            return node
    return node


def _path(node: _Node, x: list[float], margin: list[float], depth: int = 0) -> float:
    while True:
        # Outside the region this node saw (plus a margin) the point is already isolated: plain
        # random splits cannot separate a point that lies beyond every training value.
        if any(
            v < lo - m or v > hi + m
            for v, lo, hi, m in zip(x, node.lo, node.hi, margin, strict=True)
        ):
            return depth
        if node.left is None or node.right is None:
            break
        node = node.left if x[node.feat] < node.split else node.right
        depth += 1
    return depth + _c(node.size)


class IsolationForest:
    def __init__(self, trees: int = 60, sample: int = 128, seed: int = 11) -> None:
        self.trees, self.sample, self.seed = trees, sample, seed
        self._forest: list[_Node] = []
        self._psi = 0
        self._margin: list[float] = []

    def fit(self, rows: list[list[float]]) -> IsolationForest:
        rng = random.Random(self.seed)
        self._psi = min(self.sample, len(rows))
        dims = len(rows[0])
        self._margin = [
            0.5 * (max(r[f] for r in rows) - min(r[f] for r in rows)) + 0.1 for f in range(dims)
        ]
        limit = math.ceil(math.log2(max(self._psi, 2)))
        self._forest = [
            _grow(rng.sample(rows, self._psi), 0, limit, rng) for _ in range(self.trees)
        ]
        return self

    def score(self, x: list[float]) -> float:
        """0..1; ~0.5 is typical, approaching 1 is anomalous."""
        if not self._forest:
            return 0.0
        mean_path = sum(_path(t, x, self._margin) for t in self._forest) / len(self._forest)
        return 2 ** (-mean_path / (_c(self._psi) or 1.0))
