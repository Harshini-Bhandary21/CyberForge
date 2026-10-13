"""Statistical injection classifier: hashed char n-gram TF-IDF + logistic regression, pure Python.

Rules need the attacker's phrasing to match; a linear model over character n-grams generalises to
paraphrases and misspellings. It is trained on first use from the red-team payloads, hand-written
paraphrases and a benign business-mail corpus, deterministically (fixed seed), with no dependencies
and no network. Advisory only: it nudges the input scan, never decides an action alone.
"""

from __future__ import annotations

import json
import math
import random
import re
from functools import lru_cache
from pathlib import Path

DIM = 1 << 15
NGRAMS = (3, 4, 5)
DATA = Path(__file__).resolve().parents[1] / "modules" / "redteam" / "data"
_WS = re.compile(r"\s+")


def _features(text: str) -> dict[int, float]:
    t = " " + _WS.sub(" ", text.lower()) + " "
    counts: dict[int, float] = {}
    for n in NGRAMS:
        for i in range(len(t) - n + 1):
            h = hash_gram(t[i : i + n])
            counts[h] = counts.get(h, 0.0) + 1.0
    return counts


def hash_gram(g: str) -> int:
    h = 2166136261  # FNV-1a: stable across runs, unlike Python's salted hash()
    for ch in g.encode():
        h = ((h ^ ch) * 16777619) & 0xFFFFFFFF
    return h % DIM


class InjectionModel:
    def __init__(self) -> None:
        self.w: dict[int, float] = {}
        self.b = 0.0
        self.idf: dict[int, float] = {}

    def _vec(self, text: str) -> dict[int, float]:
        v = {k: (1 + math.log(c)) * self.idf.get(k, 1.0) for k, c in _features(text).items()}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        return {k: x / norm for k, x in v.items()}

    def fit(
        self,
        texts: list[str],
        labels: list[int],
        epochs: int = 40,
        lr: float = 0.8,
        l2: float = 1e-4,
    ) -> None:
        df: dict[int, int] = {}
        for t in texts:
            for k in _features(t):
                df[k] = df.get(k, 0) + 1
        n = len(texts)
        self.idf = {k: math.log((1 + n) / (1 + d)) + 1 for k, d in df.items()}
        data = [(self._vec(t), y) for t, y in zip(texts, labels, strict=True)]
        pos = sum(labels) or 1
        neg = (len(labels) - sum(labels)) or 1
        cw = {1: n / (2 * pos), 0: n / (2 * neg)}  # balance classes
        rng = random.Random(7)
        for ep in range(epochs):
            rng.shuffle(data)
            step = lr / (1 + 0.1 * ep)
            for v, y in data:
                p = self._p(v)
                g = (p - y) * cw[y]
                for k, x in v.items():
                    self.w[k] = self.w.get(k, 0.0) - step * (g * x + l2 * self.w.get(k, 0.0))
                self.b -= step * g

    def _p(self, v: dict[int, float]) -> float:
        z = self.b + sum(self.w.get(k, 0.0) * x for k, x in v.items())
        return 1 / (1 + math.exp(-max(-30.0, min(30.0, z))))

    def predict(self, text: str) -> float:
        return round(self._p(self._vec(text)), 4)


def corpus() -> tuple[list[str], list[int]]:
    attacks = [p["text"] for p in json.loads((DATA / "payloads.json").read_text())]
    attacks += json.loads((DATA / "paraphrases.json").read_text())
    benign = json.loads((DATA / "benign.json").read_text())
    return attacks + benign, [1] * len(attacks) + [0] * len(benign)


@lru_cache(maxsize=1)
def model() -> InjectionModel:
    m = InjectionModel()
    m.fit(*corpus())
    return m
