"""Aho–Corasick multi-pattern matcher: every phrase in a lexicon found in one O(text) pass.

Regex alternation re-scans the text per pattern; with hundreds of phrases (multilingual injection
lexicon, blocklists) that is the wrong shape. This automaton builds a trie with failure links once
and then reads the text a single time.
"""

from __future__ import annotations

from collections import deque


class AhoCorasick:
    def __init__(self, patterns: dict[str, str]) -> None:
        """``patterns`` maps phrase -> label. Phrases are matched case-sensitively; lower-case input."""
        self._next: list[dict[str, int]] = [{}]
        self._fail: list[int] = [0]
        self._out: list[list[str]] = [[]]
        for phrase, label in patterns.items():
            node = 0
            for ch in phrase:
                node = self._next[node].setdefault(ch, self._new())
            self._out[node].append(label)
        queue = deque(self._next[0].values())
        while queue:
            node = queue.popleft()
            for ch, child in self._next[node].items():
                f = self._fail[node]
                while f and ch not in self._next[f]:
                    f = self._fail[f]
                self._fail[child] = self._next[f].get(ch, 0)
                self._out[child] = self._out[child] + self._out[self._fail[child]]
                queue.append(child)

    def _new(self) -> int:
        self._next.append({})
        self._fail.append(0)
        self._out.append([])
        return len(self._next) - 1

    def find(self, text: str) -> set[str]:
        """Labels of all patterns occurring anywhere in ``text``."""
        found: set[str] = set()
        node = 0
        for ch in text:
            while node and ch not in self._next[node]:
                node = self._fail[node]
            node = self._next[node].get(ch, 0)
            if self._out[node]:
                found.update(self._out[node])
        return found
