"""Failure-tolerant, multi-provider LLM front door.

Providers are tried in the configured order (default: Groq → Gemini → Anthropic). A provider that
fails is skipped for a short cool-down so an outage costs one slow call, not one per request.
Every caller has a deterministic fallback, so the platform works fully offline.
"""

from __future__ import annotations

import json
import re
import threading
import time
from typing import Any

from agentshield.config import Settings
from agentshield.llm.providers import AnthropicProvider, GeminiProvider, GroqProvider, Provider

COOLDOWN_S = 30.0


class LLM:
    def __init__(self, settings: Settings, providers: list[Provider] | None = None) -> None:
        self.settings = settings
        self._providers = providers
        self._down_until: dict[str, float] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ providers
    def _build(self) -> list[Provider]:
        s, out = self.settings, []
        for name in s.active_providers:
            key = s.key_for(name)
            assert key  # active_providers only lists providers that have a key
            if name == "groq":
                out.append(GroqProvider(key, s.groq_model, s.llm_timeout_s))
            elif name == "gemini":
                out.append(GeminiProvider(key, s.gemini_model, s.llm_timeout_s))
            elif name == "anthropic":
                out.append(AnthropicProvider(key, s.judge_model, s.llm_timeout_s))
        return out

    @property
    def providers(self) -> list[Provider]:
        if self._providers is None:
            self._providers = self._build()
        return self._providers

    @property
    def enabled(self) -> bool:
        return bool(self.providers) and self.settings.use_llm

    @property
    def provider_names(self) -> list[str]:
        return [f"{p.name}:{p.model}" for p in self.providers] if self.enabled else []

    # ------------------------------------------------------------------ calls
    def _complete(
        self, system: str, user: str, max_tokens: int, json_mode: bool
    ) -> tuple[str, str] | None:
        if not self.enabled:
            return None
        for p in self.providers:
            with self._lock:
                if self._down_until.get(p.name, 0) > time.monotonic():
                    continue
            text = p.complete(system, user, max_tokens=max_tokens, json_mode=json_mode)
            if text:
                return text, p.name
            with self._lock:
                self._down_until[p.name] = time.monotonic() + COOLDOWN_S
        return None

    def complete(self, system: str, user: str, *, max_tokens: int = 700) -> str | None:
        res = self._complete(system, user, max_tokens, json_mode=False)
        return res[0] if res else None

    def complete_json(
        self, system: str, user: str, *, max_tokens: int = 500
    ) -> dict[str, Any] | None:
        """Parsed JSON object plus ``_provider`` naming who answered (for the audit trail)."""
        res = self._complete(system, user, max_tokens, json_mode=True)
        if not res:
            return None
        text, provider = res
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            return None
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        data["_provider"] = provider
        return data
