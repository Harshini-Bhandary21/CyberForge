"""LLM provider adapters: Groq, Google Gemini and Anthropic behind one tiny interface.

* Keys come from ``Settings`` (``SecretStr``) and only ever travel in request headers; they are
  never logged and never included in exception messages we surface.
* Every adapter returns ``None`` on any failure (network, quota, refusal, bad payload). Callers
  treat that as "no opinion" and fall back, so a provider outage can never open a security hole.
"""

from __future__ import annotations

import logging
from typing import Protocol

import anthropic
import httpx

log = logging.getLogger(__name__)

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


class Provider(Protocol):
    name: str
    model: str

    def complete(
        self, system: str, user: str, *, max_tokens: int, json_mode: bool
    ) -> str | None: ...


class GroqProvider:
    """Groq exposes an OpenAI-compatible chat-completions API."""

    name = "groq"

    def __init__(
        self, api_key: str, model: str, timeout: float, client: httpx.Client | None = None
    ) -> None:
        self._key, self.model = api_key, model
        self._http = client or httpx.Client(timeout=timeout)

    def complete(self, system: str, user: str, *, max_tokens: int, json_mode: bool) -> str | None:
        body: dict[str, object] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": max_tokens,
            "temperature": 0,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        try:
            r = self._http.post(
                GROQ_URL, json=body, headers={"Authorization": f"Bearer {self._key}"}
            )
            r.raise_for_status()
            return (r.json()["choices"][0]["message"]["content"] or "").strip() or None
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            log.warning("groq call failed: %s", type(exc).__name__)
            return None


class GeminiProvider:
    name = "gemini"

    def __init__(
        self, api_key: str, model: str, timeout: float, client: httpx.Client | None = None
    ) -> None:
        self._key, self.model = api_key, model
        self._http = client or httpx.Client(timeout=timeout)

    def complete(self, system: str, user: str, *, max_tokens: int, json_mode: bool) -> str | None:
        gen: dict[str, object] = {"maxOutputTokens": max(max_tokens, 1024), "temperature": 0}
        if json_mode:
            gen["responseMimeType"] = "application/json"
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": gen,
        }
        try:
            # Key goes in a header (never the URL) so it cannot leak into proxy or access logs.
            r = self._http.post(
                GEMINI_URL.format(model=self.model),
                json=body,
                headers={"x-goog-api-key": self._key},
            )
            r.raise_for_status()
            cand = r.json()["candidates"][0]
            parts = cand.get("content", {}).get("parts", [])
            return "".join(p.get("text", "") for p in parts).strip() or None
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            log.warning("gemini call failed: %s", type(exc).__name__)
            return None


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str, model: str, timeout: float) -> None:
        self.model = model
        self._client = anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=1)

    def complete(self, system: str, user: str, *, max_tokens: int, json_mode: bool) -> str | None:  # noqa: ARG002
        try:
            resp = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                output_config={"effort": "low"},
                messages=[{"role": "user", "content": user}],
            )
        except anthropic.APIError as exc:
            log.warning("anthropic call failed: %s", type(exc).__name__)
            return None
        if resp.stop_reason == "refusal":
            return None
        return "".join(b.text for b in resp.content if b.type == "text").strip() or None
