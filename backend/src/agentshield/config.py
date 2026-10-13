"""Runtime configuration, read from environment variables (prefix ``AGENTSHIELD_``) and ``.env``.

Secrets (API keys) are held as ``SecretStr`` so they never appear in logs, reprs or tracebacks.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

Role = Literal["agent", "analyst", "admin"]
DEFAULT_SIGNING_SECRET = "dev-only-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENTSHIELD_",
        env_file=(".env", "../.env"),
        extra="ignore",
        populate_by_name=True,
    )

    env: Literal["development", "test", "production"] = "development"

    # ── Storage ─────────────────────────────────────────────────────────────
    # DATABASE_URL (postgresql://…) wins over db_path (SQLite file or ":memory:").
    database_url: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("DATABASE_URL", "AGENTSHIELD_DATABASE_URL")
    )
    db_path: str = "data/agentshield.db"

    # ── API security ────────────────────────────────────────────────────────
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    # Single shared admin key (legacy) and/or a {key: role} map, e.g.
    #   AGENTSHIELD_API_KEYS='{"k1":"admin","k2":"analyst","k3":"agent"}'
    api_key: SecretStr | None = None
    api_keys: dict[str, Role] = Field(default_factory=dict)
    rate_limit_per_min: int = 1200  # per principal / client IP; 0 disables
    max_body_bytes: int = 1_000_000
    docs_enabled: bool | None = None  # default: on except in production
    enable_demo: bool | None = None  # default: on except in production
    agent_signing_secret: SecretStr = SecretStr(DEFAULT_SIGNING_SECRET)
    require_agent_identity: bool = False

    # ── LLM providers (isolated intent verifier + incident narratives) ──────
    # Tried in order; the first that answers wins. Without any key, heuristics run offline.
    use_llm: bool = True
    llm_providers: list[str] = Field(default_factory=lambda: ["groq", "gemini", "anthropic"])
    llm_timeout_s: float = 8.0
    groq_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("GROQ_API_KEY", "AGENTSHIELD_GROQ_API_KEY")
    )
    gemini_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "GEMINI_API_KEY", "GOOGLE_API_KEY", "AGENTSHIELD_GEMINI_API_KEY"
        ),
    )
    anthropic_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("ANTHROPIC_API_KEY", "AGENTSHIELD_ANTHROPIC_API_KEY"),
    )
    groq_model: str = "llama-3.3-70b-versatile"
    gemini_model: str = "gemini-2.5-flash"
    judge_model: str = "claude-haiku-5-5"  # Anthropic

    # ── Policy ──────────────────────────────────────────────────────────────
    # Pin the local hour used by time-of-day signals (reproducible evaluations); None = wall clock.
    fixed_hour: int | None = None
    approval_amount_inr: float = 10_000
    block_amount_inr: float = 500_000

    # ------------------------------------------------------------------ derived
    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def docs_on(self) -> bool:
        return (not self.is_production) if self.docs_enabled is None else self.docs_enabled

    @property
    def demo_on(self) -> bool:
        return (not self.is_production) if self.enable_demo is None else self.enable_demo

    @property
    def auth_configured(self) -> bool:
        return bool(self.api_key or self.api_keys)

    def key_for(self, provider: str) -> str | None:
        secret = {
            "groq": self.groq_api_key,
            "gemini": self.gemini_api_key,
            "anthropic": self.anthropic_api_key,
        }.get(provider)
        return secret.get_secret_value() if secret else None

    @property
    def active_providers(self) -> list[str]:
        if not self.use_llm:
            return []
        return [p for p in self.llm_providers if self.key_for(p)]

    @property
    def llm_available(self) -> bool:
        return bool(self.active_providers)

    def production_problems(self) -> list[str]:
        """Misconfigurations that must stop a production start-up."""
        problems = []
        if not self.auth_configured:
            problems.append(
                "no API key configured (set AGENTSHIELD_API_KEYS or AGENTSHIELD_API_KEY)"
            )
        if self.agent_signing_secret.get_secret_value() == DEFAULT_SIGNING_SECRET:
            problems.append("AGENTSHIELD_AGENT_SIGNING_SECRET still has the development default")
        if "*" in self.cors_origins:
            problems.append("CORS allows every origin")
        return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()
