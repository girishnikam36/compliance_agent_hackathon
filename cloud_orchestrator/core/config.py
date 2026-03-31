"""
cloud_orchestrator/core/config.py
==================================
Centralised, validated configuration for the Oxbuild Compliance Agent.

UPDATED: Replaced single Oxlo API key with per-phase provider config.
Each pipeline phase (Auditor, Judge, Architect) can use a different
provider and model, all using the OpenAI-compatible chat completions API.

Default free-tier configuration:
  Phase 1 Auditor   → Groq          (llama-3.3-70b-versatile)
  Phase 2 Judge     → OpenRouter    (deepseek/deepseek-r1-0528:free)
  Phase 3 Architect → DeepSeek      (deepseek-chat)

Usage
-----
    from cloud_orchestrator.core.config import settings

    key, url = settings.get_phase_config("AUDITOR")
    model    = settings.auditor_model
"""

from __future__ import annotations

import logging
import os
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
logger = logging.getLogger("oxbuild.config")


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING     = "staging"
    PRODUCTION  = "production"
    TEST        = "test"


class LogLevel(str, Enum):
    DEBUG    = "DEBUG"
    INFO     = "INFO"
    WARNING  = "WARNING"
    ERROR    = "ERROR"
    CRITICAL = "CRITICAL"


class Settings(BaseSettings):
    """
    All runtime configuration for Oxbuild.

    Per-phase LLM provider settings — each phase has its own:
      <PHASE>_API_KEY   — provider API key
      <PHASE>_BASE_URL  — OpenAI-compatible endpoint
      <PHASE>_MODEL     — exact model identifier for that provider

    Phases: AUDITOR, JUDGE, ARCHITECT
    """

    model_config = SettingsConfigDict(
        env_file=(
            _PROJECT_ROOT / ".env",
            _PROJECT_ROOT / f".env.{os.getenv('ENVIRONMENT', 'development')}",
            _PROJECT_ROOT / ".env.secrets",
        ),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        validate_default=True,
    )

    # ── Identity ─────────────────────────────────────────────────────────
    app_name:    str         = Field(default="oxbuild-compliance-agent")
    environment: Environment = Field(default=Environment.DEVELOPMENT)
    debug:       bool        = Field(default=False)

    # ── Phase 1: Auditor (default: Groq free tier) ────────────────────────
    # Sign up: https://console.groq.com — no credit card
    auditor_api_key:  SecretStr = Field(
        default=SecretStr(""),
        description="API key for Phase 1 Auditor. Get free key at console.groq.com",
    )
    auditor_base_url: str = Field(
        default="https://api.groq.com/openai/v1",
        description="OpenAI-compatible base URL for the Auditor.",
    )
    auditor_model: str = Field(
        default="llama-3.3-70b-versatile",
        description="Model ID for the Auditor agent.",
    )

    # ── Phase 2: Judge (default: OpenRouter free DeepSeek R1) ────────────
    # Sign up: https://openrouter.ai — no credit card
    judge_api_key:  SecretStr = Field(
        default=SecretStr(""),
        description="API key for Phase 2 Judge. Get free key at openrouter.ai",
    )
    judge_base_url: str = Field(
        default="https://openrouter.ai/api/v1",
        description="OpenAI-compatible base URL for the Judge.",
    )
    judge_model: str = Field(
        default="deepseek/deepseek-r1-0528:free",
        description="Model ID for the Judge agent.",
    )

    # ── Phase 3: Architect (default: DeepSeek direct — 5M free tokens) ───
    # Sign up: https://platform.deepseek.com — 5M tokens free
    architect_api_key:  SecretStr = Field(
        default=SecretStr(""),
        description="API key for Phase 3 Architect. Get free key at platform.deepseek.com",
    )
    architect_base_url: str = Field(
        default="https://api.deepseek.com",
        description="OpenAI-compatible base URL for the Architect.",
    )
    architect_model: str = Field(
        default="deepseek-chat",
        description="Model ID for the Architect agent.",
    )

    # ── Shared LLM settings ───────────────────────────────────────────────
    llm_timeout_s:      float = Field(default=120.0, ge=5.0,  le=600.0)
    llm_max_retries:    int   = Field(default=3,     ge=0,    le=10)
    llm_retry_backoff_s: float = Field(default=2.0,  ge=0.1)

    # Per-phase token limits
    max_tokens_auditor:   int = Field(default=4096,  ge=256, le=32768)
    max_tokens_judge:     int = Field(default=2048,  ge=256, le=16384)
    max_tokens_architect: int = Field(default=8192,  ge=512, le=65536)

    # ── FastAPI server ────────────────────────────────────────────────────
    host:            str       = Field(default="0.0.0.0")
    port:            int       = Field(default=8000, ge=1024, le=65535)
    allowed_origins: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173", "https://app.oxbuild.ai"]
    )

    # ── State manager ─────────────────────────────────────────────────────
    state_db_path: Path = Field(
        default=_PROJECT_ROOT / "local_bridge" / "data" / "state.db"
    )
    state_json_backup_path: Path = Field(
        default=_PROJECT_ROOT / "local_bridge" / "data" / "state_backup.json"
    )

    # ── Security ──────────────────────────────────────────────────────────
    api_secret_key: SecretStr = Field(
        default=SecretStr("change-me-in-production-at-least-32-chars")
    )
    max_code_length: int = Field(default=500_000, ge=100)

    # ── Observability ─────────────────────────────────────────────────────
    log_level: LogLevel = Field(default=LogLevel.INFO)
    log_json:  bool     = Field(default=False)

    # ── Feature flags ─────────────────────────────────────────────────────
    enable_mock_llm:      bool = Field(default=True)
    enable_pii_audit_log: bool = Field(default=False)

    # ── Validators ────────────────────────────────────────────────────────

    @field_validator("state_db_path", "state_json_backup_path", mode="before")
    @classmethod
    def ensure_parent_dir(cls, v: Any) -> Path:
        path = Path(v)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    @model_validator(mode="after")
    def warn_insecure_defaults(self) -> "Settings":
        if self.environment == Environment.PRODUCTION:
            secret = self.api_secret_key.get_secret_value()
            if "change-me" in secret:
                raise ValueError(
                    "API_SECRET_KEY is still the default. Generate one: "
                    "python -c \"import secrets; print(secrets.token_hex(32))\""
                )
        return self

    # ── Phase config helper (used by pipeline.py) ─────────────────────────

    def get_phase_config(self, phase: str) -> tuple[str, str, str]:
        """
        Return (api_key, base_url, model) for a pipeline phase.

        phase: "AUDITOR" | "JUDGE" | "ARCHITECT"

        Falls back to reading environment variables directly if pydantic
        didn't load them (handles edge cases with .env file discovery).
        """
        phase = phase.upper()

        key_map = {
            "AUDITOR":   self.auditor_api_key,
            "JUDGE":     self.judge_api_key,
            "ARCHITECT": self.architect_api_key,
        }
        url_map = {
            "AUDITOR":   self.auditor_base_url,
            "JUDGE":     self.judge_base_url,
            "ARCHITECT": self.architect_base_url,
        }
        model_map = {
            "AUDITOR":   self.auditor_model,
            "JUDGE":     self.judge_model,
            "ARCHITECT": self.architect_model,
        }

        if phase not in key_map:
            raise ValueError(f"Unknown phase: {phase!r}. Must be AUDITOR, JUDGE, or ARCHITECT.")

        api_key  = key_map[phase].get_secret_value()
        base_url = url_map[phase].rstrip("/")
        model    = model_map[phase]

        # Direct env var fallback (belt-and-suspenders)
        if not api_key:
            api_key = os.environ.get(f"{phase}_API_KEY", "")
        if not api_key:
            raise RuntimeError(
                f"{phase}_API_KEY is not set.\n"
                f"Add it to your .env file. See .env.example for instructions.\n"
                f"Free key sources:\n"
                f"  AUDITOR   → https://console.groq.com (no credit card)\n"
                f"  JUDGE     → https://openrouter.ai    (no credit card)\n"
                f"  ARCHITECT → https://platform.deepseek.com (5M free tokens)"
            )

        return api_key, base_url, model

    # ── Computed properties ───────────────────────────────────────────────

    @property
    def is_production(self) -> bool:
        return self.environment == Environment.PRODUCTION

    @property
    def effective_log_level(self) -> int:
        return getattr(logging, self.log_level.value)

    def configure_logging(self) -> None:
        fmt = (
            '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}'
            if self.log_json
            else "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s"
        )
        logging.basicConfig(
            level=self.effective_log_level,
            format=fmt,
            datefmt="%Y-%m-%dT%H:%M:%S",
            force=True,
        )

    def redacted_summary(self) -> dict[str, Any]:
        """Loggable summary — all secrets replaced with [REDACTED]."""
        def _key_status(key: SecretStr) -> str:
            val = key.get_secret_value()
            if not val:
                return "NOT SET"
            return f"set ({val[:8]}...)"

        return {
            "app_name":          self.app_name,
            "environment":       self.environment.value,
            "debug":             self.debug,
            "enable_mock_llm":   self.enable_mock_llm,
            "auditor_model":     self.auditor_model,
            "auditor_base_url":  self.auditor_base_url,
            "auditor_api_key":   _key_status(self.auditor_api_key),
            "judge_model":       self.judge_model,
            "judge_base_url":    self.judge_base_url,
            "judge_api_key":     _key_status(self.judge_api_key),
            "architect_model":   self.architect_model,
            "architect_base_url":self.architect_base_url,
            "architect_api_key": _key_status(self.architect_api_key),
            "log_level":         self.log_level.value,
            "host":              self.host,
            "port":              self.port,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the cached singleton Settings instance.
    Call get_settings.cache_clear() in tests to force re-evaluation.
    """
    s = Settings()  # type: ignore[call-arg]
    s.configure_logging()
    logger.info("Settings loaded:\n%s",
                "\n".join(f"  {k}: {v}" for k, v in s.redacted_summary().items()))
    return s


settings: Settings = get_settings()