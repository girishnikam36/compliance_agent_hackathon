"""
cloud_orchestrator/core/config.py
==================================
Centralised, validated configuration for the Oxbuild Compliance Agent
cloud orchestrator.  Built on ``pydantic-settings`` v2 so every value is
type-checked, coerced, and documented at import time.

Environment resolution order (highest → lowest priority):
  1. Real environment variables  (e.g. export OXLO_API_KEY=…)
  2. Secrets files               (.env.secrets  — never committed)
  3. Per-environment overrides   (.env.production / .env.development)
  4. Shared defaults             (.env)
  5. Hard-coded field defaults below

Usage
-----
    from cloud_orchestrator.core.config import settings

    print(settings.oxlo_api_key.get_secret_value())
    print(settings.llama_model)
    print(settings.is_production)
"""

from __future__ import annotations

import logging
import os
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any

from pydantic import (
    AnyHttpUrl,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# Project root — resolves regardless of working directory
# ---------------------------------------------------------------------------
_PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]

logger = logging.getLogger("oxbuild.config")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Settings model
# ---------------------------------------------------------------------------

class Settings(BaseSettings):
    """
    All runtime configuration for the Oxbuild cloud orchestrator.

    Field names map 1-to-1 with environment variable names (upper-cased by
    pydantic-settings automatically).  Every field has a type annotation and
    a description for self-documenting behaviour.
    """

    model_config = SettingsConfigDict(
        # Read from multiple .env files — later files take lower priority
        env_file=(
            _PROJECT_ROOT / ".env",
            _PROJECT_ROOT / f".env.{os.getenv('ENVIRONMENT', 'development')}",
            _PROJECT_ROOT / ".env.secrets",      # gitignored secrets overlay
        ),
        env_file_encoding="utf-8",
        env_nested_delimiter="__",               # OXLO__API_KEY maps to oxlo.api_key
        case_sensitive=False,
        extra="ignore",                          # silently drop unknown vars
        validate_default=True,
    )

    # ── Identity ─────────────────────────────────────────────────────────
    app_name: str = Field(
        default="oxbuild-compliance-agent",
        description="Human-readable service name (appears in logs / headers).",
    )
    environment: Environment = Field(
        default=Environment.DEVELOPMENT,
        description="Deployment environment. Controls logging verbosity, debug mode, etc.",
    )
    debug: bool = Field(
        default=False,
        description="Enable FastAPI debug mode. MUST be False in production.",
    )

    # ── Oxlo / LLM gateway ───────────────────────────────────────────────
    oxlo_api_key: SecretStr = Field(
        ...,                                     # required — no default
        description=(
            "Master API key for the Oxlo LLM gateway. "
            "Grants access to Llama 3.3, GPT-4o, and DeepSeek endpoints. "
            "Set via OXLO_API_KEY environment variable."
        ),
    )
    oxlo_base_url: AnyHttpUrl = Field(
        default="https://api.oxlo.ai/v1",        # type: ignore[assignment]
        description="Base URL for all Oxlo API calls.",
    )
    oxlo_timeout_s: float = Field(
        default=120.0,
        ge=5.0,
        le=600.0,
        description="Per-request HTTP timeout in seconds for LLM calls.",
    )
    oxlo_max_retries: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Maximum retry attempts on transient Oxlo errors (429, 502, 503).",
    )
    oxlo_retry_backoff_s: float = Field(
        default=2.0,
        ge=0.1,
        description="Base back-off delay (seconds) between retries; doubles each attempt.",
    )

    # ── Model identifiers ────────────────────────────────────────────────
    llama_model: str = Field(
        default="meta-llama/llama-3.3-70b-instruct",
        description="Oxlo model ID for Phase 1 (Legal Auditor).",
    )
    gpt4o_model: str = Field(
        default="gpt-4o",
        description="Oxlo model ID for Phase 2 (Risk Judge).",
    )
    deepseek_model: str = Field(
        default="deepseek-ai/DeepSeek-Coder-V2-Instruct",
        description="Oxlo model ID for Phase 3 (Code Architect).",
    )

    # ── Model hyper-parameters ───────────────────────────────────────────
    auditor_temperature: float = Field(
        default=0.05,
        ge=0.0,
        le=2.0,
        description="Temperature for the Auditor (Llama). Low = deterministic legal analysis.",
    )
    judge_temperature: float = Field(
        default=0.10,
        ge=0.0,
        le=2.0,
        description="Temperature for the Judge (GPT-4o). Slightly higher for nuanced scoring.",
    )
    architect_temperature: float = Field(
        default=0.20,
        ge=0.0,
        le=2.0,
        description="Temperature for the Architect (DeepSeek). Higher = more creative refactors.",
    )
    max_tokens_auditor:   int = Field(default=4096,  ge=256, le=32768)
    max_tokens_judge:     int = Field(default=2048,  ge=256, le=16384)
    max_tokens_architect: int = Field(default=8192,  ge=512, le=65536)

    # ── FastAPI server ───────────────────────────────────────────────────
    host: str = Field(default="0.0.0.0", description="Bind address for uvicorn.")
    port: int = Field(default=8000, ge=1024, le=65535, description="Listen port.")
    workers: int = Field(
        default=1,
        ge=1,
        le=32,
        description="Number of uvicorn worker processes (use 1 for dev).",
    )
    allowed_origins: list[str] = Field(
        default=[
            "http://localhost:3000",
            "http://localhost:5173",
            "https://app.oxbuild.ai",
        ],
        description="CORS allowed origins list.",
    )

    # ── State manager (local bridge) ─────────────────────────────────────
    state_db_path: Path = Field(
        default=_PROJECT_ROOT / "local_bridge" / "data" / "state.db",
        description="Path to the SQLite vault used by StateManager.",
    )
    state_json_backup_path: Path = Field(
        default=_PROJECT_ROOT / "local_bridge" / "data" / "state_backup.json",
        description="JSON backup written alongside the SQLite vault.",
    )

    # ── Security ─────────────────────────────────────────────────────────
    api_secret_key: SecretStr = Field(
        default=SecretStr("change-me-in-production-at-least-32-chars"),
        description="HMAC secret for signing internal request tokens.",
    )
    max_code_length: int = Field(
        default=500_000,
        ge=100,
        description="Maximum character length of submitted source code.",
    )

    # ── Observability ────────────────────────────────────────────────────
    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Root log level for the orchestrator process.",
    )
    log_json: bool = Field(
        default=False,
        description="Emit logs as JSON (for log aggregators). False = human-readable.",
    )
    sentry_dsn: SecretStr | None = Field(
        default=None,
        description="Optional Sentry DSN for error tracking.",
    )

    # ── Feature flags ────────────────────────────────────────────────────
    enable_mock_llm: bool = Field(
        default=True,
        description=(
            "When True, pipeline agents return deterministic mock responses "
            "instead of calling Oxlo. Useful for CI and local development."
        ),
    )
    enable_pii_audit_log: bool = Field(
        default=False,
        description=(
            "When True, each scan's redaction token list is written to the "
            "audit log (NOT the original values). For compliance trail purposes."
        ),
    )

    # ── Validators ───────────────────────────────────────────────────────

    @field_validator("debug", mode="before")
    @classmethod
    def no_debug_in_production(cls, v: Any, info: Any) -> bool:
        # Access other fields via info.data (available after prior fields validated)
        env = info.data.get("environment")
        if v and env == Environment.PRODUCTION:
            raise ValueError(
                "debug=True is not permitted in ENVIRONMENT=production. "
                "Set DEBUG=false in your production .env file."
            )
        return v

    @field_validator("state_db_path", "state_json_backup_path", mode="before")
    @classmethod
    def ensure_parent_dir(cls, v: Any) -> Path:
        path = Path(v)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    @field_validator("oxlo_api_key", mode="before")
    @classmethod
    def api_key_not_empty(cls, v: Any) -> Any:
        if isinstance(v, str) and not v.strip():
            raise ValueError(
                "OXLO_API_KEY must not be empty. "
                "Set it in your .env file or as an environment variable."
            )
        return v

    @model_validator(mode="after")
    def warn_insecure_defaults(self) -> "Settings":
        if self.environment == Environment.PRODUCTION:
            secret = self.api_secret_key.get_secret_value()
            if "change-me" in secret:
                raise ValueError(
                    "API_SECRET_KEY is still set to the insecure default. "
                    "Generate a strong secret: python -c \"import secrets; print(secrets.token_hex(32))\""
                )
        return self

    # ── Computed properties ───────────────────────────────────────────────

    @property
    def is_production(self) -> bool:
        return self.environment == Environment.PRODUCTION

    @property
    def is_development(self) -> bool:
        return self.environment == Environment.DEVELOPMENT

    @property
    def oxlo_base_url_str(self) -> str:
        return str(self.oxlo_base_url).rstrip("/")

    @property
    def effective_log_level(self) -> int:
        return getattr(logging, self.log_level.value)

    def configure_logging(self) -> None:
        """Apply log level and format to the root logger."""
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
        logger.debug(
            "Configuration loaded | env=%s debug=%s mock_llm=%s",
            self.environment.value,
            self.debug,
            self.enable_mock_llm,
        )

    def redacted_summary(self) -> dict[str, Any]:
        """Return a loggable dict with all secrets replaced by '[REDACTED]'."""
        return {
            "app_name":          self.app_name,
            "environment":       self.environment.value,
            "debug":             self.debug,
            "oxlo_base_url":     self.oxlo_base_url_str,
            "oxlo_api_key":      "[REDACTED]",
            "api_secret_key":    "[REDACTED]",
            "llama_model":       self.llama_model,
            "gpt4o_model":       self.gpt4o_model,
            "deepseek_model":    self.deepseek_model,
            "enable_mock_llm":   self.enable_mock_llm,
            "log_level":         self.log_level.value,
            "host":              self.host,
            "port":              self.port,
            "state_db_path":     str(self.state_db_path),
        }


# ---------------------------------------------------------------------------
# Cached singleton — import from anywhere: `from core.config import settings`
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return (and cache) the singleton Settings instance.
    Cached with ``lru_cache`` so .env is parsed exactly once per process.
    Call ``get_settings.cache_clear()`` in tests to force re-evaluation.
    """
    s = Settings()  # type: ignore[call-arg]
    s.configure_logging()
    logger.info("Settings loaded: %s", s.redacted_summary())
    return s


# Module-level alias for ergonomic imports
settings: Settings = get_settings()