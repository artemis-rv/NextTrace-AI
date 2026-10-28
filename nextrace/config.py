"""Validated runtime configuration. Every value comes from the environment (or a .env file).

Secrets (database password inside the URL, pseudonym pepper, API secrets) are never logged:
`Settings.safe_dict()` is the only representation that should ever be printed.

Values marked RESEARCH REQUIRED are operating parameters with no validated default. They are
configuration, not constants, so that tuning them never needs a code change, and they are reported
as such in /health and the docs until a measured value replaces them.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NEXTRACE_", env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ---- storage (database layer) -------------------------------------------------------------
    database_url: SecretStr = Field(description="SQLAlchemy URL, e.g. postgresql+psycopg2://user:pw@host/db")
    redis_url: SecretStr = Field(default=SecretStr("redis://127.0.0.1:6379/0"))
    object_store_root: Path = Field(default=Path("./var/objects"))
    pseudonym_pepper: SecretStr = Field(description="HMAC key for IP pseudonyms used in exports/explanations")

    flow_retention_days: int = Field(default=183, ge=1)
    state_retention_days: int = Field(default=183, ge=1)
    state_edge_retention_days: int = Field(default=14, ge=1)
    forecast_retention_days: int = Field(default=365, ge=1)
    audit_retention_days: int = Field(default=730, ge=30)
    header_pcap_retention_days: int = Field(default=183, ge=1)
    full_pcap_retention_hours: int = Field(default=72, ge=1)
    pcap_budget_bytes: int = Field(default=100 * 1024**3, ge=1024**2)
    partition_days_ahead: int = Field(default=3, ge=1, le=30)

    state_window_seconds: int = Field(default=10, ge=1, le=3600)
    cache_max_states: int = Field(default=360, ge=1, le=100_000)
    cache_ttl_seconds: int = Field(default=3600, ge=1)
    upload_max_bytes: int = Field(default=2 * 1024**3, ge=1)

    # ---- pipeline / backbone --------------------------------------------------------------------
    environment: Literal["dev", "test", "staging", "prod"] = "dev"
    log_json: bool = Field(default=True)
    log_level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR)$")
    queue_capacity: int = Field(default=1000, ge=1, le=1_000_000, description="bounded in-process queue per stage")
    backpressure_policy: Literal["block", "shed_oldest", "reject"] = Field(
        default="block", description="block: producer awaits; shed_oldest: drop oldest and count; reject: raise Backpressure")
    worker_concurrency: int = Field(default=2, ge=1, le=64)

    # Temporal sequencing. Allowed lateness follows the stream-processing pattern (Flink allowed lateness);
    # the default here is an operating choice, not a validated value. RESEARCH REQUIRED.
    sequencer_allowed_lateness_s: int = Field(default=30, ge=0, le=3600)
    sequence_length: int = Field(default=20, ge=2, le=4096, description="states per LSTM input; T=20 best on CIC-IDS2017 per arXiv 2606.11098, RESEARCH REQUIRED for this data")
    forecast_horizon_s: int = Field(default=300, ge=1, le=86400 * 7, description="RESEARCH REQUIRED")

    # Model slots: object-store sha256 of the artifact to load, or empty = unavailable (never a stub).
    detection_model_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    progression_model_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    world_model_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    heuristic_baseline_enabled: bool = Field(default=True, description="deterministic rule baseline; labelled as such, never as ML")
    heuristic_failed_ratio: float = Field(default=0.5, ge=0, le=1, description="baseline rule parameter, RESEARCH REQUIRED")
    heuristic_min_distinct_ports: int = Field(default=50, ge=1, description="baseline rule parameter, RESEARCH REQUIRED")
    heuristic_min_flows: int = Field(default=20, ge=1)

    # Correlation and risk. Weights are recorded on every score so they can be audited and re-derived.
    correlation_window_s: int = Field(default=600, ge=1, le=86400, description="entity grouping window, RESEARCH REQUIRED")
    correlation_grace_s: int = Field(default=900, ge=0, le=86400, description="delayed-matching grace period, RESEARCH REQUIRED")
    risk_weights_version: str = Field(default="w1-unvalidated", pattern=r"^[A-Za-z0-9_.-]{1,32}$")
    risk_w_probability: float = Field(default=0.4, ge=0, le=1)
    risk_w_pattern: float = Field(default=0.2, ge=0, le=1)
    risk_w_asset: float = Field(default=0.25, ge=0, le=1)
    risk_w_breadth: float = Field(default=0.15, ge=0, le=1)
    risk_sev_high: float = Field(default=0.75, ge=0, le=1, description="severity bands, RESEARCH REQUIRED")
    risk_sev_medium: float = Field(default=0.5, ge=0, le=1)
    risk_sev_low: float = Field(default=0.25, ge=0, le=1)

    # Response policy. Dry-run until an operator sets enforcement_mode=enforce AND a connector passed verification tests.
    enforcement_mode: Literal["dry_run", "enforce"] = "dry_run"
    policy_version: str = Field(default="p1-dryrun", pattern=r"^[A-Za-z0-9_.-]{1,32}$")
    policy_auto_allow_enabled: bool = Field(default=False, description="never auto-allow until thresholds are validated")
    policy_auto_allow_min_risk: float = Field(default=0.9, ge=0, le=1, description="RESEARCH REQUIRED")
    policy_max_duration_s: int = Field(default=24 * 3600, ge=60)
    policy_max_duration_critical_asset_s: int = Field(default=3600, ge=60)
    policy_require_dfir_for_isolate: bool = True
    verification_retry_limit: int = Field(default=3, ge=0, le=20)
    verification_delay_s: int = Field(default=5, ge=0, le=3600)

    # Explanations. LLM off by default; when on, output is schema-checked and can never authorize anything.
    llm_enabled: bool = False
    llm_endpoint: str | None = Field(default=None, pattern=r"^https?://[A-Za-z0-9_.:-]+(/.*)?$")
    llm_api_key: SecretStr | None = None
    llm_timeout_s: int = Field(default=20, ge=1, le=300)
    shap_background_rows: int = Field(default=200, ge=10, le=5000)

    # API
    api_rate_limit_per_minute: int = Field(default=600, ge=1)
    api_max_body_bytes: int = Field(default=1024 * 1024, ge=1024)
    api_cors_origins: list[str] = Field(default_factory=list)

    @field_validator("pseudonym_pepper")
    @classmethod
    def _pepper_strength(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < 32:
            raise ValueError("NEXTRACE_PSEUDONYM_PEPPER must be at least 32 characters")
        return v

    @field_validator("database_url")
    @classmethod
    def _db_driver(cls, v: SecretStr) -> SecretStr:
        if not v.get_secret_value().startswith("postgresql"):
            raise ValueError("NEXTRACE_DATABASE_URL must be a postgresql URL")
        return v

    @model_validator(mode="after")
    def _consistency(self) -> "Settings":
        if abs((self.risk_w_probability + self.risk_w_pattern + self.risk_w_asset + self.risk_w_breadth) - 1.0) > 1e-6:
            raise ValueError("risk weights must sum to 1")
        if not (self.risk_sev_low < self.risk_sev_medium < self.risk_sev_high):
            raise ValueError("severity bands must be strictly increasing")
        if self.llm_enabled and not self.llm_endpoint:
            raise ValueError("NEXTRACE_LLM_ENDPOINT is required when the LLM is enabled")
        if self.enforcement_mode == "enforce" and self.environment in ("dev", "test"):
            raise ValueError("enforcement_mode=enforce is not allowed in dev/test environments")
        return self

    def research_required(self) -> dict[str, object]:
        """Parameters in use that have no validated basis yet; surfaced in /health and docs."""
        keys = ["sequencer_allowed_lateness_s", "sequence_length", "forecast_horizon_s", "heuristic_failed_ratio",
                "heuristic_min_distinct_ports", "correlation_window_s", "correlation_grace_s", "risk_weights_version",
                "risk_sev_high", "risk_sev_medium", "risk_sev_low", "policy_auto_allow_min_risk"]
        return {k: getattr(self, k) for k in keys}

    def safe_dict(self) -> dict:
        """Configuration without secrets, for logs and diagnostics."""
        d = self.model_dump()
        for k in ("database_url", "redis_url", "pseudonym_pepper", "llm_api_key"):
            d[k] = "<redacted>" if d.get(k) is not None else None
        d["object_store_root"] = str(self.object_store_root)
        return d


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
