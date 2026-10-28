"""Versioned data contracts (v1) for everything that crosses a process boundary.

Producers: sensor adapters (flows), state builder (states), forecasting engine (forecast results),
analysts/UI (response proposals), firewall connector (verification results). Every model forbids
unknown fields and validates ranges so that malformed or hostile input is rejected before SQL.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

TECHNIQUE_RE = r"^T[0-9]{4}(\.[0-9]{3})?$"
MAX_FUTURE_SKEW = timedelta(minutes=5)
IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network | IPv4Address | IPv6Address


def _aware(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware (UTC)")
    return ts.astimezone(timezone.utc)


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_max_length=4096)
    version: Literal[1] = 1


class FlowRecordV1(_Contract):
    """One bidirectional flow (Zeek conn.log / Suricata flow / CICFlowMeter-style record)."""

    ts_start: datetime
    ts_end: datetime | None = None
    community_id: str | None = Field(default=None, pattern=r"^[0-9]+:[A-Za-z0-9+/]{27}=$")
    src_ip: IPAddress
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_ip: IPAddress
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    proto: int = Field(ge=0, le=255)
    service: str | None = Field(default=None, pattern=r"^[a-z0-9_,.-]{1,32}$")
    duration_ms: int | None = Field(default=None, ge=0)
    orig_bytes: int = Field(default=0, ge=0)
    resp_bytes: int = Field(default=0, ge=0)
    orig_pkts: int = Field(default=0, ge=0)
    resp_pkts: int = Field(default=0, ge=0)
    conn_state: str | None = Field(default=None, pattern=r"^[A-Z0-9]{1,8}$")
    history: str | None = Field(default=None, pattern=r"^[A-Za-z^]{1,64}$")
    pcap_segment_id: UUID | None = None
    features: list[float] | None = Field(default=None, max_length=512)
    feature_schema_id: UUID | None = None
    label: str | None = Field(default=None, pattern=r"^[A-Za-z0-9 _:-]{1,64}$")

    @field_validator("ts_start", "ts_end")
    @classmethod
    def _tz(cls, v: datetime | None) -> datetime | None:
        return None if v is None else _aware(v)

    @model_validator(mode="after")
    def _consistency(self) -> "FlowRecordV1":
        if self.ts_end is not None and self.ts_end < self.ts_start:
            raise ValueError("ts_end precedes ts_start")
        if self.ts_start > datetime.now(timezone.utc) + MAX_FUTURE_SKEW:
            raise ValueError("ts_start is in the future")
        if (self.features is None) != (self.feature_schema_id is None):
            raise ValueError("features and feature_schema_id must be given together")
        return self


class TemporalStateV1(_Contract):
    """Compact representation of one temporal network state (what the live cache holds)."""

    state_id: UUID
    sensor_id: UUID
    window_start: datetime
    window_seconds: int = Field(ge=1, le=3600)
    schema_version: int = Field(ge=1)
    n_flows: int = Field(ge=0)
    n_nodes: int = Field(ge=0)
    n_edges: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    total_pkts: int = Field(ge=0)
    summary: dict[str, Any] = Field(default_factory=dict)
    features: list[float] = Field(max_length=512)

    @field_validator("window_start")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)


class PredictionV1(_Contract):
    state_id: UUID
    window_start: datetime
    is_malicious: bool
    probability: float = Field(ge=0.0, le=1.0)
    category: str | None = Field(default=None, pattern=r"^[A-Za-z0-9 _/-]{1,64}$")
    attack_stage: str | None = Field(default=None, pattern=r"^[A-Za-z0-9 _/-]{1,64}$")
    technique_ids: list[str] = Field(default_factory=list, max_length=32)
    host_ids: list[UUID] = Field(default_factory=list, max_length=64, description="hosts implicated (optional, additive in v1.1)")

    @field_validator("technique_ids")
    @classmethod
    def _techniques(cls, v: list[str]) -> list[str]:
        import re
        for t in v:
            if not re.match(TECHNIQUE_RE, t):
                raise ValueError(f"invalid ATT&CK technique id {t!r}")
        return v

    @field_validator("window_start")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)


class ProgressionStepV1(_Contract):
    step: int = Field(ge=1, le=64)
    predicted_technique_id: str = Field(pattern=TECHNIQUE_RE)
    predicted_tactic: str | None = Field(default=None, pattern=r"^[a-z-]{3,48}$")
    target_host_id: UUID | None = None
    probability: float = Field(ge=0.0, le=1.0)
    expected_within_s: int | None = Field(default=None, ge=1)


class ExplanationV1(_Contract):
    kind: Literal["shap", "llm"]
    model_version_id: UUID | None = None
    prediction_index: int | None = Field(default=None, ge=0)
    content: dict[str, Any]
    artifact_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    prompt_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class ForecastResultV1(_Contract):
    """Output of one forecasting run. Recorded immutably; the newest completed run becomes current."""

    sensor_id: UUID
    model_version_id: UUID
    progression_model_version_id: UUID | None = None
    input_state_ids: list[UUID] = Field(min_length=1, max_length=4096)
    input_window_start: datetime
    input_window_end: datetime
    horizon_seconds: int = Field(ge=1, le=86400 * 7)
    started_at: datetime
    completed_at: datetime
    status: Literal["completed", "failed"]
    error: str | None = Field(default=None, max_length=2000)
    predictions: list[PredictionV1] = Field(default_factory=list, max_length=4096)
    progression: list[ProgressionStepV1] = Field(default_factory=list, max_length=256)
    explanations: list[ExplanationV1] = Field(default_factory=list, max_length=4096)

    @field_validator("input_window_start", "input_window_end", "started_at", "completed_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)

    @model_validator(mode="after")
    def _consistency(self) -> "ForecastResultV1":
        if self.completed_at < self.started_at:
            raise ValueError("completed_at precedes started_at")
        if self.input_window_end < self.input_window_start:
            raise ValueError("input window end precedes start")
        if self.status == "failed" and not self.error:
            raise ValueError("failed runs must carry an error")
        if self.status == "completed" and self.error:
            raise ValueError("completed runs cannot carry an error")
        for e in self.explanations:
            if e.prediction_index is not None and e.prediction_index >= len(self.predictions):
                raise ValueError("explanation refers to a prediction that does not exist")
        return self


class ResponseActionProposalV1(_Contract):
    """A proposed firewall action. Proposals never execute anything by themselves."""

    action_type: Literal["block_ip", "block_pair", "rate_limit", "isolate_host"]
    target: IPNetwork
    peer: IPAddress | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    direction: Literal["inbound", "outbound", "both"] = "both"
    enforcement_point: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    justification: str = Field(min_length=8, max_length=2000)
    expires_at: datetime
    alert_id: UUID | None = None
    investigation_id: UUID | None = None
    run_id: UUID | None = None

    @field_validator("expires_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        v = _aware(v)
        if v <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be in the future")
        return v

    @model_validator(mode="after")
    def _pair(self) -> "ResponseActionProposalV1":
        if self.action_type == "block_pair" and self.peer is None:
            raise ValueError("block_pair requires a peer")
        return self


class VerificationResultV1(_Contract):
    """Independent check that an executed action is actually enforced."""

    method: Literal["rule_readback", "probe", "traffic_observation", "manual"]
    enforced: bool
    observed: dict[str, Any] = Field(default_factory=dict)
    checked_at: datetime

    @field_validator("checked_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)


class EvidenceManifestV1(_Contract):
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)
    media_type: str = Field(pattern=r"^[a-z0-9.+-]+/[a-z0-9.+-]+$")
    kind: Literal["pcap_slice", "flow_export", "state_export", "artifact", "report", "upload"]
    description: str = Field(min_length=1, max_length=1000)
    acquisition_method: str = Field(min_length=1, max_length=200)
    source_sensor_id: UUID | None = None
    ts_first: datetime | None = None
    ts_last: datetime | None = None


class LiveEventV1(_Contract):
    """Message published on the live channel for WebSocket fan-out. Contains no payload bytes."""

    type: Literal["state", "forecast", "alert", "response_action"]
    sensor_id: UUID | None = None
    object_id: str = Field(max_length=64)
    at: datetime
    payload: dict[str, Any] = Field(default_factory=dict)
