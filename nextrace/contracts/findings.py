"""Correlation, alert, finding, risk and investigation-update contracts (owner: central contracts).

Vocabulary: a *prediction* is model output; a *correlated event* groups predictions/alerts that share an
entity and a time window; an *alert* is what reaches an analyst; a *finding* is an analyst- or
rule-confirmed statement tied to evidence. Observed facts, predictions and explanations stay separate.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from nextrace.contracts.v1 import TECHNIQUE_RE, _aware, _Contract

Severity = Literal["low", "medium", "high", "critical"]


class EntityRefV1(_Contract):
    kind: Literal["host", "host_pair", "sensor", "subnet"]
    host_id: UUID | None = None
    peer_host_id: UUID | None = None
    sensor_id: UUID | None = None
    pseudonym: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class CorrelatedEventV1(_Contract):
    """Output of the correlator: deduplicated, grouped observations with optional pattern match."""

    event_id: UUID
    sensor_id: UUID
    entity: EntityRefV1
    first_seen: datetime
    last_seen: datetime
    source_run_ids: list[UUID] = Field(min_length=1, max_length=4096)
    prediction_count: int = Field(ge=1)
    duplicate_count: int = Field(ge=0, description="predictions collapsed by the dedupe key")
    technique_ids: list[str] = Field(default_factory=list, max_length=64)
    max_probability: float = Field(ge=0.0, le=1.0)
    matched_pattern_id: str | None = Field(default=None, pattern=r"^[a-z0-9_.-]{1,64}$")
    pattern_match_score: float | None = Field(default=None, ge=0.0, le=1.0)
    late_matched: bool = Field(default=False, description="matched after the grace window by delayed matching")

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)

    @field_validator("technique_ids")
    @classmethod
    def _tech(cls, v: list[str]) -> list[str]:
        import re
        for t in v:
            if not re.match(TECHNIQUE_RE, t):
                raise ValueError(f"invalid technique id {t!r}")
        return v

    @model_validator(mode="after")
    def _order(self) -> "CorrelatedEventV1":
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen precedes first_seen")
        return self


class RiskScoreV1(_Contract):
    """Transparent risk score: every input and weight is recorded so analysts can audit the number.
    Weights come from configuration (RiskWeights); none are validated against ground truth yet."""

    score: float = Field(ge=0.0, le=1.0)
    severity: Severity
    inputs: dict[str, float] = Field(description="probability, pattern_match, asset_criticality, recency, breadth ...")
    weights: dict[str, float]
    formula: str = Field(max_length=200)
    weights_version: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,32}$")


class AlertV1(_Contract):
    alert_id: UUID | None = None
    run_id: UUID
    prediction_id: UUID | None = None
    sensor_id: UUID
    severity: Severity
    title: str = Field(min_length=1, max_length=256)
    event: CorrelatedEventV1 | None = None
    risk: RiskScoreV1 | None = None
    status: Literal["new", "acknowledged", "escalated", "closed"] = "new"
    created_at: datetime | None = None

    @field_validator("created_at")
    @classmethod
    def _tz(cls, v: datetime | None) -> datetime | None:
        return None if v is None else _aware(v)


class FindingV1(_Contract):
    """A statement an analyst or a deterministic rule stands behind, with the evidence it rests on.
    `basis` says what kind of support it has; model output alone is 'predicted', never 'confirmed'."""

    finding_id: UUID | None = None
    investigation_id: UUID
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=4000)
    basis: Literal["predicted", "rule", "analyst_confirmed", "forensic"]
    technique_ids: list[str] = Field(default_factory=list, max_length=64)
    entities: list[EntityRefV1] = Field(default_factory=list, max_length=256)
    evidence_ids: list[UUID] = Field(default_factory=list, max_length=256)
    source_alert_ids: list[UUID] = Field(default_factory=list, max_length=256)
    source_forensic_finding_ids: list[UUID] = Field(default_factory=list, max_length=256)
    created_by: UUID | None = None
    created_at: datetime | None = None

    @field_validator("technique_ids")
    @classmethod
    def _tech(cls, v: list[str]) -> list[str]:
        import re
        for t in v:
            if not re.match(TECHNIQUE_RE, t):
                raise ValueError(f"invalid technique id {t!r}")
        return v

    @model_validator(mode="after")
    def _confirmed_needs_evidence(self) -> "FindingV1":
        if self.basis in ("analyst_confirmed", "forensic") and not self.evidence_ids:
            raise ValueError(f"{self.basis} findings must reference evidence")
        return self


class InvestigationUpdateV1(_Contract):
    """Mutation request on a case. The investigations service enforces case-level authorization."""

    investigation_id: UUID
    actor_id: UUID
    action: Literal["link_alert", "link_finding", "link_forensic_finding", "link_response_action", "set_status", "add_note", "assign"]
    object_id: UUID | None = None
    status: Literal["open", "in_progress", "closed"] | None = None
    note: str | None = Field(default=None, max_length=4000)
    assignee_id: UUID | None = None

    @model_validator(mode="after")
    def _args(self) -> "InvestigationUpdateV1":
        if self.action.startswith("link_") and self.object_id is None:
            raise ValueError("link actions need object_id")
        if self.action == "set_status" and self.status is None:
            raise ValueError("set_status needs status")
        if self.action == "add_note" and not self.note:
            raise ValueError("add_note needs note")
        if self.action == "assign" and self.assignee_id is None:
            raise ValueError("assign needs assignee_id")
        return self


class AnalystFeedbackV1(_Contract):
    """Recorded, audited, and NOT used for model adaptation unless a separate, reviewed process flips
    eligible_for_training (default false in the schema)."""

    prediction_id: UUID
    user_id: UUID
    verdict: Literal["true_positive", "false_positive", "benign_anomaly", "unknown"]
    note: str | None = Field(default=None, max_length=2000)


class DashboardSnapshotV1(_Contract):
    """What the dashboard reads: current state, not history. History lives in immutable runs."""

    sensor_id: UUID
    as_of: datetime
    current_run_id: UUID | None = None
    latest_state_window_start: datetime | None = None
    cache_state_count: int = Field(ge=0)
    open_alerts: int = Field(ge=0)
    enforced_actions: int = Field(ge=0)
    pending_authorizations: int = Field(ge=0)
    capture_health: dict[str, Any] | None = None
    model_availability: dict[str, str] = Field(default_factory=dict, description="slot -> 'active'|'unavailable'|'template'")

    @field_validator("as_of", "latest_state_window_start")
    @classmethod
    def _tz(cls, v: datetime | None) -> datetime | None:
        return None if v is None else _aware(v)
