"""Policy and firewall-response contracts (owner: central contracts / integration owner).

The chain is: proposal -> deterministic policy decision -> human or policy authorization -> connector
execution (command accepted) -> independent verification (rule enforced) -> expiry -> removal -> removal
verified. `ResponseActionProposalV1` and `VerificationResultV1` live in v1.py (storage contract).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from nextrace.contracts.v1 import ResponseActionProposalV1, _aware, _Contract

ActionStatus = Literal["proposed", "authorized", "rejected", "executing", "executed", "verified",
                       "verification_failed", "expired", "removed", "removal_verified", "failed"]
Decision = Literal["deny", "require_human", "allow_dry_run", "allow"]


class PolicyInputV1(_Contract):
    """Everything the policy engine is allowed to look at. No free text, no LLM output."""

    proposal: ResponseActionProposalV1
    risk_score: float | None = Field(default=None, ge=0.0, le=1.0)
    max_probability: float | None = Field(default=None, ge=0.0, le=1.0)
    pattern_match_score: float | None = Field(default=None, ge=0.0, le=1.0)
    asset_criticality: float | None = Field(default=None, ge=0.0, le=1.0, description="of the target; 1 = most critical")
    target_is_internal: bool | None = None
    target_on_allowlist: bool = False
    proposer_kind: Literal["analyst", "system", "llm_suggestion"] = "analyst"
    enforcement_mode: Literal["dry_run", "enforce"] = "dry_run"
    duration_s: int = Field(ge=1)
    open_actions_on_target: int = Field(default=0, ge=0)


class PolicyDecisionV1(_Contract):
    """Deterministic, explainable decision. `rules_fired` lists every rule that contributed."""

    decision: Decision
    rules_fired: list[str] = Field(min_length=1, max_length=64)
    reasons: list[str] = Field(min_length=1, max_length=64)
    policy_version: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,32}$")
    max_duration_s: int | None = Field(default=None, ge=1)
    requires_roles: list[Literal["analyst", "dfir", "admin"]] = Field(default_factory=list)
    evaluated_at: datetime

    @field_validator("evaluated_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)


class ConnectorCommandV1(_Contract):
    """What a firewall connector receives. Connectors never see case data or model output."""

    action_id: UUID
    action_type: Literal["block_ip", "block_pair", "rate_limit", "isolate_host"]
    target: str = Field(max_length=64)
    peer: str | None = Field(default=None, max_length=64)
    port: int | None = Field(default=None, ge=0, le=65535)
    direction: Literal["inbound", "outbound", "both"]
    enforcement_point: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    expires_at: datetime
    dry_run: bool
    idempotency_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation: Literal["install", "remove"] = "install"

    @field_validator("expires_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)


class ConnectorResultV1(_Contract):
    """Command acceptance only. Enforcement is established separately by VerificationResultV1."""

    action_id: UUID
    accepted: bool
    execution_ref: str | None = Field(default=None, max_length=200)
    response: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool
    at: datetime
    error: str | None = Field(default=None, max_length=1000)

    @field_validator("at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)

    @model_validator(mode="after")
    def _err(self) -> "ConnectorResultV1":
        if not self.accepted and not self.error:
            raise ValueError("rejected commands must carry an error")
        return self


class ActionExtensionRequestV1(_Contract):
    """Extending an enforced action is a new authorization: a different person, a reason, a bounded new expiry."""

    action_id: UUID
    requested_by: UUID
    new_expires_at: datetime
    reason: str = Field(min_length=8, max_length=2000)

    @field_validator("new_expires_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)


class RevocationRequestV1(_Contract):
    action_id: UUID
    requested_by: UUID
    reason: str = Field(min_length=8, max_length=2000)


class ResponseActionViewV1(_Contract):
    """Read model for API and dashboard."""

    action_id: UUID
    status: ActionStatus
    enforced: bool
    action_type: str
    target: str
    enforcement_point: str
    proposed_by: UUID | None
    authorized_by: UUID | None
    proposed_at: datetime
    expires_at: datetime
    verified_at: datetime | None = None
    verification_method: str | None = None
    execution_ref: str | None = None
    investigation_id: UUID | None = None
    alert_id: UUID | None = None
