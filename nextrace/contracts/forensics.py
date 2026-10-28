"""Historical forensics contracts (owner: central contracts; producer: Person 3 forensic engine).

Historical processing is a separate pipeline from live capture. It reads uploads or carved evidence,
never the live queues, and links its results into investigations only through the authorized
investigations service.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from nextrace.contracts.v1 import TECHNIQUE_RE, IPAddress, _aware, _Contract

JobStatus = Literal["queued", "running", "completed", "failed"]
AnalysisKind = Literal["flow_reconstruction", "scan_detection", "beacon_detection", "ioc_match", "timeline", "custom"]


class ForensicJobRequestV1(_Contract):
    """Request to analyse one upload or one evidence item. Exactly one source must be given."""

    requested_by: UUID
    investigation_id: UUID | None = None
    upload_id: UUID | None = None
    evidence_id: UUID | None = None
    analyses: list[AnalysisKind] = Field(min_length=1, max_length=16)
    params: dict[str, Any] = Field(default_factory=dict)
    time_budget_s: int = Field(default=600, ge=1, le=86400)

    @model_validator(mode="after")
    def _source(self) -> "ForensicJobRequestV1":
        if (self.upload_id is None) == (self.evidence_id is None):
            raise ValueError("exactly one of upload_id or evidence_id is required")
        return self


class ForensicJobStatusV1(_Contract):
    analysis_id: UUID
    status: JobStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    progress: float = Field(default=0.0, ge=0.0, le=1.0)
    error: str | None = Field(default=None, max_length=1000)
    finding_count: int = Field(default=0, ge=0)
    result_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("started_at", "completed_at")
    @classmethod
    def _tz(cls, v: datetime | None) -> datetime | None:
        return None if v is None else _aware(v)


class ForensicArtifactV1(_Contract):
    """Any derived file (extracted flow table, timeline, report). Content-addressed and immutable."""

    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)
    media_type: str = Field(pattern=r"^[a-z0-9.+-]+/[a-z0-9.+-]+$")
    kind: Literal["artifact", "report", "export"]
    derived_from_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")
    tool_version: str = Field(pattern=r"^[A-Za-z0-9_.+-]{1,32}$")
    produced_at: datetime

    @field_validator("produced_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)


class ForensicFindingV1(_Contract):
    """One dated observation extracted from historical data. `confidence` is the rule's self-assessment."""

    seq: int = Field(ge=1)
    ts: datetime
    src_ip: IPAddress | None = None
    dst_ip: IPAddress | None = None
    technique_id: str | None = Field(default=None, pattern=TECHNIQUE_RE)
    description: str = Field(min_length=1, max_length=2000)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    rule_id: str = Field(pattern=r"^[a-z0-9_.-]{1,64}$")

    @field_validator("ts")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)


class ForensicReportV1(_Contract):
    analysis_id: UUID
    investigation_id: UUID | None = None
    generated_at: datetime
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    analyses: list[AnalysisKind]
    summary: dict[str, Any] = Field(default_factory=dict)
    findings: list[ForensicFindingV1] = Field(default_factory=list, max_length=100_000)
    artifacts: list[ForensicArtifactV1] = Field(default_factory=list, max_length=1000)
    limitations: list[str] = Field(default_factory=list, max_length=64)

    @field_validator("generated_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)
