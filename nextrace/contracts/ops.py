"""Audit, health and dashboard-query contracts (owner: central contracts)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from nextrace.contracts.v1 import _aware, _Contract


class AuditEventV1(_Contract):
    """Shape of an audit entry as emitted by modules. Persisted by services.audit (hash-chained in the DB)."""

    action: str = Field(pattern=r"^[a-z_]+(\.[a-z_]+){1,3}$", description="dotted verb, e.g. response.authorize")
    actor_id: UUID | None = None
    actor_label: str | None = Field(default=None, max_length=128)
    object_type: str | None = Field(default=None, pattern=r"^[a-z_]{1,64}$")
    object_id: str | None = Field(default=None, max_length=64)
    details: dict[str, Any] = Field(default_factory=dict)
    client_ip: str | None = Field(default=None, max_length=45)


class ComponentHealthV1(_Contract):
    name: str = Field(pattern=r"^[a-z0-9_.-]{1,64}$")
    status: Literal["ok", "degraded", "down", "unknown", "template"]
    detail: str | None = Field(default=None, max_length=500)
    checked_at: datetime
    metrics: dict[str, float] = Field(default_factory=dict)

    @field_validator("checked_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)


class HealthReportV1(_Contract):
    status: Literal["ok", "degraded", "down"]
    at: datetime
    version: str
    components: list[ComponentHealthV1]

    @field_validator("at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)


class TimeRangeQueryV1(_Contract):
    """Bounded dashboard query. Ranges are capped so no query can scan unbounded history."""

    sensor_id: UUID | None = None
    start: datetime
    end: datetime
    limit: int = Field(default=200, ge=1, le=5000)
    max_span_seconds: int = Field(default=7 * 86400, ge=1, le=90 * 86400)

    @field_validator("start", "end")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)

    @model_validator(mode="after")
    def _span(self) -> "TimeRangeQueryV1":
        if self.end <= self.start:
            raise ValueError("end must be after start")
        if (self.end - self.start).total_seconds() > self.max_span_seconds:
            raise ValueError("query span exceeds the allowed maximum")
        return self


class PageQueryV1(_Contract):
    limit: int = Field(default=50, ge=1, le=500)
    cursor: str | None = Field(default=None, pattern=r"^[0-9a-f-]{36}$", description="last seen uuidv7 id")
