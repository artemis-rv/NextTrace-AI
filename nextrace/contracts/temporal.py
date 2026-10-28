"""Temporal-state, sequence and graph contracts (owner: central contracts; co-designed with Persons 1, 2, 4).

`TemporalStateV1` (v1.py) is the unit of analysis. This module adds the shapes the models consume:
a fixed-length ordered sequence of states for the LSTM, and a graph snapshot for the GNN. Both carry
the feature schema id so a model can refuse input built with a schema it was not trained on.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from nextrace.contracts.v1 import TemporalStateV1, _aware, _Contract


class FeatureSnapshotV1(_Contract):
    """A versioned feature vector. Models check `feature_schema_id` before consuming `values`."""

    feature_schema_id: UUID
    schema_name: str = Field(pattern=r"^[a-z0-9_]{1,64}$")
    schema_version: int = Field(ge=1)
    values: list[float] = Field(min_length=1, max_length=4096)

    @field_validator("values")
    @classmethod
    def _finite(cls, v: list[float]) -> list[float]:
        for x in v:
            if x != x or x in (float("inf"), float("-inf")):
                raise ValueError("feature values must be finite")
        return v


class StateSequenceV1(_Contract):
    """Ordered, gap-annotated window of states for sequence models. Oldest first, strictly increasing."""

    sensor_id: UUID
    feature_schema_id: UUID
    window_seconds: int = Field(ge=1, le=3600)
    states: list[TemporalStateV1] = Field(min_length=1, max_length=4096)
    missing_windows: list[datetime] = Field(default_factory=list, max_length=4096,
                                           description="window starts inside the span with no state (gaps are data)")
    complete: bool = Field(description="True when no window inside the span is missing")

    @field_validator("missing_windows")
    @classmethod
    def _tz(cls, v: list[datetime]) -> list[datetime]:
        return [_aware(x) for x in v]

    @model_validator(mode="after")
    def _ordered(self) -> "StateSequenceV1":
        for a, b in zip(self.states, self.states[1:]):
            if b.window_start <= a.window_start:
                raise ValueError("states must be strictly increasing in window_start")
        for s in self.states:
            if s.sensor_id != self.sensor_id:
                raise ValueError("sequence mixes sensors")
            if s.window_seconds != self.window_seconds:
                raise ValueError("sequence mixes window lengths")
        if self.complete and self.missing_windows:
            raise ValueError("complete sequences cannot list missing windows")
        return self

    @property
    def span(self) -> tuple[datetime, datetime]:
        return self.states[0].window_start, self.states[-1].window_start


class GraphNodeV1(_Contract):
    host_id: UUID
    pseudonym: str = Field(pattern=r"^[0-9a-f]{64}$", description="HMAC pseudonym; raw IPs never enter graph contracts")
    zone: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    asset_tag: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    features: list[float] = Field(default_factory=list, max_length=256)


class GraphEdgeV1(_Contract):
    src: int = Field(ge=0, description="index into nodes")
    dst: int = Field(ge=0)
    features: list[float] = Field(min_length=1, max_length=256)


class GraphSnapshotV1(_Contract):
    """One temporal state as a graph: hosts are nodes, aggregated host->host traffic are edges."""

    state_id: UUID
    sensor_id: UUID
    window_start: datetime
    window_seconds: int = Field(ge=1, le=3600)
    node_feature_schema_id: UUID | None = None
    edge_feature_schema_id: UUID
    nodes: list[GraphNodeV1] = Field(max_length=100_000)
    edges: list[GraphEdgeV1] = Field(max_length=1_000_000)

    @field_validator("window_start")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)

    @model_validator(mode="after")
    def _refs(self) -> "GraphSnapshotV1":
        n = len(self.nodes)
        for e in self.edges:
            if e.src >= n or e.dst >= n:
                raise ValueError("edge references a node index that does not exist")
        return self


class GraphSequenceV1(_Contract):
    """Consecutive graph snapshots for dynamic-graph / world-model inputs (oldest first)."""

    sensor_id: UUID
    snapshots: list[GraphSnapshotV1] = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def _ordered(self) -> "GraphSequenceV1":
        for a, b in zip(self.snapshots, self.snapshots[1:]):
            if b.window_start <= a.window_start:
                raise ValueError("snapshots must be strictly increasing")
        return self


class SplitManifestV1(_Contract):
    """Chronological dataset split. Leakage rule: train < validation < test in time, no overlap,
    scalers fitted on train only (Arp et al. 2022: temporal snooping)."""

    dataset_id: UUID
    strategy: Literal["chronological", "chronological_grouped_by_host"] = "chronological"
    train_end: datetime
    validation_end: datetime
    test_end: datetime
    gap_seconds: int = Field(default=0, ge=0, description="embargo between splits so sequences never straddle")
    row_counts: dict[str, int] = Field(default_factory=dict)

    @field_validator("train_end", "validation_end", "test_end")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)

    @model_validator(mode="after")
    def _order(self) -> "SplitManifestV1":
        if not (self.train_end < self.validation_end < self.test_end):
            raise ValueError("splits must be strictly ordered in time")
        return self
