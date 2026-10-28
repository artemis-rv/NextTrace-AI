"""Module ports: the only surfaces modules may call on each other (owner: integration owner).

Each Protocol is implemented by exactly one module and consumed by the central pipeline. A module that
needs another module's data asks the pipeline (or a repository port), never the other module's tables.
Implementations are injected in nextrace.core.composition.
"""
from __future__ import annotations

from datetime import datetime
from typing import AsyncIterator, Iterable, Protocol, runtime_checkable
from uuid import UUID

from nextrace.contracts.findings import AlertV1, CorrelatedEventV1, RiskScoreV1
from nextrace.contracts.forensics import ForensicJobRequestV1, ForensicJobStatusV1, ForensicReportV1
from nextrace.contracts.models import (
    DetectionResultV1,
    ExplanationRequestV1,
    ExplanationResultV1,
    InferenceRequestV1,
    ModelVersionV1,
    ProgressionForecastV1,
    SimulationRequestV1,
    SimulationResultV1,
)
from nextrace.contracts.observations import CaptureHealthV1, FlowBatchV1
from nextrace.contracts.ops import ComponentHealthV1
from nextrace.contracts.response import ConnectorCommandV1, ConnectorResultV1, PolicyDecisionV1, PolicyInputV1
from nextrace.contracts.temporal import GraphSnapshotV1, StateSequenceV1
from nextrace.contracts.v1 import FlowRecordV1, PredictionV1, TemporalStateV1, VerificationResultV1


# ---- Person 4: live capture and parsing -------------------------------------------------------
@runtime_checkable
class CaptureSource(Protocol):
    """Yields ordered flow batches and health reports. Must apply its own backpressure policy."""

    async def batches(self) -> AsyncIterator[FlowBatchV1]: ...
    def health(self) -> CaptureHealthV1: ...
    async def stop(self) -> None: ...


# ---- Person 2: temporal sequencing and detection ---------------------------------------------
@runtime_checkable
class TemporalSequencer(Protocol):
    """Turns flows into temporal states (event-time windows with bounded lateness) and sequences."""

    def ingest(self, flows: Iterable[FlowRecordV1], sensor_id: UUID) -> list[TemporalStateV1]:
        """Returns states that *closed* as a result of this input (watermark advanced past them)."""
        ...

    def flush(self, sensor_id: UUID) -> list[TemporalStateV1]: ...
    def sequence(self, sensor_id: UUID, length: int, up_to: datetime | None = None) -> StateSequenceV1 | None:
        """Sequence ending at the state whose window_start == up_to (the round's own state), or the newest."""
        ...
    def late_flows_dropped(self) -> int: ...


@runtime_checkable
class Detector(Protocol):
    """LSTM+Attention detection/classification. Returns status 'unavailable' when it has no validated model."""

    def model_version(self) -> ModelVersionV1 | None: ...
    def detect(self, request: InferenceRequestV1) -> DetectionResultV1: ...
    def health(self) -> ComponentHealthV1: ...


# ---- Person 1: graph construction, GNN/GAT progression, world model, simulation ---------------
@runtime_checkable
class GraphBuilder(Protocol):
    def build(self, state: TemporalStateV1) -> GraphSnapshotV1: ...


@runtime_checkable
class ProgressionForecaster(Protocol):
    def model_version(self) -> ModelVersionV1 | None: ...
    def forecast(self, request: InferenceRequestV1, detection: DetectionResultV1) -> ProgressionForecastV1: ...
    def health(self) -> ComponentHealthV1: ...


@runtime_checkable
class Simulator(Protocol):
    def simulate(self, request: SimulationRequestV1) -> SimulationResultV1: ...
    def health(self) -> ComponentHealthV1: ...


# ---- central: explanation, correlation, policy ------------------------------------------------
@runtime_checkable
class Explainer(Protocol):
    def explain(self, request: ExplanationRequestV1) -> ExplanationResultV1: ...
    def health(self) -> ComponentHealthV1: ...


@runtime_checkable
class Correlator(Protocol):
    def correlate(self, run_id: UUID, sensor_id: UUID, predictions: list[PredictionV1], now: datetime) -> list[CorrelatedEventV1]: ...
    def late_match(self, now: datetime) -> list[CorrelatedEventV1]:
        """Re-evaluate open events against historical patterns after their grace period (delayed matching)."""
        ...


@runtime_checkable
class RiskScorer(Protocol):
    def score(self, event: CorrelatedEventV1, asset_criticality: float | None) -> RiskScoreV1: ...


@runtime_checkable
class PolicyEngine(Protocol):
    def evaluate(self, inp: PolicyInputV1) -> PolicyDecisionV1: ...


# ---- central: firewall connector and verifier -------------------------------------------------
@runtime_checkable
class FirewallConnector(Protocol):
    """Talks to one enforcement point. `execute` reports command acceptance only."""

    name: str

    def execute(self, command: ConnectorCommandV1) -> ConnectorResultV1: ...
    def verify(self, command: ConnectorCommandV1) -> VerificationResultV1: ...
    def health(self) -> ComponentHealthV1: ...


# ---- Person 3: historical forensics -----------------------------------------------------------
@runtime_checkable
class ForensicEngine(Protocol):
    def submit(self, request: ForensicJobRequestV1) -> UUID: ...
    def run_next(self) -> ForensicJobStatusV1 | None: ...
    def status(self, analysis_id: UUID) -> ForensicJobStatusV1: ...
    def report(self, analysis_id: UUID, actor_id: UUID) -> ForensicReportV1: ...


# ---- central: alert sink ------------------------------------------------------------------------
@runtime_checkable
class AlertSink(Protocol):
    def emit(self, alert: AlertV1) -> UUID: ...
