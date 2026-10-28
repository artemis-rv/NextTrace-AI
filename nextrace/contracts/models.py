"""Model, inference, forecast, simulation and explanation contracts (owner: central contracts;
producers: Person 2 detection, Person 1 forecasting/world model, central explanation module).

A model that cannot answer says so (`status='unavailable'`) and the pipeline records the gap.
No module may return `completed` with invented numbers.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from nextrace.contracts.temporal import GraphSequenceV1, GraphSnapshotV1, StateSequenceV1
from nextrace.contracts.v1 import TECHNIQUE_RE, ExplanationV1, PredictionV1, ProgressionStepV1, _aware, _Contract

ModelKind = Literal["lstm_attention", "gnn", "world_model", "llm", "heuristic_baseline", "other"]
ModelStatus = Literal["candidate", "active", "retired"]
ResultStatus = Literal["completed", "unavailable", "failed", "refused"]


class ModelVersionV1(_Contract):
    """Registry entry. `artifact_sha256` points at the object store; `evaluation` is what was measured,
    on which split, never a claim about production performance."""

    model_version_id: UUID | None = None
    name: str = Field(pattern=r"^[a-z0-9_.-]{1,64}$")
    kind: ModelKind
    version: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    feature_schema_id: UUID | None = None
    training_dataset_id: UUID | None = None
    artifact_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    hyperparameters: dict[str, Any] = Field(default_factory=dict)
    evaluation: dict[str, Any] = Field(default_factory=dict, description="metrics keyed by split, plus split manifest id")
    calibration: dict[str, Any] = Field(default_factory=dict, description="e.g. {'method':'temperature','T':1.7,'ece_val':0.03}")
    status: ModelStatus = "candidate"
    code_ref: str | None = Field(default=None, max_length=200, description="git commit / module path that produced it")


class InferenceRequestV1(_Contract):
    request_id: UUID
    sensor_id: UUID
    requested_at: datetime
    sequence: StateSequenceV1
    horizon_seconds: int = Field(ge=1, le=86400 * 7)
    graph: GraphSequenceV1 | None = None

    @field_validator("requested_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)


class DetectionResultV1(_Contract):
    """Output of the detection/classification model for one request."""

    request_id: UUID
    model_version_id: UUID | None = None
    status: ResultStatus
    reason: str | None = Field(default=None, max_length=500, description="why unavailable/failed/refused")
    predictions: list[PredictionV1] = Field(default_factory=list, max_length=4096)
    calibrated: bool = False
    attention: dict[str, Any] | None = Field(default=None, description="per-step weights for explanation; not evidence")
    latency_ms: float | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _honest(self) -> "DetectionResultV1":
        if self.status == "completed" and self.model_version_id is None:
            raise ValueError("completed results must name the model version that produced them")
        if self.status != "completed" and self.predictions:
            raise ValueError("non-completed results cannot carry predictions")
        if self.status != "completed" and not self.reason:
            raise ValueError("non-completed results must give a reason")
        return self


class ProgressionForecastV1(_Contract):
    """Output of the progression model (GNN/GAT or world model) for one request."""

    request_id: UUID
    model_version_id: UUID | None = None
    status: ResultStatus
    reason: str | None = Field(default=None, max_length=500)
    steps: list[ProgressionStepV1] = Field(default_factory=list, max_length=256)
    uncertainty: dict[str, Any] = Field(default_factory=dict, description="e.g. ensemble spread, entropy; empty when unknown")
    horizon_seconds: int = Field(ge=1, le=86400 * 7)
    latency_ms: float | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _honest(self) -> "ProgressionForecastV1":
        if self.status == "completed" and self.model_version_id is None:
            raise ValueError("completed forecasts must name the model version")
        if self.status != "completed" and self.steps:
            raise ValueError("non-completed forecasts cannot carry steps")
        if self.status != "completed" and not self.reason:
            raise ValueError("non-completed forecasts must give a reason")
        return self


class InterventionV1(_Contract):
    kind: Literal["block_ip", "block_pair", "isolate_host", "rate_limit", "patch_host", "none"]
    target_host_id: UUID | None = None
    peer_host_id: UUID | None = None
    at_step: int = Field(default=1, ge=1, le=64)


class SimulationRequestV1(_Contract):
    """What-if rollout over a learned or rule-based transition model. Results are hypotheses."""

    simulation_id: UUID
    base_run_id: UUID
    requested_by: UUID | None = None
    start: GraphSnapshotV1
    start_technique_id: str | None = Field(default=None, pattern=TECHNIQUE_RE, description="last observed technique the rollout starts from")
    interventions: list[InterventionV1] = Field(default_factory=list, max_length=32)
    n_rollouts: int = Field(default=100, ge=1, le=10_000)
    horizon_steps: int = Field(default=8, ge=1, le=64)
    seed: int | None = Field(default=None, ge=0)


class SimulationResultV1(_Contract):
    simulation_id: UUID
    model_version_id: UUID | None = None
    status: ResultStatus
    reason: str | None = Field(default=None, max_length=500)
    progression: list[ProgressionStepV1] = Field(default_factory=list, max_length=256)
    rollout_summary: dict[str, Any] = Field(default_factory=dict, description="aggregate over rollouts: hit rates per host/technique")
    result_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$", description="full rollouts in object store")
    disclaimer: str = "Simulated progression under stated assumptions. Not an observation."

    @model_validator(mode="after")
    def _honest(self) -> "SimulationResultV1":
        if self.status != "completed" and (self.progression or self.rollout_summary):
            raise ValueError("non-completed simulations cannot carry results")
        if self.status != "completed" and not self.reason:
            raise ValueError("non-completed simulations must give a reason")
        return self


class ExplanationRequestV1(_Contract):
    request_id: UUID
    run_id: UUID | None = None
    prediction_index: int | None = Field(default=None, ge=0)
    kind: Literal["shap", "llm"]
    sequence: StateSequenceV1 | None = None
    predictions: list[PredictionV1] = Field(default_factory=list, max_length=64)
    progression: list[ProgressionStepV1] = Field(default_factory=list, max_length=64)
    audience: Literal["analyst", "report"] = "analyst"
    max_tokens: int = Field(default=600, ge=50, le=4000)


class ExplanationResultV1(_Contract):
    request_id: UUID
    status: ResultStatus
    reason: str | None = Field(default=None, max_length=500)
    explanation: ExplanationV1 | None = None
    guardrail_flags: list[str] = Field(default_factory=list, max_length=32,
                                       description="violations detected in LLM output (e.g. 'contains_ip', 'instruction_like')")
    disclaimer: str = "Explanation of model output. Not evidence that an attack occurred."

    @model_validator(mode="after")
    def _honest(self) -> "ExplanationResultV1":
        if self.status == "completed" and self.explanation is None:
            raise ValueError("completed explanation results must carry an explanation")
        if self.status != "completed" and not self.reason:
            raise ValueError("non-completed explanation results must give a reason")
        return self


class InferenceRunV1(_Contract):
    """Compact provenance of one orchestration round: what went in, which models answered, what came out.
    Persisted through services.forecast.record_run (immutable rows)."""

    request: InferenceRequestV1
    detection: DetectionResultV1
    progression: ProgressionForecastV1 | None = None
    explanations: list[ExplanationResultV1] = Field(default_factory=list, max_length=64)
    started_at: datetime
    completed_at: datetime
    run_id: UUID | None = None

    @field_validator("started_at", "completed_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)

    @model_validator(mode="after")
    def _order(self) -> "InferenceRunV1":
        if self.completed_at < self.started_at:
            raise ValueError("completed_at precedes started_at")
        return self


class TechniqueRef(_Contract):
    technique_id: str = Field(pattern=TECHNIQUE_RE)
    tactic: str | None = Field(default=None, pattern=r"^[a-z-]{3,48}$")
    attack_version: str = Field(default="20.0", pattern=r"^[0-9]{1,2}\.[0-9]{1,2}$")
