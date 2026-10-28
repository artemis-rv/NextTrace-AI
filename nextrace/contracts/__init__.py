"""Canonical, versioned contracts. Everything crossing a module boundary is defined here and nowhere else.

Change policy (see docs/backend/module-contracts.md): additive optional fields bump nothing; any removal,
rename, type change or tightened validation requires a new `V2` model alongside `V1`, two approvals
(the integration owner plus one affected module owner) and a migration note. Modules import from
`nextrace.contracts`, never from each other's packages.
"""
from nextrace.contracts import errors, ports
from nextrace.contracts.findings import (
    AlertV1,
    AnalystFeedbackV1,
    CorrelatedEventV1,
    DashboardSnapshotV1,
    EntityRefV1,
    FindingV1,
    InvestigationUpdateV1,
    RiskScoreV1,
)
from nextrace.contracts.forensics import (
    ForensicArtifactV1,
    ForensicFindingV1,
    ForensicJobRequestV1,
    ForensicJobStatusV1,
    ForensicReportV1,
)
from nextrace.contracts.models import (
    DetectionResultV1,
    ExplanationRequestV1,
    ExplanationResultV1,
    InferenceRequestV1,
    InferenceRunV1,
    InterventionV1,
    ModelVersionV1,
    ProgressionForecastV1,
    SimulationRequestV1,
    SimulationResultV1,
    TechniqueRef,
)
from nextrace.contracts.observations import CaptureHealthV1, FlowBatchV1, PacketObservationV1
from nextrace.contracts.ops import AuditEventV1, ComponentHealthV1, HealthReportV1, PageQueryV1, TimeRangeQueryV1
from nextrace.contracts.response import (
    ActionExtensionRequestV1,
    ConnectorCommandV1,
    ConnectorResultV1,
    PolicyDecisionV1,
    PolicyInputV1,
    ResponseActionViewV1,
    RevocationRequestV1,
)
from nextrace.contracts.temporal import (
    FeatureSnapshotV1,
    GraphEdgeV1,
    GraphNodeV1,
    GraphSequenceV1,
    GraphSnapshotV1,
    SplitManifestV1,
    StateSequenceV1,
)
from nextrace.contracts.v1 import (
    EvidenceManifestV1,
    ExplanationV1,
    FlowRecordV1,
    ForecastResultV1,
    LiveEventV1,
    PredictionV1,
    ProgressionStepV1,
    ResponseActionProposalV1,
    TemporalStateV1,
    VerificationResultV1,
)

CONTRACT_VERSION = 1

__all__ = [n for n in dir() if n.endswith("V1") or n in ("TechniqueRef", "CONTRACT_VERSION", "errors", "ports")]
