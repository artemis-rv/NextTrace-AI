"""Contract honesty, compatibility and module isolation."""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

import nextrace.contracts as c
from nextrace.contracts import ports
from nextrace.contracts.models import DetectionResultV1, ProgressionForecastV1, SimulationResultV1
from nextrace.contracts.observations import FlowBatchV1
from nextrace.contracts.response import ConnectorResultV1
from nextrace.contracts.temporal import SplitManifestV1, StateSequenceV1
from nextrace.contracts.v1 import FlowRecordV1, TemporalStateV1

NOW = datetime.now(timezone.utc).replace(microsecond=0)
ROOT = Path(__file__).resolve().parent.parent


def _state(sensor, ws, w=10):
    return TemporalStateV1(state_id=uuid.uuid4(), sensor_id=sensor, window_start=ws, window_seconds=w, schema_version=1, n_flows=1, n_nodes=2,
                           n_edges=1, total_bytes=10, total_pkts=2, features=[1.0] * 10)


def test_results_cannot_fake_completion():
    rid = uuid.uuid4()
    with pytest.raises(ValidationError):
        DetectionResultV1(request_id=rid, status="completed")  # no model version
    with pytest.raises(ValidationError):
        DetectionResultV1(request_id=rid, status="unavailable")  # no reason
    with pytest.raises(ValidationError):
        ProgressionForecastV1(request_id=rid, status="failed", horizon_seconds=60)  # no reason
    with pytest.raises(ValidationError):
        SimulationResultV1(simulation_id=rid, status="unavailable", reason="x", rollout_summary={"a": 1})  # results on non-completed
    ok = DetectionResultV1(request_id=rid, status="unavailable", reason="no artifact")
    assert ok.predictions == []


def test_flow_batch_must_be_ordered():
    sid = uuid.uuid4()
    f1 = FlowRecordV1(ts_start=NOW - timedelta(seconds=5), src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=6)
    f2 = FlowRecordV1(ts_start=NOW - timedelta(seconds=9), src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=6)
    with pytest.raises(ValidationError):
        FlowBatchV1(sensor_id=sid, batch_seq=0, produced_at=NOW, source="pcap_replay", flows=[f1, f2])
    assert len(FlowBatchV1(sensor_id=sid, batch_seq=0, produced_at=NOW, source="pcap_replay", flows=[f2, f1]).flows) == 2


def test_sequence_rejects_mixed_sensors_and_disorder():
    a, b = uuid.uuid4(), uuid.uuid4()
    fs = uuid.uuid4()
    s1, s2 = _state(a, NOW), _state(a, NOW + timedelta(seconds=10))
    with pytest.raises(ValidationError):
        StateSequenceV1(sensor_id=a, feature_schema_id=fs, window_seconds=10, states=[s2, s1], complete=True)
    with pytest.raises(ValidationError):
        StateSequenceV1(sensor_id=a, feature_schema_id=fs, window_seconds=10, states=[s1, _state(b, NOW + timedelta(seconds=10))], complete=True)
    with pytest.raises(ValidationError):
        StateSequenceV1(sensor_id=a, feature_schema_id=fs, window_seconds=10, states=[s1, s2], complete=True, missing_windows=[NOW])
    seq = StateSequenceV1(sensor_id=a, feature_schema_id=fs, window_seconds=10, states=[s1, s2], complete=True)
    assert seq.span == (NOW, NOW + timedelta(seconds=10))


def test_split_manifest_is_chronological():
    with pytest.raises(ValidationError):
        SplitManifestV1(dataset_id=uuid.uuid4(), train_end=NOW, validation_end=NOW, test_end=NOW + timedelta(days=1))
    with pytest.raises(ValidationError):
        SplitManifestV1(dataset_id=uuid.uuid4(), train_end=NOW.replace(tzinfo=None), validation_end=NOW, test_end=NOW)


def test_connector_result_needs_error_when_rejected():
    with pytest.raises(ValidationError):
        ConnectorResultV1(action_id=uuid.uuid4(), accepted=False, dry_run=False, at=NOW)


def test_contract_exports_are_versioned():
    assert c.CONTRACT_VERSION == 1
    for name in c.__all__:
        assert name.endswith("V1") or name in ("TechniqueRef", "CONTRACT_VERSION", "errors", "ports"), name


def test_implementations_satisfy_ports():
    from nextrace.modules.capture.sources import LiveCaptureSource, PcapReplaySource
    from nextrace.modules.correlation.correlator import InMemoryCorrelator
    from nextrace.modules.correlation.risk import WeightedRiskScorer
    from nextrace.modules.detection.detector import HeuristicBaselineDetector, UnavailableDetector
    from nextrace.modules.explanation.llm import GuardedLLMExplainer
    from nextrace.modules.forecasting.forecaster import TransitionTableForecaster, UnavailableForecaster
    from nextrace.modules.forecasting.world_model import MonteCarloSimulator
    from nextrace.modules.forensics.engine import DbForensicEngine
    from nextrace.modules.response.connectors import DryRunConnector, InMemoryConnector
    from nextrace.modules.response.policy import RulePolicyEngine
    from nextrace.modules.temporal.sequencer import StreamingSequencer

    for cls, port in [(PcapReplaySource, ports.CaptureSource), (LiveCaptureSource, ports.CaptureSource), (StreamingSequencer, ports.TemporalSequencer),
                      (HeuristicBaselineDetector, ports.Detector), (UnavailableDetector, ports.Detector), (TransitionTableForecaster, ports.ProgressionForecaster),
                      (UnavailableForecaster, ports.ProgressionForecaster), (MonteCarloSimulator, ports.Simulator), (GuardedLLMExplainer, ports.Explainer),
                      (InMemoryCorrelator, ports.Correlator), (WeightedRiskScorer, ports.RiskScorer), (RulePolicyEngine, ports.PolicyEngine),
                      (DryRunConnector, ports.FirewallConnector), (InMemoryConnector, ports.FirewallConnector), (DbForensicEngine, ports.ForensicEngine)]:
        for method in [m for m in dir(port) if not m.startswith("_") and callable(getattr(port, m, None))]:
            assert hasattr(cls, method), f"{cls.__name__} lacks {port.__name__}.{method}"


def test_modules_do_not_import_each_other():
    """A module may import contracts, core, services, storage, db, parsing and config, never another module's package."""
    offenders = []
    for path in (ROOT / "nextrace" / "modules").rglob("*.py"):
        own = path.relative_to(ROOT / "nextrace" / "modules").parts[0]
        for m in re.findall(r"^\s*(?:from|import)\s+nextrace\.modules\.([a-z_]+)", path.read_text(encoding="utf-8"), flags=re.M):
            if m != own:
                offenders.append(f"{path.relative_to(ROOT)} -> modules.{m}")
    assert offenders == []


def test_services_do_not_import_modules():
    for path in list((ROOT / "nextrace" / "services").rglob("*.py")) + list((ROOT / "nextrace" / "storage").rglob("*.py")) + list((ROOT / "nextrace" / "contracts").rglob("*.py")):
        assert "nextrace.modules" not in path.read_text(encoding="utf-8"), path
