"""Versioned contract validation rules."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from nextrace.contracts.v1 import FlowRecordV1, ForecastResultV1, PredictionV1, ResponseActionProposalV1

NOW = datetime.now(timezone.utc)
BASE = {"ts_start": NOW.isoformat(), "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "proto": 6}


def test_flow_minimal_ok():
    f = FlowRecordV1(**BASE)
    assert f.version == 1 and f.orig_bytes == 0 and f.ts_start.tzinfo is not None


@pytest.mark.parametrize("patch", [
    {"ts_start": NOW.replace(tzinfo=None).isoformat()},               # naive timestamp
    {"ts_start": (NOW + timedelta(hours=1)).isoformat()},              # future
    {"ts_end": (NOW - timedelta(hours=1)).isoformat()},                # ends before start
    {"src_port": 70000},
    {"proto": 300},
    {"src_ip": "10.0.0.256"},
    {"service": "http'; DROP TABLE flows; --"},
    {"features": [1.0, 2.0]},                                          # features without schema id
    {"conn_state": "lowercase"},
    {"unexpected": 1},                                                 # extra field
])
def test_flow_rejects_bad_input(patch):
    with pytest.raises(ValidationError):
        FlowRecordV1(**{**BASE, **patch})


def test_prediction_technique_ids():
    PredictionV1(state_id=uuid4(), window_start=NOW, is_malicious=True, probability=0.9, technique_ids=["T1046", "T1021.001"])
    with pytest.raises(ValidationError):
        PredictionV1(state_id=uuid4(), window_start=NOW, is_malicious=True, probability=0.9, technique_ids=["TA0001"])
    with pytest.raises(ValidationError):
        PredictionV1(state_id=uuid4(), window_start=NOW, is_malicious=True, probability=1.5)


def test_forecast_result_consistency():
    common = dict(sensor_id=uuid4(), model_version_id=uuid4(), input_state_ids=[uuid4()], input_window_start=NOW - timedelta(minutes=1),
                  input_window_end=NOW, horizon_seconds=600, started_at=NOW, completed_at=NOW)
    ForecastResultV1(**common, status="completed")
    with pytest.raises(ValidationError):
        ForecastResultV1(**common, status="failed")              # failed without error
    with pytest.raises(ValidationError):
        ForecastResultV1(**common, status="completed", error="x")  # completed with error
    with pytest.raises(ValidationError):
        ForecastResultV1(**common, status="completed", explanations=[{"kind": "shap", "content": {}, "prediction_index": 3}])


def test_response_proposal_rules():
    ok = ResponseActionProposalV1(action_type="block_ip", target="203.0.113.0/24", enforcement_point="fw-edge-1",
                                  justification="confirmed C2 beaconing", expires_at=NOW + timedelta(hours=4))
    assert str(ok.target) == "203.0.113.0/24"
    with pytest.raises(ValidationError):
        ResponseActionProposalV1(action_type="block_ip", target="203.0.113.5", enforcement_point="fw",
                                 justification="confirmed C2 beaconing", expires_at=NOW - timedelta(minutes=1))
    with pytest.raises(ValidationError):
        ResponseActionProposalV1(action_type="block_pair", target="203.0.113.5", enforcement_point="fw",
                                 justification="confirmed C2 beaconing", expires_at=NOW + timedelta(hours=1))
    with pytest.raises(ValidationError):
        ResponseActionProposalV1(action_type="block_ip", target="203.0.113.5", enforcement_point="fw; rm -rf /",
                                 justification="confirmed C2 beaconing", expires_at=NOW + timedelta(hours=1))
