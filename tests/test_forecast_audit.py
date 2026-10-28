"""Forecast history immutability, current pointer, analyst feedback default, audit hash chain."""
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from nextrace.contracts.v1 import ForecastResultV1
from nextrace.services import audit
from nextrace.services.forecast import current_run, input_fingerprint, record_run, run_history
from tests.conftest import NOW


def _result(seed, status="completed", prob=0.9):
    sid = uuid4()
    return ForecastResultV1(
        sensor_id=seed["sensor_id"], model_version_id=seed["model_version_id"], input_state_ids=[sid],
        input_window_start=NOW - timedelta(seconds=60), input_window_end=NOW, horizon_seconds=600,
        started_at=NOW, completed_at=NOW + timedelta(milliseconds=80), status=status, error=None if status == "completed" else "oom",
        predictions=[{"state_id": sid, "window_start": NOW - timedelta(seconds=10), "is_malicious": prob > 0.5, "probability": prob,
                      "category": "recon", "technique_ids": ["T1046"]}] if status == "completed" else [],
        progression=[{"step": 1, "predicted_technique_id": "T1021.001", "predicted_tactic": "lateral-movement", "probability": 0.4}] if status == "completed" else [],
        explanations=[{"kind": "shap", "prediction_index": 0, "content": {"top": [["failed_ratio", 0.31]]}}] if status == "completed" else [],
    )


def test_record_run_sets_current_and_keeps_history(conn, seed):
    r1 = record_run(conn, _result(seed, prob=0.2))
    r2 = record_run(conn, _result(seed, prob=0.9))
    r3 = record_run(conn, _result(seed, status="failed"))
    cur = current_run(conn, seed["sensor_id"])
    assert cur["run_id"] == r2 and cur["predictions"][0]["probability"] == pytest.approx(0.9)
    assert cur["progression"][0]["predicted_technique_id"] == "T1021.001"
    hist = run_history(conn, seed["sensor_id"])
    assert [h["run_id"] for h in hist] == [r3, r2, r1]
    assert conn.execute(text("SELECT disclaimer FROM explanations WHERE run_id = :r"), {"r": r2}).scalar_one().startswith("Explanation of model output")


def test_forecast_rows_are_immutable(conn, seed):
    run_id = record_run(conn, _result(seed))
    for sql in ["UPDATE forecast_runs SET horizon_seconds = 1 WHERE run_id = :r",
                "DELETE FROM forecast_runs WHERE run_id = :r",
                "UPDATE predictions SET probability = 0 WHERE run_id = :r",
                "DELETE FROM explanations WHERE run_id = :r"]:
        with pytest.raises(IntegrityError, match="append-only"):
            with conn.begin_nested():
                conn.execute(text(sql), {"r": run_id})


def test_input_fingerprint_is_order_independent():
    a, b = uuid4(), uuid4()
    base = dict(sensor_id=uuid4(), model_version_id=uuid4(), input_window_start=NOW, input_window_end=NOW, horizon_seconds=10,
                started_at=NOW, completed_at=NOW, status="completed")
    assert input_fingerprint(ForecastResultV1(**base, input_state_ids=[a, b])) == input_fingerprint(ForecastResultV1(**base, input_state_ids=[b, a]))


def test_analyst_feedback_not_training_eligible_by_default(conn, seed):
    run_id = record_run(conn, _result(seed))
    pid = conn.execute(text("SELECT prediction_id FROM predictions WHERE run_id = :r"), {"r": run_id}).scalar_one()
    eligible = conn.execute(text(
        "INSERT INTO analyst_feedback (prediction_id, user_id, verdict) VALUES (:p, :u, 'false_positive') RETURNING eligible_for_training"),
        {"p": pid, "u": seed["users"]["analyst"]}).scalar_one()
    assert eligible is False


def test_audit_chain_detects_tampering(conn, seed):
    audit.record(conn, "test.one", actor_id=seed["users"]["admin"], details={"k": "v'; --"})
    audit.record(conn, "test.two", object_type="x", object_id="1")
    last = audit.record(conn, "test.three")
    assert audit.verify_chain(conn) is None
    with pytest.raises(IntegrityError, match="append-only"):
        with conn.begin_nested():
            conn.execute(text("UPDATE audit_log SET details = '{}' WHERE audit_id = :i"), {"i": last})
    with pytest.raises(IntegrityError, match="append-only"):
        with conn.begin_nested():
            conn.execute(text("DELETE FROM audit_log WHERE audit_id = :i"), {"i": last})
    # Simulate an attacker with superuser rights bypassing the trigger: the chain still exposes the edit.
    conn.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_immutable"))
    conn.execute(text("UPDATE audit_log SET action = 'test.forged' WHERE audit_id = :i"), {"i": last - 1})
    conn.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_immutable"))
    assert audit.verify_chain(conn) == last - 1
