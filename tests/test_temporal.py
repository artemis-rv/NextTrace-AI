"""Person 2 module: event-time windows, lateness, SQL conformance, sequences with gaps, leakage-free splits, calibration."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from nextrace.contracts.v1 import FlowRecordV1
from nextrace.mlcommon.calibration import expected_calibration_error, fit_temperature, nll, sigmoid
from nextrace.modules.temporal.sequencer import StreamingSequencer, build_sequence, window_start_for
from nextrace.mlcommon.splits import assert_no_overlap, assert_sequences_causal, chronological_split, fit_scaler
from nextrace.services import ingest, states
from tests.backend_helpers import an_hour_ago, make_sensor
from tests.conftest import make_flows

FS = uuid.uuid4()


def _flow(ts, src="10.0.0.1", dst="10.0.1.1", port=80, state="SF", proto=6, dur=50):
    return FlowRecordV1(ts_start=ts, ts_end=ts + timedelta(milliseconds=dur), src_ip=src, dst_ip=dst, dst_port=port, proto=proto, conn_state=state,
                        duration_ms=dur, orig_bytes=100, resp_bytes=200, orig_pkts=2, resp_pkts=3)


def test_window_binning_matches_date_bin_epoch():
    ts = datetime(2026, 10, 28, 12, 0, 7, tzinfo=timezone.utc)
    assert window_start_for(ts, 10) == datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)
    assert window_start_for(ts, 60) == datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)
    assert window_start_for(datetime(2026, 10, 28, 12, 0, 29, tzinfo=timezone.utc), 10) == datetime(2026, 10, 28, 12, 0, 20, tzinfo=timezone.utc)


def test_watermark_closes_windows_and_late_policy():
    sid = uuid.uuid4()
    base = an_hour_ago().replace(second=0)
    seq = StreamingSequencer(10, allowed_lateness_s=5, feature_schema_id=FS, late_policy="refire")
    out = seq.ingest([_flow(base + timedelta(seconds=1)), _flow(base + timedelta(seconds=12))], sid)
    assert out == []  # watermark = 12-5 = 7 < 10: first window still open
    out = seq.ingest([_flow(base + timedelta(seconds=16))], sid)
    assert len(out) == 1 and out[0].window_start == base and out[0].n_flows == 1
    first_id = out[0].state_id
    # a late flow for the closed window within the allowed lateness horizon -> refire with same id
    out = seq.ingest([_flow(base + timedelta(seconds=2))], sid)
    assert len(out) == 1 and out[0].state_id == first_id and out[0].n_flows == 2 and out[0].summary["late_updates"] == 1
    assert seq.stats.late_flows == 1 and seq.stats.late_refired == 1 and seq.stats.out_of_order_flows == 1
    # drop policy counts instead of refiring
    drop = StreamingSequencer(10, 0, FS, late_policy="drop")
    drop.ingest([_flow(base), _flow(base + timedelta(seconds=11))], sid)
    assert drop.ingest([_flow(base + timedelta(seconds=3))], sid) == [] and drop.late_flows_dropped() == 1
    # flush closes what is open
    rest = seq.flush(sid)
    assert [s.window_start for s in rest] == [base + timedelta(seconds=10)]


def test_sequence_reports_gaps_instead_of_filling_them():
    sid = uuid.uuid4()
    base = an_hour_ago().replace(second=0)
    seq = StreamingSequencer(10, 0, FS)
    seq.ingest([_flow(base), _flow(base + timedelta(seconds=30)), _flow(base + timedelta(seconds=41))], sid)
    s = seq.sequence(sid, 10)
    assert s is not None and [x.window_start for x in s.states] == [base, base + timedelta(seconds=30)]
    assert s.missing_windows == [base + timedelta(seconds=10), base + timedelta(seconds=20)] and not s.complete
    assert build_sequence(sid, s.states[:1], 10, FS).complete


def test_python_features_match_sql_builder(conn, seed):
    """The streaming sequencer and the SQL builder must produce identical WINDOW_FEATURES_V1 for the same flows."""
    sid = seed["sensor_id"]
    base = an_hour_ago().replace(second=0)
    raw = make_flows(400, base, step_ms=250, hosts=7)
    recs = [FlowRecordV1.model_validate(r) for r in raw]
    bid = ingest.create_batch(conn, sid, "api")
    ingest.ingest_flows(conn, sid, bid, recs)
    sql_states = states.build_states(conn, sid, base, base + timedelta(minutes=5), 10, seed["feature_schema_id"], build_edges=False)
    seq = StreamingSequencer(10, 0, seed["feature_schema_id"])
    py_states = {s.window_start: s for s in seq.ingest(recs, sid) + seq.flush(sid)}
    assert len(sql_states) == len(py_states) >= 9
    for s in sql_states:
        p = py_states[s.window_start]
        assert (p.n_flows, p.n_nodes, p.n_edges, p.total_bytes, p.total_pkts) == (s.n_flows, s.n_nodes, s.n_edges, s.total_bytes, s.total_pkts)
        assert np.allclose(np.array(p.features, dtype=np.float32), np.array(s.features, dtype=np.float32), rtol=1e-5, atol=1e-4), (p.features, s.features)


def test_chronological_split_has_no_leakage():
    ts = [an_hour_ago() + timedelta(seconds=i) for i in range(100)]
    tr, va, te, bounds = chronological_split(ts, 0.6, 0.2, timedelta(seconds=3))
    t = np.array([x.timestamp() for x in ts])
    assert_no_overlap(t[tr], t[va], t[te])
    assert t[tr].max() < t[va].min() - 3 + 1e-9 and t[va].max() < t[te].min() - 3 + 1e-9
    assert len(tr) == 60 and len(va) < 20 and len(te) < 20  # embargo removed rows at the cuts
    with pytest.raises(ValueError):
        assert_no_overlap(t[va], t[tr], t[te])
    seq_ts = np.tile(t[:20], (3, 1))
    assert_sequences_causal(seq_ts)
    with pytest.raises(ValueError):
        assert_sequences_causal(seq_ts[:, ::-1])
    x = np.random.default_rng(0).normal(size=(60, 20, 10)).astype(np.float32)
    mean, std = fit_scaler(x)
    assert mean.shape == (10,) and np.all(std > 0)


def test_temperature_scaling_improves_nll_and_ece_is_bounded():
    rng = np.random.default_rng(1)
    y = (rng.random(2000) < 0.3).astype(float)
    logits = (y * 2 - 1) * 1.0 + rng.normal(0, 1.0, 2000)
    overconfident = logits * 4.0
    T = fit_temperature(overconfident, y)
    assert T > 1.5 and nll(overconfident, y, T) < nll(overconfident, y, 1.0)
    e = expected_calibration_error(sigmoid(overconfident / T), y)
    assert 0.0 <= e <= 1.0 and e < expected_calibration_error(sigmoid(overconfident), y)
