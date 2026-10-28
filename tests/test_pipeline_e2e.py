"""End-to-end over a controlled pcap: capture -> states -> baseline detection -> runs -> correlation -> alerts -> proposals."""
from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta

from sqlalchemy import text

from nextrace.contracts.models import DetectionResultV1
from nextrace.contracts.v1 import PredictionV1
from nextrace.core.pipeline import Pipeline
from nextrace.modules.capture.sources import PcapReplaySource
from nextrace.modules.detection.detector import UnavailableDetector
from tests.backend_helpers import an_hour_ago, make_sensor, scenario_packets, write_pcap


def test_replay_end_to_end_with_baseline(conn, ctx, tmp_path):
    sid = make_sensor(conn)
    path = write_pcap(tmp_path / "e2e.pcap", scenario_packets(an_hour_ago(), scan_ports=150))
    src = PcapReplaySource(path, sid, batch_flows=40)
    pipe = Pipeline(ctx)
    stats = asyncio.run(pipe.run(src))
    assert stats.errors == 0 and stats.batches >= 2 and stats.flows_accepted >= 200 and stats.flows_rejected == 0
    assert stats.states >= 6 and stats.runs_recorded == stats.inference_rounds > 0 and stats.inference_unavailable == 0
    assert stats.alerts >= 1 and stats.queue_health["batches"]["shed"] == 0
    n_states = conn.execute(text("SELECT count(*) FROM temporal_states WHERE sensor_id = :s"), {"s": sid}).scalar_one()
    n_flows = conn.execute(text("SELECT count(*) FROM flows WHERE sensor_id = :s"), {"s": sid}).scalar_one()
    assert n_states == stats.states and n_flows == stats.flows_accepted
    runs = conn.execute(text("SELECT count(*) FROM forecast_runs WHERE sensor_id = :s AND status = 'completed'"), {"s": sid}).scalar_one()
    assert runs == stats.runs_recorded
    mal = conn.execute(text("SELECT count(*) FROM predictions p JOIN forecast_runs r USING (run_id) WHERE r.sensor_id = :s AND p.is_malicious"), {"s": sid}).scalar_one()
    assert mal >= 1
    alerts = conn.execute(text("SELECT severity, title FROM alerts WHERE sensor_id = :s"), {"s": sid}).mappings().all()
    assert alerts and all("T1046" in a["title"] for a in alerts)
    # baseline has no host attribution -> sensor-level events -> no system proposals, and nothing executed
    assert stats.proposals == 0 and conn.execute(text("SELECT count(*) FROM response_actions")).scalar_one() == 0
    # cache holds the bounded window and the current forecast
    assert ctx.cache.state_count(sid) == min(5, stats.states) and ctx.cache.get_current_forecast(sid)["run_id"]
    assert ctx.model_availability["detector"] == "heuristic_baseline" and ctx.model_availability["forecaster"] == "unavailable"
    cur = conn.execute(text("SELECT run_id FROM forecast_current WHERE sensor_id = :s"), {"s": sid}).scalar()
    assert cur is not None
    audit_n = conn.execute(text("SELECT count(*) FROM audit_log WHERE action = 'alert.emit'")).scalar_one()
    assert audit_n == stats.alerts


def test_unavailable_model_records_nothing_fake(conn, ctx, tmp_path):
    ctx.detector = UnavailableDetector()
    sid = make_sensor(conn)
    path = write_pcap(tmp_path / "u.pcap", scenario_packets(an_hour_ago()))
    stats = asyncio.run(Pipeline(ctx).run(PcapReplaySource(path, sid, batch_flows=40)))
    assert stats.states > 0 and stats.inference_rounds > 0
    assert stats.runs_recorded == 0 and stats.alerts == 0 and stats.inference_unavailable == stats.inference_rounds
    assert "artifact" in stats.last_unavailable_reason
    assert conn.execute(text("SELECT count(*) FROM forecast_runs WHERE sensor_id = :s"), {"s": sid}).scalar_one() == 0


def test_host_attributed_detection_creates_dry_run_proposal(conn, ctx, seed):
    """A detector that names hosts yields host-level events; high risk produces a *proposed* (never executed) action."""
    sid = seed["sensor_id"]
    host_id = conn.execute(text("INSERT INTO hosts (ip, pseudonym, asset_tag) VALUES ('10.9.9.9', :p, 'crit:0.9') RETURNING host_id"),
                           {"p": uuid.uuid4().bytes + uuid.uuid4().bytes}).scalar_one()
    mv = ctx.detector.model_version().model_version_id

    class HostDetector:
        def model_version(self):
            return ctx.detector.model_version()

        def detect(self, request):
            st = request.sequence.states[-1]
            return DetectionResultV1(request_id=request.request_id, model_version_id=mv, status="completed", predictions=[
                PredictionV1(state_id=st.state_id, window_start=st.window_start, is_malicious=True, probability=0.97, category="bruteforce",
                             technique_ids=["T1046", "T1110"], host_ids=[host_id])])

        def health(self):
            return ctx.detector.health()

    ctx.detector = HostDetector()
    pipe = Pipeline(ctx, persist_flows=False)
    base = an_hour_ago().replace(second=0)
    from tests.conftest import make_flows
    from nextrace.contracts.observations import FlowBatchV1
    from nextrace.contracts.v1 import FlowRecordV1
    flows = [FlowRecordV1.model_validate(f) for f in make_flows(200, base, step_ms=500)]
    batch = FlowBatchV1(sensor_id=sid, batch_seq=0, produced_at=an_hour_ago(), source="csv", flows=flows)
    states = pipe.process_batch(conn, batch) + pipe.flush(conn, sid)
    outcomes = [pipe.process_state(conn, st) for st in states]
    assert any(o and o.run_id for o in outcomes)
    assert pipe.stats.alerts >= 1 and pipe.stats.proposals >= 1
    row = conn.execute(text("SELECT status, proposed_by, target, enforcement_point, justification FROM response_actions ORDER BY action_id LIMIT 1")).mappings().first()
    assert row["status"] == "proposed" and row["proposed_by"] is None and str(row["target"]).startswith("10.9.9.9") and row["enforcement_point"] == "dry-run"
    assert "risk" in row["justification"]
    alert = conn.execute(text("SELECT severity FROM alerts ORDER BY alert_id DESC LIMIT 1")).scalar()
    assert alert in ("high", "critical")
    dec = conn.execute(text("SELECT details FROM audit_log WHERE action = 'response.policy_decision' ORDER BY audit_id DESC LIMIT 1")).scalar()
    assert dec["decision"] == "allow_dry_run" and dec["proposer_kind"] == "system" and "R05" in dec["rules"]
