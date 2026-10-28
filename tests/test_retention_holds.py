"""Retention enforcement, legal holds, PCAP ring budget, forecast trimming."""
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from nextrace.config import Settings
from nextrace.contracts.v1 import ForecastResultV1
from nextrace.db.partitions import list_partitions, partition_name
from nextrace.services import investigations as inv
from nextrace.services import retention
from nextrace.services.forecast import record_run
from nextrace.services.ingest import create_batch, ingest_flows
from nextrace.services.states import build_states
from nextrace.storage import pcap as pcapmod
from nextrace.storage.object_store import ObjectRef
from tests.conftest import NOW, make_flows
from tests.test_evidence_authz import _write_pcap

OLD = NOW - timedelta(days=200)
RECENT = NOW - timedelta(days=5)


def _settings(**over) -> Settings:
    base = dict(database_url="postgresql://x", pseudonym_pepper="p" * 32, flow_retention_days=183, state_retention_days=183,
                state_edge_retention_days=14, forecast_retention_days=365, header_pcap_retention_days=183,
                full_pcap_retention_hours=72, pcap_budget_bytes=10**9)
    return Settings(**{**base, **over})


def _load(conn, seed, start, n=300):
    b = create_batch(conn, seed["sensor_id"], "zeek_conn")
    ingest_flows(conn, seed["sensor_id"], b, make_flows(n, start))
    build_states(conn, seed["sensor_id"], start - timedelta(seconds=10), start + timedelta(seconds=60), 10, seed["feature_schema_id"])


def test_old_partitions_dropped_recent_kept(conn, seed, store):
    _load(conn, seed, OLD)
    _load(conn, seed, RECENT)
    report = retention.enforce(conn, store, _settings(), NOW)
    assert partition_name("flows", OLD.date()) in report.dropped["flows"]
    assert partition_name("temporal_states", OLD.date()) in report.dropped["temporal_states"]
    assert partition_name("state_edges", OLD.date()) in report.dropped["state_edges"]
    names = {n for n, _ in list_partitions(conn, "flows")}
    assert partition_name("flows", RECENT.date()) in names and partition_name("flows", OLD.date()) not in names
    assert conn.execute(text("SELECT count(*) FROM flows WHERE sensor_id = :s"), {"s": seed["sensor_id"]}).scalar_one() == 300
    # edges have a shorter retention: the 5-day-old edge partition stays with 14 days, goes with 3 days
    assert partition_name("state_edges", RECENT.date()) in {n for n, _ in list_partitions(conn, "state_edges")}
    retention.enforce(conn, store, _settings(state_edge_retention_days=3), NOW)
    assert partition_name("state_edges", RECENT.date()) not in {n for n, _ in list_partitions(conn, "state_edges")}
    assert conn.execute(text("SELECT count(*) FROM audit_log WHERE action = 'retention.drop_partition'")).scalar_one() >= 4


def test_pending_hold_vetoes_drop_then_preservation_releases_it(conn, seed, store):
    u = seed["users"]
    _load(conn, seed, OLD)
    case = inv.open_case(conn, "CASE-HOLD", "Litigation hold", "critical", u["dfir"])
    inv.grant_access(conn, case, u["analyst"], "metadata", u["dfir"], NOW + timedelta(days=30), "case analyst")
    with pytest.raises(IntegrityError):  # requester and approver must differ
        with conn.begin_nested():
            inv.place_hold(conn, case, OLD - timedelta(hours=1), OLD + timedelta(hours=1), "subpoena 42", u["dfir"], u["dfir"])
    hold = inv.place_hold(conn, case, OLD - timedelta(hours=1), OLD + timedelta(hours=1), "subpoena 42", u["analyst"], u["dfir"])

    report = retention.enforce(conn, store, _settings(), NOW)
    assert partition_name("flows", OLD.date()) in report.skipped_for_hold["flows"]
    assert conn.execute(text("SELECT count(*) FROM flows WHERE sensor_id = :s"), {"s": seed["sensor_id"]}).scalar_one() == 300

    eid = inv.preserve_hold(conn, store, hold, u["analyst"])
    row = conn.execute(text("SELECT o.sha256, o.size_bytes, o.storage_path, e.kind FROM evidence_items e JOIN objects o ON o.sha256 = e.object_sha256 "
                            "WHERE e.evidence_id = :e"), {"e": eid}).one()
    assert row.kind == "flow_export" and store.verify(ObjectRef(bytes(row.sha256), row.size_bytes, row.storage_path))
    import gzip
    with store.open(ObjectRef(bytes(row.sha256), row.size_bytes, row.storage_path)) as f:
        lines = gzip.decompress(f.read()).splitlines()
    assert sum(1 for l in lines if l.startswith(b'{"flow"')) == 300 and sum(1 for l in lines if l.startswith(b'{"state"')) >= 3
    assert conn.execute(text("SELECT status FROM legal_holds WHERE hold_id = :h"), {"h": hold}).scalar_one() == "preserved"

    report = retention.enforce(conn, store, _settings(), NOW)
    assert partition_name("flows", OLD.date()) in report.dropped["flows"]
    with pytest.raises(inv.AuthorizationError):
        inv.release_hold(conn, hold, u["analyst"])
    inv.release_hold(conn, hold, u["dfir"])


def test_pcap_ring_budget_and_age_rules_respect_holds(conn, seed, store, tmp_path):
    u = seed["users"]
    segs = []
    for i in range(4):
        p = tmp_path / f"s{i}.pcap"
        _write_pcap(p, 12_000, RECENT + timedelta(minutes=i), step_s=0.001)  # ~1.1 MB each
        sid, ref = pcapmod.register_segment(conn, store, seed["sensor_id"], p, "headers", snaplen=96)
        conn.execute(text("UPDATE pcap_segments SET created_at = :c WHERE segment_id = :s"), {"c": RECENT + timedelta(minutes=i), "s": sid})
        segs.append((sid, ref))
    size = segs[0][1].size_bytes
    case = inv.open_case(conn, "CASE-PCAP", "pcap hold", "high", u["dfir"])
    inv.grant_access(conn, case, u["analyst"], "metadata", u["dfir"], NOW + timedelta(days=1), "case analyst")
    inv.place_hold(conn, case, RECENT + timedelta(minutes=1), RECENT + timedelta(minutes=1, seconds=10), "preserve segment 1", u["analyst"], u["dfir"], seed["sensor_id"])
    assert conn.execute(text("SELECT status, hold_count FROM pcap_segments WHERE segment_id = :s"), {"s": segs[1][0]}).one() == ("held", 1)

    report = retention.enforce(conn, store, _settings(pcap_budget_bytes=size * 2), NOW)
    statuses = {sid: conn.execute(text("SELECT status FROM pcap_segments WHERE segment_id = :s"), {"s": sid}).scalar_one() for sid, _ in segs}
    assert statuses[segs[0][0]] == "reclaimed" and statuses[segs[1][0]] == "held" and statuses[segs[2][0]] == "reclaimed" and statuses[segs[3][0]] == "active"
    assert report.pcap_segments_reclaimed == 2 and report.pcap_bytes_freed == 2 * size
    assert not store.exists(segs[0][1]) and store.exists(segs[1][1])
    assert conn.execute(text("SELECT deleted_at IS NOT NULL FROM objects WHERE sha256 = :h"), {"h": segs[0][1].sha256}).scalar_one()

    # full-payload captures age out after 72 h even when the budget has room
    p = tmp_path / "full.pcap"
    _write_pcap(p, 10, NOW - timedelta(hours=100))
    fid, fref = pcapmod.register_segment(conn, store, seed["sensor_id"], p, "full")
    retention.enforce(conn, store, _settings(), NOW)
    assert conn.execute(text("SELECT status FROM pcap_segments WHERE segment_id = :s"), {"s": fid}).scalar_one() == "reclaimed"


def test_forecast_history_trimmed_only_when_unreferenced(conn, seed):
    def run(created):
        rid = record_run(conn, ForecastResultV1(sensor_id=seed["sensor_id"], model_version_id=seed["model_version_id"], input_state_ids=[seed["sensor_id"]],
                                                input_window_start=created, input_window_end=created, horizon_seconds=60, started_at=created,
                                                completed_at=created, status="completed"))
        conn.execute(text("ALTER TABLE forecast_runs DISABLE TRIGGER forecast_runs_immutable"))
        conn.execute(text("UPDATE forecast_runs SET created_at = :c WHERE run_id = :r"), {"c": created, "r": rid})
        conn.execute(text("ALTER TABLE forecast_runs ENABLE TRIGGER forecast_runs_immutable"))
        return rid
    old_unref = run(NOW - timedelta(days=400))
    old_alerted = run(NOW - timedelta(days=400))
    newest = run(NOW)  # current pointer
    conn.execute(text("INSERT INTO alerts (run_id, sensor_id, severity, title) VALUES (:r, :s, 'high', 'x')"), {"r": old_alerted, "s": seed["sensor_id"]})
    with pytest.raises(IntegrityError, match="append-only"):  # no deletion outside the retention job
        with conn.begin_nested():
            conn.execute(text("DELETE FROM forecast_runs WHERE run_id = :r"), {"r": old_unref})
    rep = retention.RetentionReport()
    retention.enforce_forecasts(conn, 365, NOW, rep)
    remaining = set(conn.execute(text("SELECT run_id FROM forecast_runs WHERE sensor_id = :s"), {"s": seed["sensor_id"]}).scalars())
    assert rep.forecast_runs_deleted == 1 and remaining == {old_alerted, newest}
