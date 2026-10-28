"""Flow ingestion (COPY), host pseudonyms, temporal state construction, injection resistance."""
from datetime import timedelta

from sqlalchemy import text

from nextrace.services.ingest import create_batch, ingest_flows
from nextrace.services.security import pseudonymize_ip
from nextrace.services.states import build_states, recent_states
from tests.conftest import NOW, make_flows

START = NOW - timedelta(minutes=10)


def test_ingest_accepts_valid_rejects_invalid(conn, seed):
    batch = create_batch(conn, seed["sensor_id"], "zeek_conn")
    records = make_flows(200, START) + [{"ts_start": START.isoformat(), "src_ip": "bad", "dst_ip": "10.0.0.1", "proto": 6},
                                        {"ts_start": START.isoformat(), "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "proto": 6, "orig_bytes": -1}]
    res = ingest_flows(conn, seed["sensor_id"], batch, records)
    assert (res.accepted, res.rejected) == (200, 2)
    assert conn.execute(text("SELECT count(*) FROM flows WHERE batch_id = :b"), {"b": batch}).scalar_one() == 200
    status = conn.execute(text("SELECT status, accepted, rejected FROM ingest_batches WHERE batch_id = :b"), {"b": batch}).one()
    assert tuple(status) == ("loaded", 200, 2)
    # host registry carries HMAC pseudonyms, raw IPs stay queryable
    p = conn.execute(text("SELECT pseudonym FROM hosts WHERE ip = '10.0.0.1'")).scalar_one()
    assert bytes(p) == pseudonymize_ip("10.0.0.1")
    assert len(res.errors) == 2 and "bad" not in "".join(res.errors)  # messages, not echoed payloads


def test_build_states_and_edges(conn, seed):
    batch = create_batch(conn, seed["sensor_id"], "zeek_conn")
    ingest_flows(conn, seed["sensor_id"], batch, make_flows(600, START, step_ms=100))  # 60 s of traffic
    states = build_states(conn, seed["sensor_id"], START - timedelta(seconds=10), START + timedelta(seconds=70), 10, seed["feature_schema_id"])
    assert 6 <= len(states) <= 7
    assert sum(s.n_flows for s in states) == 600
    first = states[0]
    assert first.window_seconds == 10 and len(first.features) == 10 and first.n_nodes >= 2 and first.n_edges >= 1
    edges = conn.execute(text("SELECT count(*) FROM state_edges WHERE state_id = :s"), {"s": first.state_id}).scalar_one()
    assert edges == first.n_edges
    # rebuilding is idempotent: same state ids, same counts
    again = build_states(conn, seed["sensor_id"], START - timedelta(seconds=10), START + timedelta(seconds=70), 10, seed["feature_schema_id"])
    assert [s.state_id for s in again] == [s.state_id for s in states]
    assert conn.execute(text("SELECT count(*) FROM temporal_states WHERE sensor_id = :s"), {"s": seed["sensor_id"]}).scalar_one() == len(states)
    recent = recent_states(conn, seed["sensor_id"], 3)
    assert [s.window_start for s in recent] == [s.window_start for s in states[-3:]]


def test_hostile_filter_values_are_bound_not_interpolated(conn, seed):
    batch = create_batch(conn, seed["sensor_id"], "zeek_conn")
    ingest_flows(conn, seed["sensor_id"], batch, make_flows(20, START))
    hostile = ["' OR 1=1 --", "x'; DROP TABLE flows; --", "10.0.0.1' UNION SELECT 1 --", "\\"]
    for h in hostile:
        rows = conn.execute(text("SELECT count(*) FROM flows WHERE community_id = :c OR service = :c OR label = :c"), {"c": h}).scalar_one()
        assert rows == 0
    assert conn.execute(text("SELECT count(*) FROM flows WHERE batch_id = :b"), {"b": batch}).scalar_one() == 20
    # inet comparison with a hostile string fails type validation at the database, never executes as SQL
    import pytest
    from sqlalchemy.exc import DataError
    with pytest.raises(DataError):
        with conn.begin_nested():
            conn.execute(text("SELECT count(*) FROM flows WHERE src_ip = CAST(:ip AS inet)"), {"ip": "10.0.0.1' OR '1'='1"})
