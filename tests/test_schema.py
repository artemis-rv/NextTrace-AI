"""Schema, migration and partition behaviour."""
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from nextrace.db.partitions import ensure_partitions, list_partitions, partition_name
from tests.conftest import NOW

EXPECTED_TABLES = {
    "sensors", "users", "feature_schemas", "objects", "datasets", "model_versions", "hosts", "pcap_segments",
    "ingest_batches", "flows", "temporal_states", "state_edges", "forecast_runs", "predictions", "simulations",
    "progression_forecasts", "explanations", "forecast_current", "analyst_feedback", "investigations", "alerts",
    "investigation_links", "case_grants", "evidence_items", "custody_events", "legal_holds", "uploads",
    "forensic_analyses", "forensic_findings", "response_actions", "response_action_events", "audit_log",
}


def test_migration_created_all_tables(conn):
    names = set(conn.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")).scalars())
    assert EXPECTED_TABLES <= names


def test_partitioned_tables_and_uuidv7(conn):
    parts = set(conn.execute(text("SELECT relname FROM pg_class WHERE relkind = 'p'")).scalars())
    assert {"flows", "temporal_states", "state_edges"} <= parts
    a, b = conn.execute(text("SELECT uuidv7(), uuidv7()")).one()
    assert str(a) < str(b)  # time-ordered keys


def test_rows_route_to_daily_partition(conn, seed):
    day = NOW - timedelta(days=2)
    ensure_partitions(conn, "flows", day, day)
    conn.execute(text(
        "INSERT INTO flows (ts_start, sensor_id, src_ip, dst_ip, proto) VALUES (:t, :s, '10.1.1.1', '10.1.1.2', 6)"),
        {"t": day, "s": seed["sensor_id"]})
    where = conn.execute(text("SELECT tableoid::regclass::text FROM flows WHERE ts_start = :t"), {"t": day}).scalar_one()
    assert where == partition_name("flows", day.date())
    assert any(n == where for n, _ in list_partitions(conn, "flows"))


def test_insert_without_partition_is_rejected(conn, seed):
    far = NOW - timedelta(days=4000)
    with pytest.raises(IntegrityError, match="no partition"):
        with conn.begin_nested():
            conn.execute(text(
                "INSERT INTO flows (ts_start, sensor_id, src_ip, dst_ip, proto) VALUES (:t, :s, '10.1.1.1', '10.1.1.2', 6)"),
                {"t": far, "s": seed["sensor_id"]})


@pytest.mark.parametrize("sql", [
    "INSERT INTO users (username, role) VALUES ('Bad User; DROP TABLE users', 'admin')",
    "INSERT INTO users (username, role) VALUES ('okname', 'superuser')",
    "INSERT INTO progression_forecasts (run_id, step, predicted_technique_id, probability) VALUES (uuidv7(), 1, 'X9999', 0.5)",
    "INSERT INTO investigations (case_number, title, severity, opened_by) VALUES ('bad case', 't', 'low', uuidv7())",
])
def test_check_constraints_reject_bad_values(conn, sql):
    with pytest.raises(IntegrityError):
        with conn.begin_nested():
            conn.execute(text(sql))


def test_flow_feature_columns_must_pair(conn, seed):
    ensure_partitions(conn, "flows", NOW, NOW)
    with pytest.raises(IntegrityError):
        with conn.begin_nested():
            conn.execute(text(
                "INSERT INTO flows (ts_start, sensor_id, src_ip, dst_ip, proto, features) VALUES (:t, :s, '10.1.1.1', '10.1.1.2', 6, '{1,2}')"),
                {"t": NOW, "s": seed["sensor_id"]})
