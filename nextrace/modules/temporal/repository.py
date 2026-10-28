"""Persistence for sequencer-built states (central repository function used by the pipeline, not by modules)."""
from __future__ import annotations

from datetime import timedelta
from typing import Iterable
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from nextrace.contracts.v1 import TemporalStateV1
from nextrace.db.partitions import ensure_partitions


def persist_states(conn: Connection, states: Iterable[TemporalStateV1], feature_schema_id: UUID) -> int:
    states = list(states)
    if not states:
        return 0
    lo = min(s.window_start for s in states)
    hi = max(s.window_start for s in states) + timedelta(seconds=1)
    ensure_partitions(conn, "temporal_states", lo, hi)
    rows = [{"id": s.state_id, "sensor": s.sensor_id, "ws": s.window_start, "w": s.window_seconds, "v": s.schema_version,
             "nf": s.n_flows, "nn": s.n_nodes, "ne": s.n_edges, "tb": s.total_bytes, "tp": s.total_pkts,
             "summary": __import__("json").dumps(s.summary, default=str), "feat": "{" + ",".join(repr(float(x)) for x in s.features) + "}",
             "fs": feature_schema_id} for s in states]
    conn.execute(text(
        "INSERT INTO temporal_states (state_id, sensor_id, window_start, window_seconds, schema_version, n_flows, n_nodes, n_edges, "
        "total_bytes, total_pkts, summary, features, feature_schema_id) VALUES (:id, :sensor, :ws, :w, :v, :nf, :nn, :ne, :tb, :tp, "
        "CAST(:summary AS jsonb), CAST(:feat AS real[]), :fs) "
        "ON CONFLICT (sensor_id, window_start, window_seconds) DO UPDATE SET n_flows = EXCLUDED.n_flows, n_nodes = EXCLUDED.n_nodes, "
        "n_edges = EXCLUDED.n_edges, total_bytes = EXCLUDED.total_bytes, total_pkts = EXCLUDED.total_pkts, summary = EXCLUDED.summary, "
        "features = EXCLUDED.features, built_at = now()"), rows)
    return len(rows)
