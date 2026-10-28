"""Temporal network state construction from flows (set-based SQL, idempotent per window).

Window length is configuration (NEXTRACE_STATE_WINDOW_SECONDS, default 10 s). The literature shows
the window is a tunable with large effect on detection quality, so it is stored on every state row
and never assumed. Edges are a rebuildable derivative kept for a short retention.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from nextrace.contracts.v1 import TemporalStateV1
from nextrace.db.partitions import ensure_partitions

WINDOW_FEATURES_V1 = [
    {"name": "n_flows", "dtype": "float32", "description": "flows starting in window"},
    {"name": "n_nodes", "dtype": "float32", "description": "distinct hosts"},
    {"name": "n_edges", "dtype": "float32", "description": "distinct (src,dst) pairs"},
    {"name": "total_bytes", "dtype": "float32", "description": "orig+resp bytes"},
    {"name": "total_pkts", "dtype": "float32", "description": "orig+resp packets"},
    {"name": "distinct_dst_ports", "dtype": "float32", "description": "distinct destination ports"},
    {"name": "tcp_ratio", "dtype": "float32", "description": "share of TCP flows"},
    {"name": "udp_ratio", "dtype": "float32", "description": "share of UDP flows"},
    {"name": "failed_ratio", "dtype": "float32", "description": "share of flows with conn_state in S0/REJ/RSTOS0/RSTRH/SH/SHR"},
    {"name": "mean_duration_ms", "dtype": "float32", "description": "mean flow duration"},
]
EDGE_FEATURES_V1 = [
    {"name": "n_flows", "dtype": "float32"}, {"name": "bytes", "dtype": "float32"}, {"name": "pkts", "dtype": "float32"},
    {"name": "dst_ports", "dtype": "float32"}, {"name": "mean_duration_ms", "dtype": "float32"},
]
EPOCH = "2000-01-01 00:00:00+00"


def register_feature_schema(conn: Connection, name: str, version: int, definition: list[dict]) -> UUID:
    canonical = json.dumps(definition, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(canonical).digest()
    existing = conn.execute(text(
        "SELECT feature_schema_id, definition_sha256 FROM feature_schemas WHERE name = :n AND version = :v"),
        {"n": name, "v": version}).first()
    if existing:
        if bytes(existing[1]) != digest:
            raise ValueError(f"feature schema {name} v{version} already exists with a different definition")
        return existing[0]
    return conn.execute(text(
        "INSERT INTO feature_schemas (name, version, definition, definition_sha256) "
        "VALUES (:n, :v, CAST(:d AS jsonb), :h) RETURNING feature_schema_id"),
        {"n": name, "v": version, "d": canonical.decode(), "h": digest}).scalar_one()


def build_states(conn: Connection, sensor_id: UUID, start: datetime, end: datetime, window_seconds: int,
                 feature_schema_id: UUID, build_edges: bool = True) -> list[TemporalStateV1]:
    """(Re)build every state whose window starts in [start, end) and return them oldest first."""
    ensure_partitions(conn, "temporal_states", start, end + timedelta(days=1))
    if build_edges:
        ensure_partitions(conn, "state_edges", start, end + timedelta(days=1))
    params = {"s": sensor_id, "start": start, "end": end, "w": window_seconds, "fs": feature_schema_id}

    rows = conn.execute(text(f"""
        WITH w AS (
          SELECT date_bin(make_interval(secs => :w), ts_start, TIMESTAMPTZ '{EPOCH}') AS ws, *
          FROM flows WHERE sensor_id = :s AND ts_start >= :start AND ts_start < :end
        ), agg AS (
          SELECT ws, count(*) AS n_flows, sum(orig_bytes + resp_bytes) AS bytes, sum(orig_pkts + resp_pkts) AS pkts,
                 count(DISTINCT dst_port) AS dports, count(DISTINCT (src_ip, dst_ip)) AS n_edges,
                 avg((proto = 6)::int) AS tcp_ratio, avg((proto = 17)::int) AS udp_ratio,
                 avg((conn_state IN ('S0','REJ','RSTOS0','RSTRH','SH','SHR'))::int) AS failed_ratio,
                 coalesce(avg(duration_ms), 0) AS mean_dur,
                 count(DISTINCT src_ip) AS n_src, count(DISTINCT dst_ip) AS n_dst, max(orig_bytes + resp_bytes) AS max_flow_bytes
          FROM w GROUP BY ws
        ), nodes AS (
          SELECT ws, count(DISTINCT ip) AS n_nodes FROM (SELECT ws, src_ip AS ip FROM w UNION SELECT ws, dst_ip FROM w) u GROUP BY ws
        )
        INSERT INTO temporal_states (sensor_id, window_start, window_seconds, schema_version, n_flows, n_nodes, n_edges,
                                     total_bytes, total_pkts, summary, features, feature_schema_id)
        SELECT :s, a.ws, :w, 1, a.n_flows, n.n_nodes, a.n_edges, a.bytes, a.pkts,
               jsonb_build_object('distinct_src', a.n_src, 'distinct_dst', a.n_dst, 'max_flow_bytes', a.max_flow_bytes),
               ARRAY[a.n_flows, n.n_nodes, a.n_edges, a.bytes, a.pkts, a.dports, a.tcp_ratio, a.udp_ratio, a.failed_ratio, a.mean_dur]::real[],
               :fs
        FROM agg a JOIN nodes n USING (ws)
        ON CONFLICT (sensor_id, window_start, window_seconds) DO UPDATE SET
          n_flows = EXCLUDED.n_flows, n_nodes = EXCLUDED.n_nodes, n_edges = EXCLUDED.n_edges,
          total_bytes = EXCLUDED.total_bytes, total_pkts = EXCLUDED.total_pkts, summary = EXCLUDED.summary,
          features = EXCLUDED.features, feature_schema_id = EXCLUDED.feature_schema_id, built_at = now()
        RETURNING state_id, sensor_id, window_start, window_seconds, schema_version, n_flows, n_nodes, n_edges,
                  total_bytes, total_pkts, summary, features
    """), params).mappings().all()

    if build_edges and rows:
        conn.execute(text(f"""
            WITH w AS (
              SELECT date_bin(make_interval(secs => :w), ts_start, TIMESTAMPTZ '{EPOCH}') AS ws, *
              FROM flows WHERE sensor_id = :s AND ts_start >= :start AND ts_start < :end
            )
            INSERT INTO state_edges (state_id, window_start, src_host_id, dst_host_id, n_flows, bytes, pkts, dst_ports, features)
            SELECT t.state_id, t.window_start, hs.host_id, hd.host_id, count(*), sum(w.orig_bytes + w.resp_bytes),
                   sum(w.orig_pkts + w.resp_pkts), count(DISTINCT w.dst_port),
                   ARRAY[count(*), sum(w.orig_bytes + w.resp_bytes), sum(w.orig_pkts + w.resp_pkts),
                         count(DISTINCT w.dst_port), coalesce(avg(w.duration_ms), 0)]::real[]
            FROM w
            JOIN temporal_states t ON t.sensor_id = :s AND t.window_start = w.ws AND t.window_seconds = :w
            JOIN hosts hs ON hs.ip = w.src_ip
            JOIN hosts hd ON hd.ip = w.dst_ip
            GROUP BY t.state_id, t.window_start, hs.host_id, hd.host_id
            ON CONFLICT (state_id, window_start, src_host_id, dst_host_id) DO UPDATE SET
              n_flows = EXCLUDED.n_flows, bytes = EXCLUDED.bytes, pkts = EXCLUDED.pkts,
              dst_ports = EXCLUDED.dst_ports, features = EXCLUDED.features
        """), params)

    states = [TemporalStateV1(**{**dict(r), "features": list(r["features"])}) for r in rows]
    return sorted(states, key=lambda s: s.window_start)


def recent_states(conn: Connection, sensor_id: UUID, limit: int) -> list[TemporalStateV1]:
    rows = conn.execute(text(
        "SELECT state_id, sensor_id, window_start, window_seconds, schema_version, n_flows, n_nodes, n_edges, "
        "total_bytes, total_pkts, summary, features FROM temporal_states WHERE sensor_id = :s "
        "ORDER BY window_start DESC LIMIT :n"), {"s": sensor_id, "n": limit}).mappings().all()
    return [TemporalStateV1(**{**dict(r), "features": list(r["features"])}) for r in reversed(rows)]
