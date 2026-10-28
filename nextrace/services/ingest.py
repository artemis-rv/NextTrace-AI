"""Flow ingestion: validate (contract), upsert hosts, pre-create partitions, bulk-load with COPY."""
from __future__ import annotations

import csv
import io
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.engine import Connection

from nextrace.contracts.v1 import FlowRecordV1
from nextrace.db.partitions import ensure_partitions
from nextrace.services.security import pseudonymize_ip

COPY_COLUMNS = ("ts_start", "ts_end", "sensor_id", "batch_id", "community_id", "src_ip", "src_port", "dst_ip",
                "dst_port", "proto", "service", "duration_ms", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
                "conn_state", "history", "pcap_segment_id", "features", "feature_schema_id", "label")


@dataclass
class IngestResult:
    batch_id: UUID
    accepted: int = 0
    rejected: int = 0
    errors: list[str] = field(default_factory=list)  # first few validation messages, never raw payloads
    timings_s: dict[str, float] = field(default_factory=dict)


def create_batch(conn: Connection, sensor_id: UUID, source: str, object_sha256: bytes | None = None) -> UUID:
    return conn.execute(text(
        "INSERT INTO ingest_batches (sensor_id, source, object_sha256) VALUES (:s, :src, :h) RETURNING batch_id"),
        {"s": sensor_id, "src": source, "h": object_sha256}).scalar_one()


def validate_records(raw: Iterable[dict[str, Any] | FlowRecordV1], result: IngestResult) -> list[FlowRecordV1]:
    ok: list[FlowRecordV1] = []
    for item in raw:
        if isinstance(item, FlowRecordV1):
            ok.append(item)
            continue
        try:
            ok.append(FlowRecordV1.model_validate(item))
        except ValidationError as e:
            result.rejected += 1
            if len(result.errors) < 10:
                result.errors.append("; ".join(f"{'.'.join(map(str, err['loc']))}: {err['msg']}" for err in e.errors()))
    return ok


def upsert_hosts(conn: Connection, ips: set[str], seen_at: datetime) -> None:
    """One set-based statement per batch (unnest), not one round trip per host."""
    if not ips:
        return
    ordered = sorted(ips)
    conn.execute(text(
        "INSERT INTO hosts (ip, pseudonym, first_seen, last_seen) "
        "SELECT u.ip, u.p, :t, :t FROM unnest(CAST(:ips AS inet[]), CAST(:ps AS bytea[])) AS u(ip, p) "
        "ON CONFLICT (ip) DO UPDATE SET last_seen = GREATEST(hosts.last_seen, EXCLUDED.last_seen), "
        "first_seen = LEAST(hosts.first_seen, EXCLUDED.first_seen)"),
        {"t": seen_at, "ips": ordered, "ps": [pseudonymize_ip(ip) for ip in ordered]})


def _pg_array(values: list[float] | None) -> str | None:
    return None if values is None else "{" + ",".join(repr(float(v)) for v in values) + "}"


def ingest_flows(conn: Connection, sensor_id: UUID, batch_id: UUID, records: Iterable[dict[str, Any] | FlowRecordV1]) -> IngestResult:
    """Bulk-load validated flows. Rejected records are counted, not stored (OWASP: validate, don't echo)."""
    result = IngestResult(batch_id=batch_id)
    t0 = time.perf_counter()
    flows = validate_records(records, result)
    result.timings_s["validate"] = round(time.perf_counter() - t0, 4)
    if flows:
        ts_min = min(f.ts_start for f in flows)
        ts_max = max(f.ts_start for f in flows)
        ensure_partitions(conn, "flows", ts_min, ts_max)
        t1 = time.perf_counter()
        upsert_hosts(conn, {str(f.src_ip) for f in flows} | {str(f.dst_ip) for f in flows}, ts_max)
        result.timings_s["hosts"] = round(time.perf_counter() - t1, 4)

        t2 = time.perf_counter()
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        for f in flows:
            w.writerow([
                f.ts_start.isoformat(), f.ts_end.isoformat() if f.ts_end else None, str(sensor_id), str(batch_id),
                f.community_id, str(f.src_ip), f.src_port, str(f.dst_ip), f.dst_port, f.proto, f.service,
                f.duration_ms, f.orig_bytes, f.resp_bytes, f.orig_pkts, f.resp_pkts, f.conn_state, f.history,
                str(f.pcap_segment_id) if f.pcap_segment_id else None, _pg_array(f.features),
                str(f.feature_schema_id) if f.feature_schema_id else None, f.label,
            ])
        buf.seek(0)
        raw = conn.connection.cursor()  # psycopg2 cursor for COPY (SQLAlchemy has no COPY API)
        try:
            raw.copy_expert(f"COPY flows ({', '.join(COPY_COLUMNS)}) FROM STDIN WITH (FORMAT csv, NULL '')", buf)
        finally:
            raw.close()
        result.accepted = len(flows)
        result.timings_s["copy"] = round(time.perf_counter() - t2, 4)

    conn.execute(text(
        "UPDATE ingest_batches SET accepted = :a, rejected = :r, status = 'loaded' WHERE batch_id = :b"),
        {"a": result.accepted, "r": result.rejected, "b": batch_id})
    return result
