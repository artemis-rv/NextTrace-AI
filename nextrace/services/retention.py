"""Retention enforcement: partition drops (vetoed by pending legal holds), bounded PCAP rings,
forecast history trimming, object integrity sweep. Every action is audited."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Connection

from nextrace.config import Settings
from nextrace.db.partitions import drop_partition, list_partitions
from nextrace.services import audit
from nextrace.services.investigations import holds_blocking
from nextrace.storage.object_store import LocalObjectStore, ObjectRef


@dataclass
class RetentionReport:
    dropped: dict[str, list[str]] = field(default_factory=dict)
    skipped_for_hold: dict[str, list[str]] = field(default_factory=dict)
    forecast_runs_deleted: int = 0
    pcap_segments_reclaimed: int = 0
    pcap_bytes_freed: int = 0

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__


def _day_bounds(day: date) -> tuple[datetime, datetime]:
    s = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    return s, s + timedelta(days=1)


def enforce_partitions(conn: Connection, table: str, retention_days: int, now: datetime, report: RetentionReport) -> None:
    cutoff = (now - timedelta(days=retention_days)).date()
    for name, day in list_partitions(conn, table):
        if day >= cutoff:
            continue
        s, e = _day_bounds(day)
        blocking = holds_blocking(conn, s, e)
        if blocking:
            report.skipped_for_hold.setdefault(table, []).append(name)
            continue
        drop_partition(conn, name)
        report.dropped.setdefault(table, []).append(name)
        audit.record(conn, "retention.drop_partition", object_type="partition", object_id=name, details={"table": table, "day": day.isoformat()})


def enforce_forecasts(conn: Connection, retention_days: int, now: datetime, report: RetentionReport) -> None:
    """Delete old runs that nothing references (alerts, investigations, feedback keep their runs)."""
    cutoff = now - timedelta(days=retention_days)
    conn.execute(text("SELECT set_config('nextrace.retention_job', 'on', true)"))
    ids = list(conn.execute(text(
        "SELECT r.run_id FROM forecast_runs r WHERE r.created_at < :c "
        "AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.run_id = r.run_id) "
        "AND NOT EXISTS (SELECT 1 FROM investigation_links l WHERE l.object_type = 'forecast_run' AND l.object_id = r.run_id) "
        "AND NOT EXISTS (SELECT 1 FROM analyst_feedback f JOIN predictions p ON p.prediction_id = f.prediction_id WHERE p.run_id = r.run_id) "
        "AND NOT EXISTS (SELECT 1 FROM response_actions x WHERE x.run_id = r.run_id) "
        "AND NOT EXISTS (SELECT 1 FROM simulations s WHERE s.base_run_id = r.run_id) "
        "AND NOT EXISTS (SELECT 1 FROM forecast_current c WHERE c.run_id = r.run_id)"), {"c": cutoff}).scalars())
    if ids:
        p = {"ids": ids}
        conn.execute(text("DELETE FROM explanations WHERE run_id = ANY(CAST(:ids AS uuid[]))"), p)
        conn.execute(text("DELETE FROM progression_forecasts WHERE run_id = ANY(CAST(:ids AS uuid[]))"), p)
        conn.execute(text("DELETE FROM predictions WHERE run_id = ANY(CAST(:ids AS uuid[]))"), p)
        conn.execute(text("DELETE FROM forecast_runs WHERE run_id = ANY(CAST(:ids AS uuid[]))"), p)
        audit.record(conn, "retention.delete_forecasts", details={"count": len(ids), "cutoff": cutoff.isoformat()})
    conn.execute(text("SELECT set_config('nextrace.retention_job', 'off', true)"))
    report.forecast_runs_deleted = len(ids)


def _reclaim(conn: Connection, store: LocalObjectStore, seg: dict[str, Any], report: RetentionReport) -> None:
    ref = ObjectRef(bytes(seg["sha256"]), int(seg["size_bytes"]), seg["storage_path"])
    still_evidence = conn.execute(text("SELECT EXISTS (SELECT 1 FROM evidence_items WHERE object_sha256 = :h)"), {"h": ref.sha256}).scalar_one()
    others = conn.execute(text(
        "SELECT count(*) FROM pcap_segments WHERE object_sha256 = :h AND segment_id <> :id AND status <> 'reclaimed'"),
        {"h": ref.sha256, "id": seg["segment_id"]}).scalar_one()
    conn.execute(text("UPDATE pcap_segments SET status = 'reclaimed', reclaimed_at = now() WHERE segment_id = :id"), {"id": seg["segment_id"]})
    if not still_evidence and others == 0:
        store.delete(ref)
        conn.execute(text("UPDATE objects SET deleted_at = now() WHERE sha256 = :h"), {"h": ref.sha256})
        report.pcap_bytes_freed += ref.size_bytes
    report.pcap_segments_reclaimed += 1
    audit.record(conn, "retention.reclaim_pcap", object_type="pcap_segment", object_id=seg["segment_id"],
                 details={"sha256": ref.hex, "bytes": ref.size_bytes, "object_deleted": not still_evidence and others == 0})


def enforce_pcap(conn: Connection, store: LocalObjectStore, settings: Settings, now: datetime, report: RetentionReport) -> None:
    """Age rule per capture kind, then oldest-first reclaim until under the byte budget. Held segments are never reclaimed."""
    sel = ("SELECT s.segment_id, s.capture_kind, s.created_at, o.sha256, o.size_bytes, o.storage_path FROM pcap_segments s "
           "JOIN objects o ON o.sha256 = s.object_sha256 WHERE s.status = 'active' AND s.hold_count = 0 ")
    header_cutoff = now - timedelta(days=settings.header_pcap_retention_days)
    full_cutoff = now - timedelta(hours=settings.full_pcap_retention_hours)
    aged = conn.execute(text(sel + "AND ((s.capture_kind = 'headers' AND s.ts_last < :h) OR (s.capture_kind = 'full' AND s.ts_last < :f)) "
                             "ORDER BY s.created_at"), {"h": header_cutoff, "f": full_cutoff}).mappings().all()
    for seg in aged:
        _reclaim(conn, store, dict(seg), report)
    used = conn.execute(text(
        "SELECT coalesce(sum(o.size_bytes), 0) FROM pcap_segments s JOIN objects o ON o.sha256 = s.object_sha256 WHERE s.status <> 'reclaimed'")).scalar_one()
    if used > settings.pcap_budget_bytes:
        for seg in conn.execute(text(sel + "AND s.capture_kind <> 'upload' ORDER BY s.created_at")).mappings().all():
            if used <= settings.pcap_budget_bytes:
                break
            _reclaim(conn, store, dict(seg), report)
            used -= int(seg["size_bytes"])


def verify_objects(conn: Connection, store: LocalObjectStore, limit: int = 1000) -> dict[str, int]:
    """Integrity sweep over live objects, oldest-verified first."""
    rows = conn.execute(text(
        "SELECT sha256, size_bytes, storage_path FROM objects WHERE deleted_at IS NULL ORDER BY last_verified_at NULLS FIRST LIMIT :n"),
        {"n": limit}).mappings().all()
    ok = bad = 0
    for r in rows:
        ref = ObjectRef(bytes(r["sha256"]), int(r["size_bytes"]), r["storage_path"])
        good = store.verify(ref)
        conn.execute(text("UPDATE objects SET last_verified_at = now(), verify_ok = :ok WHERE sha256 = :h"), {"ok": good, "h": ref.sha256})
        if good:
            ok += 1
        else:
            bad += 1
            audit.record(conn, "integrity.object_mismatch", object_type="object", object_id=ref.hex)
    return {"verified": ok, "failed": bad}


def enforce(conn: Connection, store: LocalObjectStore, settings: Settings, now: datetime | None = None) -> RetentionReport:
    now = now or datetime.now(timezone.utc)
    report = RetentionReport()
    enforce_partitions(conn, "state_edges", settings.state_edge_retention_days, now, report)
    enforce_partitions(conn, "temporal_states", settings.state_retention_days, now, report)
    enforce_partitions(conn, "flows", settings.flow_retention_days, now, report)
    enforce_forecasts(conn, settings.forecast_retention_days, now, report)
    enforce_pcap(conn, store, settings, now, report)
    return report
