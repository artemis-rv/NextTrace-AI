"""Alert persistence and the investigation-update command handler."""
from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from nextrace.contracts.errors import Conflict, Forbidden, NotFound
from nextrace.contracts.findings import AlertV1, AnalystFeedbackV1, InvestigationUpdateV1
from nextrace.services import audit, investigations

ALERT_TRANSITIONS = {"new": {"acknowledged", "closed", "escalated"}, "acknowledged": {"escalated", "closed"}, "escalated": {"closed"}, "closed": set()}


def emit_alert(conn: Connection, alert: AlertV1) -> UUID:
    aid = conn.execute(text(
        "INSERT INTO alerts (run_id, prediction_id, sensor_id, severity, title) VALUES (:r, :p, :s, :sev, :t) RETURNING alert_id"),
        {"r": alert.run_id, "p": alert.prediction_id, "s": alert.sensor_id, "sev": alert.severity, "t": alert.title[:256]}).scalar_one()
    details: dict[str, Any] = {"severity": alert.severity}
    if alert.risk is not None:
        details["risk"] = alert.risk.model_dump()
    if alert.event is not None:
        details["event_id"] = str(alert.event.event_id)
        details["techniques"] = alert.event.technique_ids
        details["matched_pattern"] = alert.event.matched_pattern_id
    audit.record(conn, "alert.emit", object_type="alert", object_id=aid, details=details)
    return aid


def list_alerts(conn: Connection, sensor_id: UUID | None, status: str | None, limit: int, cursor: UUID | None) -> list[dict[str, Any]]:
    rows = conn.execute(text(
        "SELECT alert_id, run_id, prediction_id, sensor_id, severity, title, status, assigned_to, investigation_id, created_at, updated_at "
        "FROM alerts WHERE (CAST(:s AS uuid) IS NULL OR sensor_id = :s) AND (CAST(:st AS text) IS NULL OR status = :st) "
        "AND (CAST(:c AS uuid) IS NULL OR alert_id < :c) ORDER BY alert_id DESC LIMIT :n"),
        {"s": sensor_id, "st": status, "c": cursor, "n": limit}).mappings().all()
    return [dict(r) for r in rows]


def get_alert(conn: Connection, alert_id: UUID) -> dict[str, Any]:
    row = conn.execute(text("SELECT * FROM alerts WHERE alert_id = :a"), {"a": alert_id}).mappings().first()
    if row is None:
        raise NotFound("alert not found")
    return dict(row)


def set_alert_status(conn: Connection, alert_id: UUID, status: str, actor: UUID, reason: str | None = None) -> None:
    cur = conn.execute(text("SELECT status FROM alerts WHERE alert_id = :a FOR UPDATE"), {"a": alert_id}).scalar()
    if cur is None:
        raise NotFound("alert not found")
    if status not in ALERT_TRANSITIONS[cur]:
        raise Conflict(f"alert cannot go from {cur} to {status}")
    conn.execute(text("UPDATE alerts SET status = :s, updated_at = now(), closed_reason = CASE WHEN :s = 'closed' THEN :r ELSE closed_reason END "
                      "WHERE alert_id = :a"), {"s": status, "r": reason, "a": alert_id})
    audit.record(conn, "alert.status", object_type="alert", object_id=alert_id, actor_id=actor, details={"from": cur, "to": status})


def record_feedback(conn: Connection, fb: AnalystFeedbackV1) -> UUID:
    """Stored for review; eligible_for_training stays false (schema default) so feedback never trains anything by default."""
    fid = conn.execute(text(
        "INSERT INTO analyst_feedback (prediction_id, user_id, verdict, note) VALUES (:p, :u, :v, :n) RETURNING feedback_id"),
        {"p": fb.prediction_id, "u": fb.user_id, "v": fb.verdict, "n": fb.note}).scalar_one()
    audit.record(conn, "feedback.record", object_type="prediction", object_id=fb.prediction_id, actor_id=fb.user_id, details={"verdict": fb.verdict})
    return fid


def apply_update(conn: Connection, upd: InvestigationUpdateV1) -> None:
    """Single entry point for case mutations; every branch goes through case-level authorization."""
    investigations.require_access(conn, upd.actor_id, upd.investigation_id, "metadata")
    if upd.action.startswith("link_"):
        object_type = {"link_alert": "alert", "link_finding": "forensic_finding", "link_forensic_finding": "forensic_finding",
                       "link_response_action": "response_action"}[upd.action]
        investigations.link_object(conn, upd.investigation_id, object_type, upd.object_id, upd.actor_id, upd.note)
        if object_type == "alert":
            conn.execute(text("UPDATE alerts SET investigation_id = :i, updated_at = now() WHERE alert_id = :a AND investigation_id IS NULL"),
                         {"i": upd.investigation_id, "a": upd.object_id})
        return
    if upd.action == "set_status":
        conn.execute(text("UPDATE investigations SET status = :s, closed_at = CASE WHEN :s = 'closed' THEN now() ELSE NULL END WHERE investigation_id = :i"),
                     {"s": upd.status, "i": upd.investigation_id})
        audit.record(conn, "investigation.status", object_type="investigation", object_id=upd.investigation_id, actor_id=upd.actor_id, details={"to": upd.status})
        return
    if upd.action == "add_note":
        conn.execute(text("UPDATE investigations SET summary = coalesce(summary, '') || :n WHERE investigation_id = :i"),
                     {"n": "\n" + upd.note.replace("\r", ""), "i": upd.investigation_id})
        audit.record(conn, "investigation.note", object_type="investigation", object_id=upd.investigation_id, actor_id=upd.actor_id)
        return
    if upd.action == "assign":
        row = conn.execute(text("SELECT active FROM users WHERE user_id = :u"), {"u": upd.assignee_id}).first()
        if row is None or not row.active:
            raise Forbidden("assignee must be an active user")
        conn.execute(text("UPDATE alerts SET assigned_to = :u, updated_at = now() WHERE investigation_id = :i"), {"u": upd.assignee_id, "i": upd.investigation_id})
        audit.record(conn, "investigation.assign", object_type="investigation", object_id=upd.investigation_id, actor_id=upd.actor_id,
                     details={"assignee": str(upd.assignee_id)})


def investigation_view(conn: Connection, investigation_id: UUID, actor: UUID) -> dict[str, Any]:
    investigations.require_access(conn, actor, investigation_id, "metadata")
    inv = conn.execute(text("SELECT * FROM investigations WHERE investigation_id = :i"), {"i": investigation_id}).mappings().first()
    if inv is None:
        raise NotFound("investigation not found")
    out = dict(inv)
    out["links"] = [dict(r) for r in conn.execute(text(
        "SELECT object_type, object_id, added_by, added_at, note FROM investigation_links WHERE investigation_id = :i ORDER BY added_at"), {"i": investigation_id}).mappings()]
    out["evidence"] = [dict(r) for r in conn.execute(text(
        "SELECT evidence_id, kind, encode(object_sha256,'hex') AS sha256, description, acquired_by, acquired_at, acquisition_method "
        "FROM evidence_items WHERE investigation_id = :i ORDER BY acquired_at"), {"i": investigation_id}).mappings()]
    out["holds"] = [dict(r) for r in conn.execute(text(
        "SELECT hold_id, status, scope_start, scope_end, reason FROM legal_holds WHERE investigation_id = :i"), {"i": investigation_id}).mappings()]
    return json.loads(json.dumps(out, default=str))
