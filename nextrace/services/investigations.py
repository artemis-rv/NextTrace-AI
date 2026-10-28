"""Investigations: case-level authorization, evidence with chain of custody, legal holds."""
from __future__ import annotations

import gzip
import io
import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from nextrace.services import audit
from nextrace.services.security import AuthorizationError
from nextrace.storage.object_store import LocalObjectStore, ObjectRef
from nextrace.storage import pcap as pcapmod

PCAP_KINDS = {"pcap_slice", "upload"}


def open_case(conn: Connection, case_number: str, title: str, severity: str, opened_by: UUID) -> UUID:
    cid = conn.execute(text(
        "INSERT INTO investigations (case_number, title, severity, opened_by) VALUES (:c, :t, :s, :u) RETURNING investigation_id"),
        {"c": case_number, "t": title, "s": severity, "u": opened_by}).scalar_one()
    audit.record(conn, "investigation.open", object_type="investigation", object_id=cid, actor_id=opened_by,
                 details={"case_number": case_number, "severity": severity})
    return cid


def link_object(conn: Connection, investigation_id: UUID, object_type: str, object_id: UUID, added_by: UUID, note: str | None = None) -> None:
    require_access(conn, added_by, investigation_id, "metadata")
    conn.execute(text(
        "INSERT INTO investigation_links (investigation_id, object_type, object_id, added_by, note) VALUES (:i, :t, :o, :u, :n) "
        "ON CONFLICT DO NOTHING"), {"i": investigation_id, "t": object_type, "o": object_id, "u": added_by, "n": note})


# -- authorization -----------------------------------------------------------------------------
def grant_access(conn: Connection, investigation_id: UUID, user_id: UUID, access_level: str, granted_by: UUID,
                 expires_at: datetime, reason: str) -> UUID:
    role = conn.execute(text("SELECT role FROM users WHERE user_id = :u AND active"), {"u": granted_by}).scalar()
    if role not in ("dfir", "admin"):
        raise AuthorizationError("only dfir or admin users can grant case access")
    gid = conn.execute(text(
        "INSERT INTO case_grants (investigation_id, user_id, access_level, granted_by, expires_at, reason) "
        "VALUES (:i, :u, :l, :g, :e, :r) RETURNING grant_id"),
        {"i": investigation_id, "u": user_id, "l": access_level, "g": granted_by, "e": expires_at, "r": reason}).scalar_one()
    audit.record(conn, "case.grant", object_type="investigation", object_id=investigation_id, actor_id=granted_by,
                 details={"user_id": str(user_id), "access_level": access_level, "expires_at": expires_at.isoformat()})
    return gid


def revoke_access(conn: Connection, grant_id: UUID, revoked_by: UUID) -> None:
    conn.execute(text("UPDATE case_grants SET revoked_at = now() WHERE grant_id = :g AND revoked_at IS NULL"), {"g": grant_id})
    audit.record(conn, "case.revoke", object_type="case_grant", object_id=grant_id, actor_id=revoked_by)


def has_access(conn: Connection, user_id: UUID, investigation_id: UUID, level: str) -> bool:
    """Deny by default. 'full_pcap' satisfies 'metadata'; nothing is implied by role alone except admin."""
    if level not in ("metadata", "full_pcap"):
        raise ValueError("unknown access level")
    row = conn.execute(text("SELECT role, active FROM users WHERE user_id = :u"), {"u": user_id}).first()
    if row is None or not row.active:
        return False
    if level == "metadata":
        if row.role == "admin":
            return True
        if conn.execute(text("SELECT opened_by = :u FROM investigations WHERE investigation_id = :i"),
                        {"u": user_id, "i": investigation_id}).scalar():
            return True  # the case owner; packet access still needs an explicit grant from someone else
    levels = ["full_pcap"] if level == "full_pcap" else ["metadata", "full_pcap"]
    return conn.execute(text(
        "SELECT EXISTS (SELECT 1 FROM case_grants WHERE investigation_id = :i AND user_id = :u AND revoked_at IS NULL "
        "AND expires_at > now() AND access_level = ANY(:levels))"),
        {"i": investigation_id, "u": user_id, "levels": levels}).scalar_one()


def require_access(conn: Connection, user_id: UUID, investigation_id: UUID, level: str) -> None:
    if not has_access(conn, user_id, investigation_id, level):
        audit.record(conn, "case.access_denied", object_type="investigation", object_id=investigation_id, actor_id=user_id,
                     details={"level": level})
        raise AuthorizationError(f"user lacks {level} access to this investigation")


# -- evidence ----------------------------------------------------------------------------------
def register_object(conn: Connection, ref: ObjectRef, kind: str, media_type: str) -> None:
    conn.execute(text(
        "INSERT INTO objects (sha256, size_bytes, media_type, kind, storage_path) VALUES (:h, :s, :m, :k, :p) "
        "ON CONFLICT (sha256) DO NOTHING"), {"h": ref.sha256, "s": ref.size_bytes, "m": media_type, "k": kind, "p": ref.storage_path})


def add_evidence(conn: Connection, investigation_id: UUID, ref: ObjectRef, kind: str, media_type: str, description: str,
                 acquired_by: UUID, acquisition_method: str, source_sensor_id: UUID | None = None,
                 ts_first: datetime | None = None, ts_last: datetime | None = None) -> UUID:
    require_access(conn, acquired_by, investigation_id, "metadata")
    register_object(conn, ref, "artifact" if kind in ("artifact", "report") else ("pcap" if kind in PCAP_KINDS else "export"), media_type)
    eid = conn.execute(text(
        "INSERT INTO evidence_items (investigation_id, kind, object_sha256, description, source_sensor_id, ts_first, ts_last, acquired_by, acquisition_method) "
        "VALUES (:i, :k, :h, :d, :s, :f, :l, :u, :m) RETURNING evidence_id"),
        {"i": investigation_id, "k": kind, "h": ref.sha256, "d": description, "s": source_sensor_id, "f": ts_first, "l": ts_last,
         "u": acquired_by, "m": acquisition_method}).scalar_one()
    _custody(conn, eid, "acquired", acquired_by, True, {"sha256": ref.hex, "size_bytes": ref.size_bytes, "method": acquisition_method})
    audit.record(conn, "evidence.acquire", object_type="evidence", object_id=eid, actor_id=acquired_by,
                 details={"investigation_id": str(investigation_id), "sha256": ref.hex, "kind": kind})
    return eid


def _custody(conn: Connection, evidence_id: UUID, action: str, actor: UUID, hash_verified: bool | None, details: dict[str, Any]) -> None:
    conn.execute(text(
        "INSERT INTO custody_events (evidence_id, action, actor_id, hash_verified, details) VALUES (:e, :a, :u, :v, CAST(:d AS jsonb))"),
        {"e": evidence_id, "a": action, "u": actor, "v": hash_verified, "d": json.dumps(details, default=str)})


def _evidence_ref(conn: Connection, evidence_id: UUID) -> tuple[dict[str, Any], ObjectRef]:
    row = conn.execute(text(
        "SELECT e.investigation_id, e.kind, o.sha256, o.size_bytes, o.storage_path, o.deleted_at "
        "FROM evidence_items e JOIN objects o ON o.sha256 = e.object_sha256 WHERE e.evidence_id = :e"), {"e": evidence_id}).mappings().first()
    if row is None:
        raise LookupError("unknown evidence item")
    return dict(row), ObjectRef(bytes(row["sha256"]), int(row["size_bytes"]), row["storage_path"])


def verify_evidence(conn: Connection, store: LocalObjectStore, evidence_id: UUID, actor: UUID) -> bool:
    row, ref = _evidence_ref(conn, evidence_id)
    require_access(conn, actor, row["investigation_id"], "metadata")
    ok = row["deleted_at"] is None and store.verify(ref)
    conn.execute(text("UPDATE objects SET last_verified_at = now(), verify_ok = :ok WHERE sha256 = :h"), {"ok": ok, "h": ref.sha256})
    _custody(conn, evidence_id, "verified", actor, ok, {"sha256": ref.hex})
    audit.record(conn, "evidence.verify", object_type="evidence", object_id=evidence_id, actor_id=actor, details={"ok": ok})
    return ok


def open_evidence(conn: Connection, store: LocalObjectStore, evidence_id: UUID, user_id: UUID) -> ObjectRef:
    """Authorise, verify integrity, record custody; the caller streams the object from the returned ref.
    Packet captures need an explicit full_pcap grant on the case."""
    row, ref = _evidence_ref(conn, evidence_id)
    level = "full_pcap" if row["kind"] in PCAP_KINDS else "metadata"
    require_access(conn, user_id, row["investigation_id"], level)
    if row["deleted_at"] is not None or not store.verify(ref):
        _custody(conn, evidence_id, "accessed", user_id, False, {"sha256": ref.hex})
        raise RuntimeError("evidence failed integrity verification; access refused")
    _custody(conn, evidence_id, "accessed", user_id, True, {"sha256": ref.hex, "level": level})
    audit.record(conn, "evidence.access", object_type="evidence", object_id=evidence_id, actor_id=user_id, details={"level": level})
    return ref


def carve_pcap_evidence(conn: Connection, store: LocalObjectStore, investigation_id: UUID, sensor_id: UUID | None,
                        start: datetime, end: datetime, actor: UUID, description: str) -> UUID:
    """Carve a packet slice from retained captures into a new immutable evidence object."""
    require_access(conn, actor, investigation_id, "full_pcap")
    segs = pcapmod.segments_overlapping(conn, sensor_id, start, end)
    buf = io.BytesIO()
    n = pcapmod.carve(store, segs, start, end, buf)
    ref = store.put_bytes(buf.getvalue(), "pcap")
    eid = add_evidence(conn, investigation_id, ref, "pcap_slice", pcapmod.PCAP_MEDIA_TYPE, description, actor,
                       f"carved {n} packets from {len(segs)} retained segment(s)", sensor_id, start, end)
    return eid


# -- legal holds -------------------------------------------------------------------------------
def place_hold(conn: Connection, investigation_id: UUID, scope_start: datetime, scope_end: datetime, reason: str,
               requested_by: UUID, approved_by: UUID, sensor_id: UUID | None = None, host_ips: list[str] | None = None) -> UUID:
    require_access(conn, requested_by, investigation_id, "metadata")
    role = conn.execute(text("SELECT role FROM users WHERE user_id = :u AND active"), {"u": approved_by}).scalar()
    if role not in ("dfir", "admin"):
        raise AuthorizationError("legal holds must be approved by a dfir or admin user")
    hid = conn.execute(text(
        "INSERT INTO legal_holds (investigation_id, sensor_id, scope_start, scope_end, host_ips, reason, requested_by, approved_by) "
        "VALUES (:i, :s, :a, :b, CAST(:h AS inet[]), :r, :q, :p) RETURNING hold_id"),
        {"i": investigation_id, "s": sensor_id, "a": scope_start, "b": scope_end, "h": host_ips, "r": reason, "q": requested_by, "p": approved_by}).scalar_one()
    conn.execute(text(
        "UPDATE pcap_segments SET hold_count = hold_count + 1, status = 'held' WHERE status <> 'reclaimed' "
        "AND ts_last >= :a AND ts_first <= :b AND (CAST(:s AS uuid) IS NULL OR sensor_id = :s)"),
        {"a": scope_start, "b": scope_end, "s": sensor_id})
    audit.record(conn, "hold.place", object_type="legal_hold", object_id=hid, actor_id=requested_by,
                 details={"approved_by": str(approved_by), "scope": [scope_start.isoformat(), scope_end.isoformat()]})
    return hid


def preserve_hold(conn: Connection, store: LocalObjectStore, hold_id: UUID, actor: UUID) -> UUID:
    """Copy in-scope flows and states to an immutable gzip JSONL evidence object; the hold becomes 'preserved'."""
    h = conn.execute(text("SELECT * FROM legal_holds WHERE hold_id = :h FOR UPDATE"), {"h": hold_id}).mappings().first()
    if h is None or h["status"] != "pending":
        raise ValueError("hold is not pending")
    require_access(conn, actor, h["investigation_id"], "metadata")
    params = {"a": h["scope_start"], "b": h["scope_end"], "s": h["sensor_id"], "ips": h["host_ips"]}
    host_filter = "" if h["host_ips"] is None else " AND (src_ip = ANY(CAST(:ips AS inet[])) OR dst_ip = ANY(CAST(:ips AS inet[])))"
    buf = io.BytesIO()
    n_flows = n_states = 0
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        for r in conn.execute(text(
                "SELECT row_to_json(f) AS j FROM flows f WHERE ts_start >= :a AND ts_start < :b "
                "AND (CAST(:s AS uuid) IS NULL OR sensor_id = :s)" + host_filter + " ORDER BY ts_start, flow_id"), params).scalars():
            gz.write(json.dumps({"flow": r}, default=str).encode() + b"\n")
            n_flows += 1
        for r in conn.execute(text(
                "SELECT row_to_json(t) AS j FROM temporal_states t WHERE window_start >= :a AND window_start < :b "
                "AND (CAST(:s AS uuid) IS NULL OR sensor_id = :s) ORDER BY window_start"), params).scalars():
            gz.write(json.dumps({"state": r}, default=str).encode() + b"\n")
            n_states += 1
    ref = store.put_bytes(buf.getvalue(), "export")
    eid = add_evidence(conn, h["investigation_id"], ref, "flow_export", "application/gzip",
                       f"legal hold {hold_id}: {n_flows} flows, {n_states} states", actor,
                       "preserve_hold: row_to_json export of in-scope flows and temporal states", h["sensor_id"],
                       h["scope_start"], h["scope_end"])
    conn.execute(text("UPDATE legal_holds SET status = 'preserved', preserved_at = now() WHERE hold_id = :h"), {"h": hold_id})
    audit.record(conn, "hold.preserve", object_type="legal_hold", object_id=hold_id, actor_id=actor,
                 details={"evidence_id": str(eid), "flows": n_flows, "states": n_states})
    return eid


def release_hold(conn: Connection, hold_id: UUID, released_by: UUID) -> None:
    h = conn.execute(text("SELECT * FROM legal_holds WHERE hold_id = :h FOR UPDATE"), {"h": hold_id}).mappings().first()
    if h is None or h["status"] == "released":
        raise ValueError("hold is not active")
    role = conn.execute(text("SELECT role FROM users WHERE user_id = :u AND active"), {"u": released_by}).scalar()
    if role not in ("dfir", "admin"):
        raise AuthorizationError("legal holds can only be released by a dfir or admin user")
    conn.execute(text(
        "UPDATE pcap_segments SET hold_count = hold_count - 1 WHERE status = 'held' AND hold_count > 0 "
        "AND ts_last >= :a AND ts_first <= :b AND (CAST(:s AS uuid) IS NULL OR sensor_id = :s)"),
        {"a": h["scope_start"], "b": h["scope_end"], "s": h["sensor_id"]})
    conn.execute(text("UPDATE pcap_segments SET status = 'active' WHERE status = 'held' AND hold_count = 0"))
    conn.execute(text("UPDATE legal_holds SET status = 'released', released_at = now(), released_by = :u WHERE hold_id = :h"),
                 {"u": released_by, "h": hold_id})
    audit.record(conn, "hold.release", object_type="legal_hold", object_id=hold_id, actor_id=released_by)


def holds_blocking(conn: Connection, start: datetime, end: datetime) -> list[UUID]:
    """Pending holds overlapping [start, end): retention must not drop data under them."""
    return list(conn.execute(text(
        "SELECT hold_id FROM legal_holds WHERE status = 'pending' AND scope_start < :e AND scope_end > :s"),
        {"s": start, "e": end}).scalars())
