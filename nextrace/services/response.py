"""Response (firewall) actions: propose -> authorize -> execute -> verify -> expire -> remove.

The database trigger is the authority on legal transitions; this module mirrors the state machine
for callers and records who did what. 'executed' means the connector reported success; only a
recorded verification can make an action 'verified', which is the only enforced state.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from nextrace.contracts.v1 import ResponseActionProposalV1, VerificationResultV1
from nextrace.services import audit
from nextrace.services.security import AuthorizationError

TRANSITIONS: dict[str, set[str]] = {
    "proposed": {"authorized", "rejected"},
    "authorized": {"executing", "rejected"},
    "executing": {"executed", "failed"},
    "executed": {"verified", "verification_failed"},
    "verification_failed": {"executing", "failed"},
    "verified": {"expired", "removed"},
    "expired": {"removed", "failed"},
    "removed": {"removal_verified"},
    "rejected": set(), "failed": set(), "removal_verified": set(),
}
ENFORCED_STATES = {"verified"}


def propose(conn: Connection, proposal: ResponseActionProposalV1, proposed_by: UUID | None) -> UUID:
    audit.set_actor(conn, proposed_by)
    aid = conn.execute(text(
        "INSERT INTO response_actions (investigation_id, alert_id, run_id, action_type, target, peer, port, direction, "
        "enforcement_point, proposed_by, justification, expires_at) VALUES (:inv, :alert, :run, :type, CAST(:target AS inet), "
        "CAST(:peer AS inet), :port, :dir, :ep, :by, :why, :exp) RETURNING action_id"),
        {"inv": proposal.investigation_id, "alert": proposal.alert_id, "run": proposal.run_id, "type": proposal.action_type,
         "target": str(proposal.target), "peer": None if proposal.peer is None else str(proposal.peer), "port": proposal.port,
         "dir": proposal.direction, "ep": proposal.enforcement_point, "by": proposed_by, "why": proposal.justification,
         "exp": proposal.expires_at}).scalar_one()
    audit.record(conn, "response.propose", object_type="response_action", object_id=aid, actor_id=proposed_by,
                 details={"action_type": proposal.action_type, "target": str(proposal.target), "enforcement_point": proposal.enforcement_point})
    return aid


def _status(conn: Connection, action_id: UUID) -> str:
    s = conn.execute(text("SELECT status FROM response_actions WHERE action_id = :a FOR UPDATE"), {"a": action_id}).scalar()
    if s is None:
        raise LookupError("unknown response action")
    return s


def _transition(conn: Connection, action_id: UUID, to_status: str, actor: UUID | None, sets: str, params: dict[str, Any], action: str) -> None:
    frm = _status(conn, action_id)
    if to_status not in TRANSITIONS[frm]:
        raise ValueError(f"illegal transition {frm} -> {to_status}")
    audit.set_actor(conn, actor)
    conn.execute(text(f"UPDATE response_actions SET status = :to{sets} WHERE action_id = :a"), {"to": to_status, "a": action_id, **params})
    audit.record(conn, action, object_type="response_action", object_id=action_id, actor_id=actor, details={"from": frm, "to": to_status})


def authorize(conn: Connection, action_id: UUID, authorized_by: UUID, note: str | None = None) -> None:
    row = conn.execute(text("SELECT role FROM users WHERE user_id = :u AND active"), {"u": authorized_by}).first()
    if row is None or row.role not in ("analyst", "dfir", "admin"):
        raise AuthorizationError("only active analyst, dfir or admin users can authorize response actions")
    _transition(conn, action_id, "authorized", authorized_by, ", authorized_by = :by, authorized_at = now(), authorization_note = :note",
                {"by": authorized_by, "note": note}, "response.authorize")


def reject(conn: Connection, action_id: UUID, by: UUID, note: str) -> None:
    _transition(conn, action_id, "rejected", by, ", authorization_note = :note", {"note": note}, "response.reject")


def start_execution(conn: Connection, action_id: UUID, executor: UUID | None) -> None:
    _transition(conn, action_id, "executing", executor, "", {}, "response.execute_start")


def record_execution(conn: Connection, action_id: UUID, executor: UUID | None, ok: bool, execution_ref: str | None,
                     response: dict[str, Any]) -> None:
    """The connector's own result. Success here is NOT enforcement; call record_verification next."""
    to = "executed" if ok else "failed"
    _transition(conn, action_id, to, executor, ", executed_at = now(), execution_ref = :ref, execution_response = CAST(:resp AS jsonb)",
                {"ref": execution_ref, "resp": json.dumps(response, default=str)}, "response.execute_result")


def record_verification(conn: Connection, action_id: UUID, verifier: UUID | None, result: VerificationResultV1) -> bool:
    to = "verified" if result.enforced else "verification_failed"
    payload = {"enforced": result.enforced, "observed": result.observed, "checked_at": result.checked_at.isoformat()}
    _transition(conn, action_id, to, verifier, ", verified_at = :at, verification_method = :m, verification_result = CAST(:r AS jsonb)",
                {"at": result.checked_at, "m": result.method, "r": json.dumps(payload, default=str)}, "response.verify")
    return result.enforced


def retry_execution(conn: Connection, action_id: UUID, executor: UUID | None) -> None:
    _transition(conn, action_id, "executing", executor, "", {}, "response.execute_retry")


def mark_failed(conn: Connection, action_id: UUID, by: UUID | None, reason: str) -> None:
    _transition(conn, action_id, "failed", by, ", execution_response = COALESCE(execution_response, '{}'::jsonb) || CAST(:r AS jsonb)",
                {"r": json.dumps({"failure_reason": reason})}, "response.fail")


def expire_due(conn: Connection, now: datetime | None = None) -> list[UUID]:
    """Flip verified actions whose expiry passed to 'expired' so removal can be scheduled."""
    now = now or datetime.now(timezone.utc)
    ids = list(conn.execute(text(
        "SELECT action_id FROM response_actions WHERE status = 'verified' AND expires_at <= :now ORDER BY expires_at"), {"now": now}).scalars())
    for aid in ids:
        _transition(conn, aid, "expired", None, "", {}, "response.expire")
    return ids


def record_removal(conn: Connection, action_id: UUID, executor: UUID | None, ok: bool) -> None:
    if ok:
        _transition(conn, action_id, "removed", executor, ", removed_at = now()", {}, "response.remove")
    else:
        _transition(conn, action_id, "failed", executor, "", {}, "response.remove_failed")


def record_removal_verification(conn: Connection, action_id: UUID, verifier: UUID | None, result: VerificationResultV1) -> None:
    if result.enforced:
        raise ValueError("removal verification must observe the rule as no longer enforced")
    _transition(conn, action_id, "removal_verified", verifier, ", removal_verified_at = :at, verification_result = CAST(:r AS jsonb)",
                {"at": result.checked_at, "r": json.dumps({"removal": result.observed, "checked_at": result.checked_at.isoformat()}, default=str)},
                "response.remove_verify")


def is_enforced(conn: Connection, action_id: UUID) -> bool:
    return bool(conn.execute(text("SELECT enforced FROM response_actions WHERE action_id = :a"), {"a": action_id}).scalar())


def history(conn: Connection, action_id: UUID) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute(text(
        "SELECT from_status, to_status, actor_id, at, details FROM response_action_events WHERE action_id = :a ORDER BY at, event_id"),
        {"a": action_id}).mappings().all()]
