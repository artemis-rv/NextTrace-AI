"""Append-only, hash-chained audit log (chain is computed and enforced in the database)."""
from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection


def record(conn: Connection, action: str, *, object_type: str | None = None, object_id: str | UUID | None = None,
           details: dict[str, Any] | None = None, actor_id: UUID | None = None, actor_label: str | None = None,
           client_ip: str | None = None) -> int:
    row = conn.execute(text(
        "INSERT INTO audit_log (actor_id, actor_label, action, object_type, object_id, details, client_ip) "
        "VALUES (:actor, :label, :action, :otype, :oid, CAST(:details AS jsonb), CAST(:ip AS inet)) RETURNING audit_id"
    ), {"actor": actor_id, "label": actor_label, "action": action, "otype": object_type,
        "oid": None if object_id is None else str(object_id),
        "details": json.dumps(details or {}, default=str), "ip": client_ip}).scalar_one()
    return int(row)


def verify_chain(conn: Connection) -> int | None:
    """None when intact, otherwise the first audit_id that fails recomputation."""
    v = conn.execute(text("SELECT nt_audit_verify()")).scalar()
    return None if v is None else int(v)


def set_actor(conn: Connection, actor_id: UUID | None) -> None:
    conn.execute(text("SELECT set_config('nextrace.actor_id', :a, true)"), {"a": "" if actor_id is None else str(actor_id)})
