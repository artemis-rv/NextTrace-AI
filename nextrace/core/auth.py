"""API-key authentication and role checks. Keys are compared as SHA-256 digests in constant time.

Roles: viewer < analyst < dfir < admin; `service` is for machine producers (capture, forensics workers).
Case-level (object-level) authorization is enforced separately by services.investigations (OWASP API1).
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from nextrace.contracts.errors import Forbidden, Unauthorized
from nextrace.services.security import hash_api_key

ROLE_RANK = {"viewer": 0, "analyst": 1, "dfir": 2, "admin": 3}


@dataclass(frozen=True)
class Principal:
    user_id: UUID
    username: str
    role: str

    def at_least(self, role: str) -> bool:
        if self.role == "service":
            return role == "service"
        return ROLE_RANK.get(self.role, -1) >= ROLE_RANK[role]


def authenticate(conn: Connection, raw_key: str | None) -> Principal:
    if not raw_key or len(raw_key) > 256:
        raise Unauthorized()
    digest = hash_api_key(raw_key)
    row = conn.execute(text("SELECT user_id, username, role, api_key_hash FROM users WHERE api_key_hash = :h AND active"),
                       {"h": digest}).first()
    # The DB lookup is by exact digest; the constant-time compare guards against a future non-indexed path.
    if row is None or not hmac.compare_digest(bytes(row.api_key_hash), digest):
        raise Unauthorized()
    return Principal(user_id=row.user_id, username=row.username, role=row.role)


def require_role(principal: Principal, role: str) -> None:
    if not principal.at_least(role):
        raise Forbidden(f"role {role} required", have=principal.role)


def require_any_role(principal: Principal, roles: tuple[str, ...]) -> None:
    if principal.role not in roles:
        raise Forbidden("insufficient role", have=principal.role)
