"""Firewall/response action lifecycle: authorization, execution vs enforcement, expiry, removal."""
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from nextrace.contracts.v1 import ResponseActionProposalV1, VerificationResultV1
from nextrace.services import response as rs
from nextrace.services.security import AuthorizationError
from tests.conftest import NOW


def _proposal(hours=2):
    return ResponseActionProposalV1(action_type="block_ip", target="198.51.100.7", enforcement_point="fw-edge-1",
                                    justification="forecast: lateral movement from compromised host", expires_at=NOW + timedelta(hours=hours))


def _verify(ok, method="rule_readback", at=None):
    return VerificationResultV1(method=method, enforced=ok, observed={"rule_present": ok}, checked_at=at or NOW)


def test_full_lifecycle_executed_is_not_enforced(conn, seed):
    u = seed["users"]
    aid = rs.propose(conn, _proposal(), u["analyst"])
    assert conn.execute(text("SELECT status, enforced FROM response_actions WHERE action_id = :a"), {"a": aid}).one() == ("proposed", False)
    with pytest.raises(IntegrityError):  # two-person rule enforced by the database
        with conn.begin_nested():
            rs.authorize(conn, aid, u["analyst"])
    with pytest.raises(AuthorizationError):
        rs.authorize(conn, aid, u["viewer"])
    rs.authorize(conn, aid, u["analyst2"], "approved on call")
    rs.start_execution(conn, aid, u["service"])
    rs.record_execution(conn, aid, u["service"], True, "CHG-1001", {"api_status": 200})
    assert not rs.is_enforced(conn, aid)            # the API said yes; nothing has verified it
    assert rs.record_verification(conn, aid, u["service"], _verify(False, "probe")) is False
    assert conn.execute(text("SELECT status FROM response_actions WHERE action_id = :a"), {"a": aid}).scalar_one() == "verification_failed"
    rs.retry_execution(conn, aid, u["service"])
    rs.record_execution(conn, aid, u["service"], True, "CHG-1002", {"api_status": 200})
    assert rs.record_verification(conn, aid, u["service"], _verify(True)) is True
    assert rs.is_enforced(conn, aid)

    assert rs.expire_due(conn, NOW + timedelta(hours=1)) == []
    assert rs.expire_due(conn, NOW + timedelta(hours=3)) == [aid]
    assert not rs.is_enforced(conn, aid)
    rs.record_removal(conn, aid, u["service"], True)
    with pytest.raises(ValueError):
        rs.record_removal_verification(conn, aid, u["service"], _verify(True))   # still enforced => not removed
    rs.record_removal_verification(conn, aid, u["service"], _verify(False))
    trail = [(h["from_status"], h["to_status"]) for h in rs.history(conn, aid)]
    assert trail == [(None, "proposed"), ("proposed", "authorized"), ("authorized", "executing"), ("executing", "executed"),
                     ("executed", "verification_failed"), ("verification_failed", "executing"), ("executing", "executed"),
                     ("executed", "verified"), ("verified", "expired"), ("expired", "removed"), ("removed", "removal_verified")]
    actors = [h["actor_id"] for h in rs.history(conn, aid)]
    assert actors[0] == u["analyst"] and actors[1] == u["analyst2"] and actors[8] is None


def test_illegal_transitions_blocked_in_db_and_service(conn, seed):
    u = seed["users"]
    aid = rs.propose(conn, _proposal(), None)  # system-proposed
    with pytest.raises(ValueError, match="illegal"):
        rs.start_execution(conn, aid, u["service"])          # not authorized yet
    with pytest.raises(IntegrityError, match="illegal"):
        with conn.begin_nested():
            conn.execute(text("UPDATE response_actions SET status = 'verified' WHERE action_id = :a"), {"a": aid})
    with pytest.raises(IntegrityError, match="authorized_by"):
        with conn.begin_nested():
            conn.execute(text("UPDATE response_actions SET status = 'authorized' WHERE action_id = :a"), {"a": aid})
    with pytest.raises(IntegrityError, match="must start as proposed"):
        with conn.begin_nested():
            conn.execute(text("INSERT INTO response_actions (action_type, target, enforcement_point, justification, expires_at, status) "
                              "VALUES ('block_ip', '198.51.100.9', 'fw', 'justification text', now() + interval '1 hour', 'verified')"))
    rs.reject(conn, aid, u["dfir"], "false positive")
    with pytest.raises(ValueError, match="illegal"):
        rs.authorize(conn, aid, u["dfir"])
    with pytest.raises(IntegrityError, match="terminal"):
        with conn.begin_nested():
            conn.execute(text("UPDATE response_actions SET justification = 'edited later' WHERE action_id = :a"), {"a": aid})
    with pytest.raises(IntegrityError, match="append-only"):
        with conn.begin_nested():
            conn.execute(text("DELETE FROM response_action_events WHERE action_id = :a"), {"a": aid})


def test_every_block_has_an_expiry(conn):
    with pytest.raises(IntegrityError):
        with conn.begin_nested():
            conn.execute(text("INSERT INTO response_actions (action_type, target, enforcement_point, justification, expires_at) "
                              "VALUES ('block_ip', '198.51.100.9', 'fw', 'justification text', NULL)"))
