"""Deterministic policy and the verified response lifecycle: authorization, execution, verification, retry, expiry, revocation, extension."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from nextrace.config import get_settings
from nextrace.contracts.errors import Conflict, Forbidden
from nextrace.contracts.response import ActionExtensionRequestV1, PolicyInputV1, RevocationRequestV1
from nextrace.contracts.v1 import ResponseActionProposalV1
from nextrace.modules.response.connectors import DryRunConnector, InMemoryConnector
from nextrace.modules.response.lifecycle import ResponseManager
from nextrace.modules.response.policy import RulePolicyEngine


def _settings(**over):
    """A re-validated Settings (model_copy skips validation)."""
    from nextrace.config import Settings
    return Settings.model_validate({**get_settings().model_dump(), **over})


def _proposal(target="203.0.113.9", hours=2, action="block_ip", ep="memory"):
    return ResponseActionProposalV1(action_type=action, target=target, enforcement_point=ep, justification="test proposal justification",
                                    expires_at=datetime.now(timezone.utc) + timedelta(hours=hours))


def test_policy_rules_are_deterministic_and_explained():
    s = _settings(enforcement_mode="dry_run")
    pe = RulePolicyEngine(s)
    base = dict(proposal=_proposal(), duration_s=3600, enforcement_mode="dry_run")
    d = pe.evaluate(PolicyInputV1(**base, proposer_kind="llm_suggestion"))
    assert d.decision == "deny" and d.rules_fired == ["R01"]
    assert pe.evaluate(PolicyInputV1(**base, target_on_allowlist=True)).rules_fired == ["R02"]
    assert pe.evaluate(PolicyInputV1(**base, proposer_kind="system")).rules_fired == ["R03"]
    d = pe.evaluate(PolicyInputV1(**{**base, "duration_s": 10 ** 6}, asset_criticality=0.9, open_actions_on_target=3))
    assert d.decision == "allow_dry_run" and d.max_duration_s == s.policy_max_duration_critical_asset_s and d.requires_roles == ["dfir"] and {"R04", "R05", "R07", "R08"} <= set(d.rules_fired)
    d = pe.evaluate(PolicyInputV1(**{**base, "proposal": _proposal(action="isolate_host")}))
    assert "R06" in d.rules_fired and d.requires_roles == ["dfir"]
    # enforce mode: no auto-allow unless explicitly enabled
    pe2 = RulePolicyEngine(_settings(enforcement_mode="enforce", environment="staging"))
    d = pe2.evaluate(PolicyInputV1(**{**base, "enforcement_mode": "enforce"}, risk_score=0.99))
    assert d.decision == "require_human" and d.rules_fired[-1] == "R10"
    pe3 = RulePolicyEngine(_settings(enforcement_mode="enforce", environment="staging", policy_auto_allow_enabled=True))
    assert pe3.evaluate(PolicyInputV1(**{**base, "enforcement_mode": "enforce"}, risk_score=0.99, target_is_internal=False)).decision == "allow"
    assert pe3.evaluate(PolicyInputV1(**{**base, "enforcement_mode": "enforce"}, risk_score=0.5)).decision == "require_human"
    same = [pe.evaluate(PolicyInputV1(**base)).model_dump(exclude={"evaluated_at"}) for _ in range(3)]
    assert same[0] == same[1] == same[2]


def test_enforce_mode_is_refused_in_dev():
    with pytest.raises(ValueError):
        _settings(enforcement_mode="enforce", environment="dev")


def _mgr(connector, **over):
    s = _settings(environment="staging", enforcement_mode="enforce", verification_retry_limit=1, **over)
    return ResponseManager({"memory": connector, "dry-run": DryRunConnector()}, RulePolicyEngine(s), s), s


def test_full_lifecycle_verified_expiry_removal(conn, seed):
    users = seed["users"]
    mem = InMemoryConnector()
    mgr, s = _mgr(mem)
    aid, decision = mgr.propose(conn, _proposal(), users["analyst"], proposer_kind="analyst", risk_score=0.7)
    assert decision.decision == "require_human" and mgr.view(conn, aid).status == "proposed"
    with pytest.raises(Forbidden):
        mgr.authorize(conn, aid, users["analyst"])          # two-person rule
    with pytest.raises(Forbidden):
        mgr.authorize(conn, aid, users["viewer"])           # role too low
    mgr.authorize(conn, aid, users["analyst2"], "looks right")
    out = mgr.execute(conn, aid, users["dfir"])
    assert out["accepted"] and out["enforced"] and out["status"] == "verified"
    v = mgr.view(conn, aid)
    assert v.enforced and v.verification_method == "rule_readback" and mem.calls == ["install"]
    # expiry -> removal -> removal verified
    due = mgr.run_due(conn, now=datetime.now(timezone.utc) + timedelta(hours=3))   # clock moves past expiry
    assert due["expired"] == [str(aid)] and due["removed"] == [str(aid)]
    assert mgr.view(conn, aid).status == "removal_verified" and not mem.rules
    hist = [h["to_status"] for h in mgr.history(conn, aid)]
    assert hist == ["proposed", "authorized", "executing", "executed", "verified", "expired", "removed", "removal_verified"]


def test_accepted_but_not_enforced_retries_then_fails_with_escalation(conn, seed):
    users = seed["users"]
    mem = InMemoryConnector(accept=True, install=False)   # device says yes, rule never lands
    mgr, s = _mgr(mem)
    aid, _ = mgr.propose(conn, _proposal(), users["analyst"], risk_score=0.7)
    mgr.authorize(conn, aid, users["dfir"])
    first = mgr.execute(conn, aid, users["dfir"])
    assert first["accepted"] and first["enforced"] is False and first["status"] == "verification_failed" and not mgr.view(conn, aid).enforced
    second = mgr.execute(conn, aid, users["dfir"])
    assert second["status"] == "failed"
    assert conn.execute(text("SELECT count(*) FROM audit_log WHERE action = 'response.escalate' AND object_id = :a"), {"a": str(aid)}).scalar_one() == 1
    # refused command -> failed immediately
    mgr2, _ = _mgr(InMemoryConnector(accept=False))
    aid2, _ = mgr2.propose(conn, _proposal(target="203.0.113.10"), users["analyst"], risk_score=0.7)
    mgr2.authorize(conn, aid2, users["dfir"])
    assert mgr2.execute(conn, aid2, users["dfir"])["status"] == "failed"


def test_dry_run_never_reaches_verified(conn, seed):
    users = seed["users"]
    s = _settings(enforcement_mode="dry_run")
    mem = InMemoryConnector()
    mgr = ResponseManager({"memory": mem, "dry-run": DryRunConnector()}, RulePolicyEngine(s), s)
    aid, decision = mgr.propose(conn, _proposal(), users["analyst"], risk_score=0.7)
    assert decision.decision == "allow_dry_run"
    mgr.authorize(conn, aid, users["analyst2"])
    out = mgr.execute(conn, aid, users["dfir"])
    assert out["dry_run"] and out["enforced"] is False and out["status"] == "executed" and not mem.rules
    assert mgr.view(conn, aid).status == "executed" and not mgr.view(conn, aid).enforced
    due = mgr.run_due(conn, now=datetime.now(timezone.utc) + timedelta(hours=3))
    assert str(aid) in due["closed_unverified"] and mgr.view(conn, aid).status == "failed"


def test_revocation_and_authorized_extension(conn, seed):
    users = seed["users"]
    mem = InMemoryConnector()
    mgr, s = _mgr(mem, policy_max_duration_s=7200)
    aid, _ = mgr.propose(conn, _proposal(hours=1), users["analyst"], risk_score=0.7)
    mgr.authorize(conn, aid, users["analyst2"])
    assert mgr.execute(conn, aid, users["dfir"])["status"] == "verified"
    old_exp = mgr.view(conn, aid).expires_at
    # proposer and authorizer cannot extend; a third person can, bounded by the policy cap
    for who in (users["analyst"], users["analyst2"]):
        with pytest.raises(Forbidden):
            mgr.extend(conn, ActionExtensionRequestV1(action_id=aid, requested_by=who, new_expires_at=old_exp + timedelta(hours=1), reason="still active attacker"))
    with pytest.raises(Conflict):
        mgr.extend(conn, ActionExtensionRequestV1(action_id=aid, requested_by=users["dfir"], new_expires_at=old_exp - timedelta(minutes=1), reason="still active attacker"))
    mgr.extend(conn, ActionExtensionRequestV1(action_id=aid, requested_by=users["dfir"], new_expires_at=old_exp + timedelta(days=5), reason="still active attacker"))
    new_exp = mgr.view(conn, aid).expires_at
    assert old_exp < new_exp <= datetime.now(timezone.utc) + timedelta(seconds=7200 + 5)
    assert any(h["details"].get("extension") for h in mgr.history(conn, aid))
    # revocation removes the rule and verifies removal
    mgr.revoke(conn, RevocationRequestV1(action_id=aid, requested_by=users["admin"], reason="false positive confirmed"))
    assert mgr.view(conn, aid).status == "removal_verified" and not mem.rules
    # revoking a proposal rejects it
    aid2, _ = mgr.propose(conn, _proposal(target="203.0.113.11"), users["analyst"], risk_score=0.7)
    mgr.revoke(conn, RevocationRequestV1(action_id=aid2, requested_by=users["analyst2"], reason="not needed anymore"))
    assert mgr.view(conn, aid2).status == "rejected"
    with pytest.raises(Conflict):
        mgr.revoke(conn, RevocationRequestV1(action_id=aid2, requested_by=users["analyst2"], reason="not needed anymore"))


def test_policy_denies_llm_and_unscored_system_proposals(conn, seed):
    mgr, _ = _mgr(InMemoryConnector())
    with pytest.raises(Forbidden):
        mgr.propose(conn, _proposal(), seed["users"]["analyst"], proposer_kind="llm_suggestion")
    with pytest.raises(Forbidden):
        mgr.propose(conn, _proposal(), None, proposer_kind="system")
    assert conn.execute(text("SELECT count(*) FROM audit_log WHERE action = 'response.policy_deny'")).scalar_one() >= 2
    assert conn.execute(text("SELECT count(*) FROM response_actions")).scalar_one() == 0
