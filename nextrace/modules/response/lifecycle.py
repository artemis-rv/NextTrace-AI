"""Response lifecycle manager: policy gate -> authorization -> execution -> verification -> expiry/removal,
plus retry, escalation, revocation and authorized extension. Wraps services.response (the DB state machine).

Invariants:
  * nothing executes without a recorded authorization by an active user whose role satisfies the policy decision;
  * the proposer never authorizes their own proposal (DB CHECK) and never extends it either;
  * `executed` is command acceptance; only a verification with enforced=True reaches `verified`;
  * in dry_run mode the connector simulates and the action stops at `executed`, visibly unverified;
  * verification failures retry up to `verification_retry_limit`, then the action fails and an escalation is audited.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from nextrace.config import Settings
from nextrace.contracts.errors import Conflict, ConnectorError, Forbidden, NotFound
from nextrace.contracts.response import ActionExtensionRequestV1, ConnectorCommandV1, PolicyDecisionV1, PolicyInputV1, ResponseActionViewV1, RevocationRequestV1
from nextrace.contracts.v1 import ResponseActionProposalV1, VerificationResultV1
from nextrace.modules.response.connectors import idempotency_key
from nextrace.services import audit
from nextrace.services import response as svc
from nextrace.services.security import AuthorizationError

ROLE_RANK = {"viewer": 0, "analyst": 1, "dfir": 2, "admin": 3}


class ResponseManager:
    def __init__(self, connectors: dict[str, Any], policy: Any, settings: Settings):
        if not connectors:
            raise ValueError("at least one connector is required")
        self.connectors = connectors
        self.policy = policy
        self.s = settings

    # -- helpers ---------------------------------------------------------------------------------
    def _row(self, conn: Connection, action_id: UUID, lock: bool = False) -> dict[str, Any]:
        r = conn.execute(text("SELECT * FROM response_actions WHERE action_id = :a" + (" FOR UPDATE" if lock else "")), {"a": action_id}).mappings().first()
        if r is None:
            raise NotFound("response action not found")
        return dict(r)

    def _connector(self, enforcement_point: str) -> Any:
        c = self.connectors.get(enforcement_point) or self.connectors.get("dry-run")
        if c is None:
            raise ConnectorError("no connector for enforcement point", enforcement_point=enforcement_point)
        return c

    def _policy_input(self, conn: Connection, proposal: ResponseActionProposalV1, proposer_kind: str, risk_score: float | None,
                      asset_criticality: float | None, target_is_internal: bool | None) -> PolicyInputV1:
        open_on_target = conn.execute(text(
            "SELECT count(*) FROM response_actions WHERE target = CAST(:t AS inet) AND status NOT IN ('rejected','failed','removal_verified')"),
            {"t": str(proposal.target)}).scalar_one()
        allow = conn.execute(text("SELECT EXISTS (SELECT 1 FROM hosts WHERE ip = CAST(:t AS inet) AND asset_tag LIKE 'protected%')"), {"t": str(proposal.target).split("/")[0]}).scalar_one()
        return PolicyInputV1(proposal=proposal, risk_score=risk_score, asset_criticality=asset_criticality, target_is_internal=target_is_internal,
                             target_on_allowlist=bool(allow), proposer_kind=proposer_kind, enforcement_mode=self.s.enforcement_mode,
                             duration_s=max(1, int((proposal.expires_at - datetime.now(timezone.utc)).total_seconds())), open_actions_on_target=int(open_on_target))

    @staticmethod
    def _role(conn: Connection, user_id: UUID) -> str:
        r = conn.execute(text("SELECT role FROM users WHERE user_id = :u AND active"), {"u": user_id}).scalar()
        if r is None:
            raise Forbidden("unknown or inactive user")
        return r

    def _command(self, row: dict[str, Any], operation: str) -> ConnectorCommandV1:
        return ConnectorCommandV1(action_id=row["action_id"], action_type=row["action_type"], target=str(row["target"]),
                                  peer=str(row["peer"]) if row["peer"] else None, port=row["port"], direction=row["direction"],
                                  enforcement_point=row["enforcement_point"], expires_at=row["expires_at"], dry_run=self.s.enforcement_mode == "dry_run",
                                  idempotency_key=idempotency_key(row["action_id"], operation), operation=operation)

    # -- propose / authorize / reject ------------------------------------------------------------
    def propose(self, conn: Connection, proposal: ResponseActionProposalV1, proposed_by: UUID | None, proposer_kind: str = "analyst",
                risk_score: float | None = None, asset_criticality: float | None = None, target_is_internal: bool | None = None) -> tuple[UUID, PolicyDecisionV1]:
        inp = self._policy_input(conn, proposal, proposer_kind, risk_score, asset_criticality, target_is_internal)
        decision = self.policy.evaluate(inp)
        if decision.decision == "deny":
            audit.record(conn, "response.policy_deny", object_type="response_proposal", actor_id=proposed_by,
                         details={"rules": decision.rules_fired, "reasons": decision.reasons, "target": str(proposal.target)})
            raise Forbidden("policy denied the proposal", rules=decision.rules_fired)
        if decision.max_duration_s is not None:
            cap = datetime.now(timezone.utc) + timedelta(seconds=decision.max_duration_s)
            if proposal.expires_at > cap:
                proposal = proposal.model_copy(update={"expires_at": cap})
        aid = svc.propose(conn, proposal, proposed_by)
        audit.record(conn, "response.policy_decision", object_type="response_action", object_id=aid, actor_id=proposed_by,
                     details={"decision": decision.decision, "rules": decision.rules_fired, "requires_roles": decision.requires_roles,
                              "policy_version": decision.policy_version, "proposer_kind": proposer_kind, "risk_score": risk_score})
        return aid, decision

    def decision_for(self, conn: Connection, action_id: UUID) -> PolicyDecisionV1:
        """Deterministic re-evaluation from the stored row (same inputs -> same decision)."""
        row = self._row(conn, action_id)
        last = conn.execute(text("SELECT details FROM audit_log WHERE action = 'response.policy_decision' AND object_id = :a ORDER BY audit_id DESC LIMIT 1"),
                            {"a": str(action_id)}).scalar()
        details = last if isinstance(last, dict) else (json.loads(last) if last else {})
        proposal = ResponseActionProposalV1(action_type=row["action_type"], target=str(row["target"]), peer=str(row["peer"]) if row["peer"] else None,
                                            port=row["port"], direction=row["direction"], enforcement_point=row["enforcement_point"],
                                            justification=row["justification"], expires_at=max(row["expires_at"], datetime.now(timezone.utc) + timedelta(seconds=60)),
                                            alert_id=row["alert_id"], investigation_id=row["investigation_id"], run_id=row["run_id"])
        inp = self._policy_input(conn, proposal, details.get("proposer_kind", "system" if row["proposed_by"] is None else "analyst"),
                                 details.get("risk_score"), None, None)
        return self.policy.evaluate(inp)

    def authorize(self, conn: Connection, action_id: UUID, user_id: UUID, note: str | None = None) -> PolicyDecisionV1:
        row = self._row(conn, action_id, lock=True)
        if row["proposed_by"] == user_id:
            raise Forbidden("the proposer cannot authorize their own proposal")
        decision = self.decision_for(conn, action_id)
        role = self._role(conn, user_id)
        needed = max((ROLE_RANK[r] for r in decision.requires_roles), default=ROLE_RANK["analyst"])
        if ROLE_RANK.get(role, -1) < needed:
            audit.record(conn, "response.authorize_denied", object_type="response_action", object_id=action_id, actor_id=user_id,
                         details={"role": role, "requires": decision.requires_roles})
            raise Forbidden("role insufficient for this action", requires=decision.requires_roles)
        try:
            svc.authorize(conn, action_id, user_id, note)
        except AuthorizationError as e:
            raise Forbidden(str(e)) from e
        return decision

    def reject(self, conn: Connection, action_id: UUID, user_id: UUID, note: str) -> None:
        self._role(conn, user_id)
        svc.reject(conn, action_id, user_id, note)

    # -- execute + verify ------------------------------------------------------------------------
    def execute(self, conn: Connection, action_id: UUID, executor: UUID | None) -> dict[str, Any]:
        row = self._row(conn, action_id, lock=True)
        if row["status"] not in ("authorized", "verification_failed"):
            raise Conflict(f"action is {row['status']}, not executable")
        if row["expires_at"] <= datetime.now(timezone.utc):
            svc.mark_failed(conn, action_id, executor, "expired before execution")
            raise Conflict("action expired before execution")
        connector = self._connector(row["enforcement_point"])
        cmd = self._command(row, "install")
        if row["status"] == "authorized":
            svc.start_execution(conn, action_id, executor)
        else:
            svc.retry_execution(conn, action_id, executor)
        result = connector.execute(cmd)
        svc.record_execution(conn, action_id, executor, result.accepted, result.execution_ref, {**result.response, "dry_run": result.dry_run, "error": result.error})
        out: dict[str, Any] = {"accepted": result.accepted, "dry_run": result.dry_run, "execution_ref": result.execution_ref}
        if not result.accepted:
            out["status"] = "failed"
            audit.record(conn, "response.escalate", object_type="response_action", object_id=action_id, actor_id=executor,
                         details={"reason": "connector refused command", "error": result.error})
            return out
        if cmd.dry_run:
            out["status"] = "executed"
            out["enforced"] = False
            out["note"] = "dry-run: command simulated, nothing enforced, no verification attempted"
            audit.record(conn, "response.dry_run", object_type="response_action", object_id=action_id, actor_id=executor)
            return out
        verification = connector.verify(cmd)
        enforced = svc.record_verification(conn, action_id, executor, verification)
        out["enforced"] = enforced
        out["verification"] = verification.model_dump(mode="json")
        if not enforced:
            attempts = conn.execute(text("SELECT count(*) FROM response_action_events WHERE action_id = :a AND to_status = 'verification_failed'"), {"a": action_id}).scalar_one()
            if attempts > self.s.verification_retry_limit:
                svc.mark_failed(conn, action_id, executor, f"verification failed {attempts} times")
                audit.record(conn, "response.escalate", object_type="response_action", object_id=action_id, actor_id=executor,
                             details={"reason": "verification retry limit exceeded", "attempts": int(attempts)})
                out["status"] = "failed"
            else:
                out["status"] = "verification_failed"
                out["retries_left"] = int(self.s.verification_retry_limit - attempts + 1)
        else:
            out["status"] = "verified"
        return out

    def verify_now(self, conn: Connection, action_id: UUID, verifier: UUID | None) -> VerificationResultV1:
        """Re-check an enforced rule (periodic drift detection). A verified action that is no longer enforced is removed-and-failed."""
        row = self._row(conn, action_id)
        if row["status"] != "verified":
            raise Conflict("only verified actions can be re-verified")
        v = self._connector(row["enforcement_point"]).verify(self._command(row, "install"))
        audit.record(conn, "response.reverify", object_type="response_action", object_id=action_id, actor_id=verifier, details={"enforced": v.enforced})
        return v

    # -- expiry, removal, revocation, extension ---------------------------------------------------
    def _remove(self, conn: Connection, row: dict[str, Any], actor: UUID | None) -> bool:
        connector = self._connector(row["enforcement_point"])
        cmd = self._command(row, "remove")
        res = connector.execute(cmd)
        svc.record_removal(conn, row["action_id"], actor, res.accepted)
        if not res.accepted:
            return False
        v = connector.verify(self._command(row, "install"))
        if v.enforced:
            audit.record(conn, "response.escalate", object_type="response_action", object_id=row["action_id"], actor_id=actor,
                         details={"reason": "rule still enforced after removal"})
            return False
        svc.record_removal_verification(conn, row["action_id"], actor, v)
        return True

    def run_due(self, conn: Connection, now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(timezone.utc)
        expired = svc.expire_due(conn, now)
        removed, stuck = [], []
        for aid in expired:
            row = self._row(conn, aid, lock=True)
            (removed if self._remove(conn, row, None) else stuck).append(str(aid))
        # dry-run or never-verified actions past expiry: close them out so nothing lingers as 'executed'
        lingering = list(conn.execute(text("SELECT action_id FROM response_actions WHERE status IN ('executed','executing','verification_failed','authorized','proposed') "
                                           "AND expires_at <= :now"), {"now": now}).scalars())
        for aid in lingering:
            st = self._row(conn, aid)["status"]
            if st in ("proposed", "authorized"):
                svc.reject(conn, aid, None, "expired before execution") if st == "proposed" else svc.mark_failed_from_authorized(conn, aid) if hasattr(svc, "mark_failed_from_authorized") else self._fail_authorized(conn, aid)
            elif st == "executed":
                svc._transition(conn, aid, "verification_failed", None, ", verified_at = now(), verification_method = 'manual', verification_result = CAST(:r AS jsonb)",
                                {"r": json.dumps({"enforced": False, "note": "expired without verification"})}, "response.verify")
                svc.mark_failed(conn, aid, None, "expired without verification")
            else:
                svc.mark_failed(conn, aid, None, "expired before verification")
        return {"expired": [str(a) for a in expired], "removed": removed, "removal_stuck": stuck, "closed_unverified": [str(a) for a in lingering]}

    @staticmethod
    def _fail_authorized(conn: Connection, aid: UUID) -> None:
        svc.start_execution(conn, aid, None)
        svc.mark_failed(conn, aid, None, "expired before execution")

    def revoke(self, conn: Connection, req: RevocationRequestV1) -> None:
        row = self._row(conn, req.action_id, lock=True)
        role = self._role(conn, req.requested_by)
        if ROLE_RANK.get(role, -1) < ROLE_RANK["analyst"]:
            raise Forbidden("analyst role required to revoke")
        if row["status"] in ("proposed", "authorized"):
            svc.reject(conn, req.action_id, req.requested_by, f"revoked: {req.reason}")
        elif row["status"] == "verified":
            audit.record(conn, "response.revoke", object_type="response_action", object_id=req.action_id, actor_id=req.requested_by, details={"reason": req.reason})
            if not self._remove(conn, row, req.requested_by):
                raise ConnectorError("removal did not complete; escalation recorded")
        elif row["status"] in ("executed", "verification_failed"):
            audit.record(conn, "response.revoke", object_type="response_action", object_id=req.action_id, actor_id=req.requested_by, details={"reason": req.reason})
            svc.mark_failed(conn, req.action_id, req.requested_by, f"revoked: {req.reason}") if row["status"] == "verification_failed" else \
                self._fail_executed(conn, req.action_id, req.requested_by, req.reason)
        else:
            raise Conflict(f"action in state {row['status']} cannot be revoked")

    @staticmethod
    def _fail_executed(conn: Connection, aid: UUID, actor: UUID, reason: str) -> None:
        svc._transition(conn, aid, "verification_failed", actor, ", verified_at = now(), verification_method = 'manual', verification_result = CAST(:r AS jsonb)",
                        {"r": json.dumps({"enforced": False, "note": f"revoked: {reason}"})}, "response.verify")
        svc.mark_failed(conn, aid, actor, f"revoked: {reason}")

    def extend(self, conn: Connection, req: ActionExtensionRequestV1) -> UUID:
        """Authorized extension of an enforced action: a second person, a reason, a bounded new expiry. The original
        authorization and expiry stay in the event history; the row's expires_at moves forward."""
        row = self._row(conn, req.action_id, lock=True)
        if row["status"] != "verified":
            raise Conflict("only verified (enforced) actions can be extended")
        if req.requested_by in (row["proposed_by"], row["authorized_by"]):
            raise Forbidden("extension must be authorized by someone other than the proposer and the original authorizer")
        role = self._role(conn, req.requested_by)
        decision = self.decision_for(conn, req.action_id)
        needed = max((ROLE_RANK[r] for r in decision.requires_roles), default=ROLE_RANK["analyst"])
        if ROLE_RANK.get(role, -1) < needed:
            raise Forbidden("role insufficient to extend this action", requires=decision.requires_roles)
        now = datetime.now(timezone.utc)
        cap = now + timedelta(seconds=decision.max_duration_s or self.s.policy_max_duration_s)
        if req.new_expires_at <= row["expires_at"]:
            raise Conflict("new expiry must be later than the current expiry")
        new_exp = min(req.new_expires_at, cap)
        conn.execute(text("UPDATE response_actions SET expires_at = :e WHERE action_id = :a"), {"e": new_exp, "a": req.action_id})
        conn.execute(text("INSERT INTO response_action_events (action_id, from_status, to_status, actor_id, details) VALUES (:a, 'verified', 'verified', :u, CAST(:d AS jsonb))"),
                     {"a": req.action_id, "u": req.requested_by, "d": json.dumps({"extension": True, "old_expires_at": row["expires_at"].isoformat(),
                                                                                  "new_expires_at": new_exp.isoformat(), "reason": req.reason})})
        audit.record(conn, "response.extend", object_type="response_action", object_id=req.action_id, actor_id=req.requested_by,
                     details={"old_expires_at": row["expires_at"].isoformat(), "new_expires_at": new_exp.isoformat(), "capped": new_exp < req.new_expires_at})
        return req.action_id

    # -- read models ------------------------------------------------------------------------------
    def view(self, conn: Connection, action_id: UUID) -> ResponseActionViewV1:
        r = self._row(conn, action_id)
        return ResponseActionViewV1(action_id=r["action_id"], status=r["status"], enforced=bool(r["enforced"]), action_type=r["action_type"], target=str(r["target"]),
                                    enforcement_point=r["enforcement_point"], proposed_by=r["proposed_by"], authorized_by=r["authorized_by"], proposed_at=r["proposed_at"],
                                    expires_at=r["expires_at"], verified_at=r["verified_at"], verification_method=r["verification_method"],
                                    execution_ref=r["execution_ref"], investigation_id=r["investigation_id"], alert_id=r["alert_id"])

    def list(self, conn: Connection, status: str | None, limit: int) -> list[ResponseActionViewV1]:
        ids = conn.execute(text("SELECT action_id FROM response_actions WHERE (CAST(:s AS text) IS NULL OR status = :s) ORDER BY action_id DESC LIMIT :n"),
                           {"s": status, "n": limit}).scalars().all()
        return [self.view(conn, i) for i in ids]

    def history(self, conn: Connection, action_id: UUID) -> list[dict[str, Any]]:
        return svc.history(conn, action_id)
