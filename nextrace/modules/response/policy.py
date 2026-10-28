"""Deterministic response policy (NIST SP 800-207 vocabulary: this is the policy engine; the connector is the
enforcement point). No LLM output reaches this code. Every decision lists the rules that fired.

Rules (ordered, first terminal decision wins, caps accumulate):
  R01 proposer is an LLM suggestion                        -> deny (LLM06: no agency)
  R02 target on the protection allow-list                   -> deny
  R03 system proposal without a risk score                  -> deny
  R04 duration above the global cap                         -> cap to policy_max_duration_s
  R05 critical asset (criticality >= 0.8)                   -> cap to critical max, require dfir
  R06 isolate_host                                          -> require dfir (configurable)
  R07 >= 3 open actions on the same target                  -> require dfir (escalation)
  R08 enforcement_mode == dry_run                           -> allow_dry_run (human still authorises; nothing is enforced)
  R09 auto-allow enabled, enforce mode, risk >= threshold   -> allow   (disabled by default; RESEARCH REQUIRED thresholds)
  R10 otherwise                                             -> require_human (analyst)
"""
from __future__ import annotations

from datetime import datetime, timezone

from nextrace.config import Settings
from nextrace.contracts.response import PolicyDecisionV1, PolicyInputV1

CRITICAL_ASSET = 0.8  # band edge for "critical asset"; the criticality value itself comes from asset inventory


class RulePolicyEngine:
    def __init__(self, settings: Settings):
        self.s = settings

    def evaluate(self, inp: PolicyInputV1) -> PolicyDecisionV1:
        fired: list[str] = []
        reasons: list[str] = []
        roles: set[str] = set()
        max_duration: int | None = None
        now = datetime.now(timezone.utc)

        def deny(rule: str, why: str) -> PolicyDecisionV1:
            fired.append(rule); reasons.append(why)
            return PolicyDecisionV1(decision="deny", rules_fired=fired, reasons=reasons, policy_version=self.s.policy_version, evaluated_at=now)

        if inp.proposer_kind == "llm_suggestion":
            return deny("R01", "LLM output cannot propose privileged actions; an analyst must author the proposal")
        if inp.target_on_allowlist:
            return deny("R02", "target is on the protected allow-list")
        if inp.proposer_kind == "system" and inp.risk_score is None:
            return deny("R03", "system proposals must carry a risk score")
        if inp.duration_s > self.s.policy_max_duration_s:
            fired.append("R04"); reasons.append(f"duration capped to {self.s.policy_max_duration_s}s")
            max_duration = self.s.policy_max_duration_s
        if inp.asset_criticality is not None and inp.asset_criticality >= CRITICAL_ASSET:
            fired.append("R05"); reasons.append("critical asset: shorter cap and dfir authorisation")
            cap = self.s.policy_max_duration_critical_asset_s
            max_duration = cap if max_duration is None else min(max_duration, cap)
            roles.add("dfir")
        if inp.proposal.action_type == "isolate_host" and self.s.policy_require_dfir_for_isolate:
            fired.append("R06"); reasons.append("host isolation requires dfir authorisation")
            roles.add("dfir")
        if inp.open_actions_on_target >= 3:
            fired.append("R07"); reasons.append("repeated actions on the same target escalate to dfir")
            roles.add("dfir")
        if inp.enforcement_mode == "dry_run":
            fired.append("R08"); reasons.append("enforcement mode is dry_run: command is simulated, nothing is enforced")
            return PolicyDecisionV1(decision="allow_dry_run", rules_fired=fired, reasons=reasons, policy_version=self.s.policy_version,
                                    max_duration_s=max_duration, requires_roles=sorted(roles) or ["analyst"], evaluated_at=now)
        if (self.s.policy_auto_allow_enabled and inp.risk_score is not None and inp.risk_score >= self.s.policy_auto_allow_min_risk
                and not roles and not inp.target_is_internal):
            fired.append("R09"); reasons.append("risk above auto-allow threshold (unvalidated threshold)")
            return PolicyDecisionV1(decision="allow", rules_fired=fired, reasons=reasons, policy_version=self.s.policy_version,
                                    max_duration_s=max_duration, requires_roles=["analyst"], evaluated_at=now)
        fired.append("R10"); reasons.append("human authorisation required")
        return PolicyDecisionV1(decision="require_human", rules_fired=fired, reasons=reasons, policy_version=self.s.policy_version,
                                max_duration_s=max_duration, requires_roles=sorted(roles) or ["analyst"], evaluated_at=now)
