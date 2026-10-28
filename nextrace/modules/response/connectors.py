"""Firewall connectors (enforcement points). `execute` means the device accepted the command; `verify` is the
independent read-back that establishes enforcement. Both are separate on purpose (NIST SP 800-41: test that
rules work as expected, not only that they were entered).
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone

from nextrace.contracts.ops import ComponentHealthV1
from nextrace.contracts.response import ConnectorCommandV1, ConnectorResultV1
from nextrace.contracts.v1 import VerificationResultV1
from nextrace.core.health import component


def idempotency_key(action_id, operation: str) -> str:
    return hashlib.sha256(f"{action_id}:{operation}".encode()).hexdigest()


class DryRunConnector:
    """Accepts every well-formed command, enforces nothing, and says so in verification."""

    name = "dry-run"

    def __init__(self) -> None:
        self.commands: list[ConnectorCommandV1] = []

    def execute(self, command: ConnectorCommandV1) -> ConnectorResultV1:
        self.commands.append(command)
        return ConnectorResultV1(action_id=command.action_id, accepted=True, execution_ref=f"dry-run:{command.idempotency_key[:12]}",
                                 response={"simulated": True, "operation": command.operation}, dry_run=True, at=datetime.now(timezone.utc))

    def verify(self, command: ConnectorCommandV1) -> VerificationResultV1:
        return VerificationResultV1(method="manual", enforced=False, observed={"dry_run": True, "note": "nothing was installed"},
                                    checked_at=datetime.now(timezone.utc))

    def health(self) -> ComponentHealthV1:
        return component("connector.dry-run", "ok", "simulation only", commands=len(self.commands))


class InMemoryConnector:
    """Test double with controllable faults: `accept` (command acceptance) and `install` (whether the rule really lands)."""

    name = "memory"

    def __init__(self, accept: bool = True, install: bool = True):
        self.accept = accept
        self.install = install
        self.rules: dict[str, ConnectorCommandV1] = {}
        self.calls: list[str] = []

    def execute(self, command: ConnectorCommandV1) -> ConnectorResultV1:
        self.calls.append(command.operation)
        now = datetime.now(timezone.utc)
        if not self.accept:
            return ConnectorResultV1(action_id=command.action_id, accepted=False, dry_run=command.dry_run, at=now, error="device refused command")
        if command.dry_run:
            return ConnectorResultV1(action_id=command.action_id, accepted=True, execution_ref="dry", response={"simulated": True}, dry_run=True, at=now)
        if command.operation == "install":
            if self.install:
                self.rules[command.idempotency_key] = command
        else:
            self.rules.pop(idempotency_key(command.action_id, "install"), None)
        return ConnectorResultV1(action_id=command.action_id, accepted=True, execution_ref=f"mem:{command.idempotency_key[:8]}",
                                 response={"rules": len(self.rules)}, dry_run=False, at=now)

    def verify(self, command: ConnectorCommandV1) -> VerificationResultV1:
        present = idempotency_key(command.action_id, "install") in self.rules
        return VerificationResultV1(method="rule_readback", enforced=present, observed={"rule_present": present}, checked_at=datetime.now(timezone.utc))

    def health(self) -> ComponentHealthV1:
        return component("connector.memory", "ok", rules=len(self.rules))


_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


class NftablesConnector:  # pragma: no cover - requires a Linux host with nft and privileges; untested here
    """Template for a Linux nftables enforcement point.

    Commands are built as argument lists (no shell), every value is validated as an IP/CIDR or integer, and
    verification reads the ruleset back (`nft -j list set`) instead of trusting the exit code.
    TODO(INTEGRATION): run this in a staging host with a scratch table, add traffic-observation verification, and only
    then allow NEXTRACE_ENFORCEMENT_MODE=enforce with this connector.
    """

    name = "nftables"

    def __init__(self, table: str = "nextrace", set_name: str = "blocked", runner=None):
        if not (_NAME_RE.match(table) and _NAME_RE.match(set_name)):
            raise ValueError("invalid nft identifiers")
        self.table, self.set = table, set_name
        self.run = runner or self._subprocess

    @staticmethod
    def _subprocess(args: list[str]) -> tuple[int, str]:
        import subprocess

        p = subprocess.run(args, capture_output=True, text=True, timeout=10, check=False)
        return p.returncode, p.stdout

    @staticmethod
    def _addr(value: str) -> str:
        return str(ipaddress.ip_network(value, strict=False))

    def execute(self, command: ConnectorCommandV1) -> ConnectorResultV1:
        now = datetime.now(timezone.utc)
        if command.action_type not in ("block_ip",):
            return ConnectorResultV1(action_id=command.action_id, accepted=False, dry_run=command.dry_run, at=now, error="unsupported action for nftables template")
        addr = self._addr(command.target)
        verb = "add" if command.operation == "install" else "delete"
        args = ["nft", verb, "element", "inet", self.table, self.set, f"{{ {addr} }}"]
        if command.dry_run:
            return ConnectorResultV1(action_id=command.action_id, accepted=True, execution_ref="dry", response={"would_run": args}, dry_run=True, at=now)
        rc, out = self.run(args)
        return ConnectorResultV1(action_id=command.action_id, accepted=rc == 0, execution_ref=" ".join(args), response={"rc": rc, "out": out[:500]},
                                 dry_run=False, at=now, error=None if rc == 0 else f"nft exit {rc}")

    def verify(self, command: ConnectorCommandV1) -> VerificationResultV1:
        rc, out = self.run(["nft", "-j", "list", "set", "inet", self.table, self.set])
        present = rc == 0 and self._addr(command.target).split("/")[0] in out
        return VerificationResultV1(method="rule_readback", enforced=present, observed={"rc": rc, "present": present}, checked_at=datetime.now(timezone.utc))

    def health(self) -> ComponentHealthV1:
        return component("connector.nftables", "template", "untested template")
