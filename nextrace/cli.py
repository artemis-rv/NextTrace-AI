"""Operational entry points: python -m nextrace.cli <command>."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone

from nextrace.config import get_settings
from nextrace.db.engine import transaction
from nextrace.db.partitions import ensure_partitions_ahead
from nextrace.services import audit, response, retention
from nextrace.services.security import RedactingFilter
from nextrace.storage.object_store import LocalObjectStore


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger().addFilter(RedactingFilter())
    p = argparse.ArgumentParser(prog="nextrace")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("config", help="print validated configuration without secrets")
    sub.add_parser("ensure-partitions", help="pre-create daily partitions ahead of time")
    sub.add_parser("retention", help="enforce retention (partitions, forecasts, pcap budget)")
    sub.add_parser("expire-actions", help="mark verified response actions past expiry as expired")
    v = sub.add_parser("verify", help="verify object integrity and the audit hash chain")
    v.add_argument("--limit", type=int, default=1000)
    args = p.parse_args(argv)

    settings = get_settings()
    if args.cmd == "config":
        print(json.dumps(settings.safe_dict(), indent=2, default=str))
        return 0
    store = LocalObjectStore(settings.object_store_root)
    now = datetime.now(timezone.utc)
    with transaction() as conn:
        if args.cmd == "ensure-partitions":
            print(json.dumps(ensure_partitions_ahead(conn, now, settings.partition_days_ahead), indent=2))
        elif args.cmd == "retention":
            print(json.dumps(retention.enforce(conn, store, settings, now).as_dict(), indent=2, default=str))
        elif args.cmd == "expire-actions":
            print(json.dumps([str(a) for a in response.expire_due(conn, now)]))
        elif args.cmd == "verify":
            out = retention.verify_objects(conn, store, args.limit)
            out["audit_first_bad_id"] = audit.verify_chain(conn)
            print(json.dumps(out))
            return 0 if out["failed"] == 0 and out["audit_first_bad_id"] is None else 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
