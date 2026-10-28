"""Process entry points: python -m nextrace.workers <command>.

  bootstrap   create a sensor and an admin user, print the API key once
  replay      run the live pipeline over a pcap file (controlled fixture) as a given sensor
  api         serve the HTTP API (uvicorn)
  forensics   run queued forensic jobs (loop)
  maintenance delayed correlation matching + response expiry/removal (run every minute)
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from sqlalchemy import text

from nextrace.config import get_settings
from nextrace.core.logging import configure_logging
from nextrace.services.security import new_api_key


def _ctx():
    from nextrace.core.composition import build_context

    return build_context(get_settings())


def cmd_bootstrap(args: argparse.Namespace) -> int:
    from nextrace.db.engine import transaction

    with transaction() as conn:
        sensor_id = conn.execute(text("INSERT INTO sensors (name, kind) VALUES (:n, :k) ON CONFLICT (name) DO UPDATE SET kind = EXCLUDED.kind RETURNING sensor_id"),
                                 {"n": args.sensor_name, "k": args.sensor_kind}).scalar_one()
        raw, digest = new_api_key()
        user_id = conn.execute(text("INSERT INTO users (username, role, api_key_hash) VALUES (:u, :r, :h) "
                                    "ON CONFLICT (username) DO UPDATE SET api_key_hash = EXCLUDED.api_key_hash RETURNING user_id"),
                               {"u": args.username, "r": args.role, "h": digest}).scalar_one()
    print(json.dumps({"sensor_id": str(sensor_id), "user_id": str(user_id), "api_key": raw, "note": "store the key now; only its hash is kept"}))
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    from nextrace.core.pipeline import Pipeline
    from nextrace.modules.capture.sources import PcapReplaySource

    ctx = _ctx()
    with ctx.conn_factory() as conn:
        sensor_id = conn.execute(text("SELECT sensor_id FROM sensors WHERE name = :n"), {"n": args.sensor_name}).scalar()
    if sensor_id is None:
        print("unknown sensor; run bootstrap first", file=sys.stderr)
        return 2
    src = PcapReplaySource(Path(args.pcap), UUID(str(sensor_id)), batch_flows=args.batch_flows, realtime=args.realtime)
    pipe = Pipeline(ctx, persist_flows=not args.no_persist_flows)
    stats = asyncio.run(pipe.run(src))
    out = stats.as_dict()
    out["capture_health"] = src.health().model_dump(mode="json")
    out["model_availability"] = ctx.model_availability
    print(json.dumps(out, indent=2, default=str))
    return 0


def cmd_api(args: argparse.Namespace) -> int:
    import uvicorn

    from nextrace.api.app import create_app

    uvicorn.run(create_app(_ctx()), host=args.host, port=args.port, log_config=None)
    return 0


def cmd_forensics(args: argparse.Namespace) -> int:
    ctx = _ctx()
    while True:
        st = ctx.forensics.run_next()
        if st is not None:
            print(st.model_dump_json())
        elif args.once:
            return 0
        else:
            time.sleep(args.poll_s)


def cmd_maintenance(args: argparse.Namespace) -> int:
    from nextrace.core.pipeline import Pipeline

    ctx = _ctx()
    pipe = Pipeline(ctx)
    while True:
        now = datetime.now(timezone.utc)
        with ctx.conn_factory() as conn:
            late = pipe.late_match(conn, now)
            due = ctx.response.run_due(conn, now)
        print(json.dumps({"at": now.isoformat(), "late_events": late, **due}, default=str))
        if args.once:
            return 0
        time.sleep(args.interval_s)


def main(argv: list[str] | None = None) -> int:
    s = get_settings()
    configure_logging(s.log_level, s.log_json)
    p = argparse.ArgumentParser(prog="nextrace.workers")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bootstrap"); b.add_argument("--sensor-name", required=True); b.add_argument("--sensor-kind", default="pcap_upload")
    b.add_argument("--username", required=True); b.add_argument("--role", default="admin"); b.set_defaults(fn=cmd_bootstrap)
    r = sub.add_parser("replay"); r.add_argument("--pcap", required=True); r.add_argument("--sensor-name", required=True)
    r.add_argument("--batch-flows", type=int, default=500); r.add_argument("--realtime", action="store_true"); r.add_argument("--no-persist-flows", action="store_true")
    r.set_defaults(fn=cmd_replay)
    a = sub.add_parser("api"); a.add_argument("--host", default="127.0.0.1"); a.add_argument("--port", type=int, default=8000); a.set_defaults(fn=cmd_api)
    f = sub.add_parser("forensics"); f.add_argument("--once", action="store_true"); f.add_argument("--poll-s", type=float, default=2.0); f.set_defaults(fn=cmd_forensics)
    m = sub.add_parser("maintenance"); m.add_argument("--once", action="store_true"); m.add_argument("--interval-s", type=float, default=60.0); m.set_defaults(fn=cmd_maintenance)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
