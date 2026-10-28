"""Local benchmark: ingestion throughput (COPY vs multi-row INSERT), state construction, host lookup
latency, and on-disk growth per flow. Writes bench/results/<timestamp>.json. Numbers are for the
machine it runs on and say nothing about packet capture (no capture path exists in this repository).

Usage: NEXTRACE_DATABASE_URL=... NEXTRACE_PSEUDONYM_PEPPER=... python bench/benchmark.py --flows 200000
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import text  # noqa: E402

from nextrace.contracts.v1 import FlowRecordV1  # noqa: E402
from nextrace.db.engine import get_engine  # noqa: E402
from nextrace.db.partitions import ensure_partitions  # noqa: E402
from nextrace.services.ingest import create_batch, ingest_flows, upsert_hosts  # noqa: E402
from nextrace.services.states import WINDOW_FEATURES_V1, build_states, register_feature_schema  # noqa: E402


def synth(n: int, start: datetime, src_hosts: int = 2000, dst_hosts: int = 500) -> list[dict]:
    """Enterprise-like shape: a few thousand internal clients talking to a few hundred servers."""
    out = []
    for i in range(n):
        ts = start + timedelta(microseconds=i * 500)  # 2000 flows/s of simulated traffic
        s = (i * 7919) % src_hosts
        d = (i * 104729) % dst_hosts
        out.append({"ts_start": ts.isoformat(), "src_ip": f"10.{s // 256}.{s % 256}.{(i % 3) + 1}",
                    "dst_ip": f"172.16.{d // 256}.{d % 256}", "src_port": 1024 + i % 60000,
                    "dst_port": [22, 53, 80, 443, 445][i % 5], "proto": 17 if i % 5 == 1 else 6,
                    "orig_bytes": i % 1500, "resp_bytes": (i * 3) % 4000, "orig_pkts": 1 + i % 9, "resp_pkts": 1 + i % 7,
                    "conn_state": "SF" if i % 13 else "S0", "duration_ms": i % 3000})
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=100_000)
    ap.add_argument("--insert-sample", type=int, default=20_000)
    args = ap.parse_args()
    eng = get_engine()
    start = datetime.now(timezone.utc) - timedelta(hours=1)
    res: dict = {"machine": platform.platform(), "python": platform.python_version(), "flows": args.flows}

    with eng.begin() as c:
        sensor = c.execute(text("INSERT INTO sensors (name, kind) VALUES (:n, 'zeek') RETURNING sensor_id"), {"n": f"bench-{int(time.time())}"}).scalar_one()
        fs = register_feature_schema(c, "window", 1, WINDOW_FEATURES_V1)
        c.execute(text("SELECT pg_total_relation_size('flows')"))
        size0 = sum(c.execute(text("SELECT pg_total_relation_size(inhrelid) FROM pg_inherits WHERE inhparent = 'flows'::regclass")).scalars())
        res["pg_version"] = c.execute(text("SHOW server_version")).scalar()

    records = synth(args.flows, start)
    t = time.perf_counter()
    validated = [FlowRecordV1.model_validate(r) for r in records]
    res["validation_s"] = round(time.perf_counter() - t, 3)

    with eng.begin() as c:
        batch = create_batch(c, sensor, "api")
        t = time.perf_counter()
        r = ingest_flows(c, sensor, batch, validated)
        res["ingest_total_s"] = round(time.perf_counter() - t, 3)
        res["ingest_phases_s"] = r.timings_s
        res["copy_flows_per_s"] = round(r.accepted / r.timings_s["copy"])
        res["ingest_flows_per_s_end_to_end"] = round(r.accepted / res["ingest_total_s"])

    # multi-row INSERT comparison on a sample, same validation path
    sample = validated[: args.insert_sample]
    with eng.begin() as c:
        batch2 = create_batch(c, sensor, "api")
        ensure_partitions(c, "flows", start, start + timedelta(hours=1))
        upsert_hosts(c, {str(f.src_ip) for f in sample} | {str(f.dst_ip) for f in sample}, start)
        rows = [{"t": f.ts_start, "s": sensor, "b": batch2, "si": str(f.src_ip), "sp": f.src_port, "di": str(f.dst_ip), "dp": f.dst_port,
                 "p": f.proto, "ob": f.orig_bytes, "rb": f.resp_bytes, "op": f.orig_pkts, "rp": f.resp_pkts, "cs": f.conn_state, "d": f.duration_ms}
                for f in sample]
        t = time.perf_counter()
        c.execute(text("INSERT INTO flows (ts_start, sensor_id, batch_id, src_ip, src_port, dst_ip, dst_port, proto, orig_bytes, resp_bytes, "
                       "orig_pkts, resp_pkts, conn_state, duration_ms) VALUES (:t, :s, :b, CAST(:si AS inet), :sp, CAST(:di AS inet), :dp, :p, "
                       ":ob, :rb, :op, :rp, :cs, :d)"), rows)
        res["executemany_insert_s"] = round(time.perf_counter() - t, 3)
        res["executemany_flows_per_s"] = round(len(sample) / res["executemany_insert_s"])

    with eng.begin() as c:
        t = time.perf_counter()
        states = build_states(c, sensor, start, start + timedelta(hours=1), 10, fs)
        res["state_build_s"] = round(time.perf_counter() - t, 3)
        res["states_built"] = len(states)
        res["edges_built"] = c.execute(text("SELECT count(*) FROM state_edges WHERE state_id = ANY(CAST(:ids AS uuid[]))"),
                                       {"ids": [str(s.state_id) for s in states]}).scalar_one()
        c.execute(text("ANALYZE flows"))
        lat = []
        for i in range(50):
            s = (i * 7919) % 2000
            ip = f"10.{s // 256}.{s % 256}.{(i % 3) + 1}"
            t = time.perf_counter()
            c.execute(text("SELECT count(*) FROM flows WHERE (src_ip = CAST(:ip AS inet) OR dst_ip = CAST(:ip AS inet)) AND ts_start >= :a AND ts_start < :b"),
                      {"ip": ip, "a": start, "b": start + timedelta(hours=1)}).scalar_one()
            lat.append((time.perf_counter() - t) * 1000)
        res["host_lookup_ms_p50"] = round(statistics.median(lat), 2)
        res["host_lookup_ms_p95"] = round(sorted(lat)[int(len(lat) * 0.95) - 1], 2)
        t = time.perf_counter()
        c.execute(text("SELECT count(*) FROM flows WHERE ts_start >= :a AND ts_start < :b"), {"a": start, "b": start + timedelta(minutes=5)}).scalar_one()
        res["range_count_5min_ms"] = round((time.perf_counter() - t) * 1000, 2)
        size1 = sum(c.execute(text("SELECT pg_total_relation_size(inhrelid) FROM pg_inherits WHERE inhparent = 'flows'::regclass")).scalars())
        total_rows = args.flows + len(sample)
        res["flows_bytes_per_row_incl_indexes"] = round((size1 - size0) / total_rows, 1)
        res["flows_table_mb"] = round((size1 - size0) / 1e6, 1)
        res["states_mb"] = round(sum(c.execute(text("SELECT pg_total_relation_size(inhrelid) FROM pg_inherits WHERE inhparent = 'temporal_states'::regclass")).scalars()) / 1e6, 2)
        res["edges_mb"] = round(sum(c.execute(text("SELECT pg_total_relation_size(inhrelid) FROM pg_inherits WHERE inhparent = 'state_edges'::regclass")).scalars()) / 1e6, 2)

    out = Path(__file__).resolve().parent / "results"
    out.mkdir(exist_ok=True)
    path = out / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"
    path.write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=2))
    print(f"written {path}")


if __name__ == "__main__":
    main()
