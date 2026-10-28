"""Daily range partitions for high-volume telemetry tables.

Retention is enforced by dropping whole partitions (cheap, no VACUUM debt) rather than DELETE.
Partition names are generated from dates only; nothing here is derived from user input.
"""
from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.engine import Connection

PARTITIONED_TABLES: dict[str, str] = {
    "flows": "ts_start",
    "temporal_states": "window_start",
    "state_edges": "window_start",
}
_NAME_RE = re.compile(r"^(flows|temporal_states|state_edges)_p(\d{8})$")


def partition_name(table: str, day: date) -> str:
    if table not in PARTITIONED_TABLES:
        raise ValueError(f"not a partitioned table: {table}")
    return f"{table}_p{day:%Y%m%d}"


def _day(ts: datetime) -> date:
    return ts.astimezone(timezone.utc).date()


def ensure_partitions(conn: Connection, table: str, start: datetime, end: datetime) -> list[str]:
    """Create daily partitions covering [start, end]. Idempotent."""
    created: list[str] = []
    day = _day(start)
    last = _day(end)
    while day <= last:
        name = partition_name(table, day)
        nxt = day + timedelta(days=1)
        conn.execute(text(
            f'CREATE TABLE IF NOT EXISTS "{name}" PARTITION OF "{table}" '
            f"FOR VALUES FROM ('{day.isoformat()} 00:00:00+00') TO ('{nxt.isoformat()} 00:00:00+00')"
        ))
        created.append(name)
        day = nxt
    return created


def ensure_partitions_ahead(conn: Connection, now: datetime, days_ahead: int) -> dict[str, list[str]]:
    """Keep partitions pre-created for today and the next N days, for every partitioned table."""
    end = now + timedelta(days=days_ahead)
    return {t: ensure_partitions(conn, t, now, end) for t in PARTITIONED_TABLES}


def list_partitions(conn: Connection, table: str) -> list[tuple[str, date]]:
    """(partition name, lower bound day) for every attached partition, oldest first."""
    rows = conn.execute(text(
        "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid "
        "JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = :t"
    ), {"t": table}).scalars().all()
    out: list[tuple[str, date]] = []
    for name in rows:
        m = _NAME_RE.match(name)
        if m and m.group(1) == table:
            out.append((name, datetime.strptime(m.group(2), "%Y%m%d").date()))
    return sorted(out, key=lambda x: x[1])


def drop_partition(conn: Connection, name: str) -> None:
    """Detach, then drop. Detaching first lets PostgreSQL verify that no row in a referencing
    partitioned table (state_edges -> temporal_states) still points at the partition."""
    m = _NAME_RE.match(name)
    if not m:
        raise ValueError(f"refusing to drop non-partition table {name!r}")
    conn.execute(text(f'ALTER TABLE "{m.group(1)}" DETACH PARTITION "{name}"'))
    conn.execute(text(f'DROP TABLE "{name}"'))
