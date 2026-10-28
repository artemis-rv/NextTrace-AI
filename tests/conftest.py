"""Test fixtures. Tests need a reachable PostgreSQL 18 (NEXTRACE_TEST_DATABASE_URL); Redis is faked.

The schema is rebuilt once per session through the real Alembic migration (downgrade + upgrade),
so the migration itself is exercised. Each test runs inside a transaction that is rolled back.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

TEST_DB = os.environ.get("NEXTRACE_TEST_DATABASE_URL", "postgresql+psycopg2://postgres:postgres@127.0.0.1:5432/nextrace_test")
os.environ["NEXTRACE_DATABASE_URL"] = TEST_DB
os.environ.setdefault("NEXTRACE_PSEUDONYM_PEPPER", "unit-test-pepper-0123456789abcdef0123456789")
os.environ.setdefault("NEXTRACE_REDIS_URL", "redis://127.0.0.1:6379/15")

import fakeredis  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import text  # noqa: E402

from nextrace.config import get_settings  # noqa: E402
from nextrace.db.engine import get_engine, reset_engine  # noqa: E402
from nextrace.services.states import WINDOW_FEATURES_V1, register_feature_schema  # noqa: E402
from nextrace.storage.cache import StateCache  # noqa: E402
from nextrace.storage.object_store import LocalObjectStore  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime.now(timezone.utc).replace(microsecond=0)


@pytest.fixture(scope="session")
def engine():
    reset_engine()
    try:
        eng = get_engine(TEST_DB)
        with eng.connect() as c:
            c.execute(text("SELECT 1"))
    except Exception as e:  # pragma: no cover
        pytest.skip(f"PostgreSQL test database not reachable: {e}")
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", TEST_DB)
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    yield eng
    eng.dispose()


@pytest.fixture
def conn(engine):
    with engine.connect() as c:
        tx = c.begin()
        try:
            yield c
        finally:
            tx.rollback()


@pytest.fixture
def store(tmp_path) -> LocalObjectStore:
    return LocalObjectStore(tmp_path / "objects")


@pytest.fixture
def cache() -> StateCache:
    return StateCache(fakeredis.FakeRedis(), max_states=5, ttl_seconds=120)


@pytest.fixture
def settings():
    return get_settings()


@pytest.fixture
def seed(conn):
    """A sensor, one user per role, and the window feature schema."""
    sensor_id = conn.execute(text(
        "INSERT INTO sensors (name, kind) VALUES (:n, 'zeek') RETURNING sensor_id"), {"n": f"sensor-{uuid.uuid4().hex[:8]}"}).scalar_one()
    users = {}
    for role in ("viewer", "analyst", "dfir", "admin", "service"):
        users[role] = conn.execute(text(
            "INSERT INTO users (username, role) VALUES (:u, :r) RETURNING user_id"),
            {"u": f"{role}-{uuid.uuid4().hex[:6]}", "r": role}).scalar_one()
    users["analyst2"] = conn.execute(text(
        "INSERT INTO users (username, role) VALUES (:u, 'analyst') RETURNING user_id"), {"u": f"analyst2-{uuid.uuid4().hex[:6]}"}).scalar_one()
    fs = register_feature_schema(conn, "window", 1, WINDOW_FEATURES_V1)
    model = conn.execute(text(
        "INSERT INTO model_versions (name, kind, version, feature_schema_id) VALUES ('lstm', 'lstm_attention', :v, :fs) RETURNING model_version_id"),
        {"v": uuid.uuid4().hex[:8], "fs": fs}).scalar_one()
    return {"sensor_id": sensor_id, "users": users, "feature_schema_id": fs, "model_version_id": model}


def make_flows(n: int, start: datetime, step_ms: int = 100, hosts: int = 6) -> list[dict]:
    """Deterministic synthetic flows: a small set of hosts talking over a few ports."""
    out = []
    for i in range(n):
        ts = start + timedelta(milliseconds=i * step_ms)
        src = f"10.0.0.{(i % hosts) + 1}"
        dst = f"10.0.1.{((i * 7) % hosts) + 1}"
        out.append({
            "ts_start": ts.isoformat(), "ts_end": (ts + timedelta(milliseconds=50)).isoformat(),
            "src_ip": src, "src_port": 40000 + (i % 1000), "dst_ip": dst, "dst_port": [22, 80, 443, 53][i % 4],
            "proto": 17 if i % 4 == 3 else 6, "service": ["ssh", "http", "ssl", "dns"][i % 4], "duration_ms": 50,
            "orig_bytes": 100 + i, "resp_bytes": 200 + i, "orig_pkts": 3, "resp_pkts": 4,
            "conn_state": "S0" if i % 10 == 0 else "SF", "history": "ShADadfF",
        })
    return out


# ---- backend fixtures (added with the backend layer) --------------------------------------------
@pytest.fixture
def ctx(conn, store, cache):
    """Composition root bound to the test transaction: every 'transaction' is a savepoint on `conn`."""
    from nextrace.core.composition import build_context, savepoint_factory

    settings = get_settings().model_copy(update={"heuristic_min_distinct_ports": 30, "heuristic_min_flows": 10, "sequence_length": 6,
                                                "correlation_window_s": 600, "correlation_grace_s": 900})
    c = build_context(settings, conn_factory=lambda: savepoint_factory(conn), store=store, cache=cache)
    c.single_connection = True
    return c
