"""Engine/session factory and reflected table registry.

The schema is defined once, in SQL migrations (migrations/sql). Python never redeclares columns;
tables are reflected on first use so there is a single source of truth.
"""
from __future__ import annotations

import contextlib
from typing import Iterator

from sqlalchemy import MetaData, Table, create_engine, text
from sqlalchemy.engine import Connection, Engine

from nextrace.config import get_settings

_engine: Engine | None = None
_metadata = MetaData()


def get_engine(url: str | None = None) -> Engine:
    global _engine
    if _engine is None:
        url = url or get_settings().database_url.get_secret_value()
        _engine = create_engine(url, pool_pre_ping=True, future=True)
    return _engine


def reset_engine() -> None:
    global _engine
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _metadata.clear()


def table(name: str) -> Table:
    """Reflected table (cached). Names are code constants, never user input."""
    if name not in _metadata.tables:
        Table(name, _metadata, autoload_with=get_engine())
    return _metadata.tables[name]


@contextlib.contextmanager
def transaction(actor_id: str | None = None) -> Iterator[Connection]:
    """A transaction with the acting user bound as a session setting for DB-side triggers."""
    with get_engine().begin() as conn:
        if actor_id is not None:
            conn.execute(text("SELECT set_config('nextrace.actor_id', :a, true)"), {"a": str(actor_id)})
        yield conn
