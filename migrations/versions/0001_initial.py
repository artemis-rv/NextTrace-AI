"""Initial NEXTRACE AI schema.

Revision ID: 0001
Revises:
Create Date: 2026-10-28
"""
from __future__ import annotations

from pathlib import Path

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

_SQL_DIR = Path(__file__).resolve().parent.parent / "sql"


def upgrade() -> None:
    op.execute((_SQL_DIR / "0001_initial.sql").read_text(encoding="utf-8"))


def downgrade() -> None:
    op.execute((_SQL_DIR / "0001_initial_down.sql").read_text(encoding="utf-8"))
