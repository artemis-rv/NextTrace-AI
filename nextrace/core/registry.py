"""Model and feature-schema registry (central). Model versions are rows; artifacts are objects in the store."""
from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from nextrace.contracts.models import ModelVersionV1

_DB_KINDS = {"lstm_attention": "lstm_attention", "gnn": "gnn", "llm": "llm"}  # everything else is stored as 'other'


def ensure_model_version(conn: Connection, mv: ModelVersionV1) -> UUID:
    """Idempotent on (name, version). Returns the row id and keeps hyperparameters/metrics in sync."""
    kind = _DB_KINDS.get(mv.kind, "other")
    hp = dict(mv.hyperparameters)
    hp.setdefault("kind_detail", mv.kind)
    metrics = {"evaluation": mv.evaluation, "calibration": mv.calibration, "code_ref": mv.code_ref}
    return conn.execute(text(
        "INSERT INTO model_versions (name, kind, version, artifact_sha256, feature_schema_id, training_dataset_id, hyperparameters, metrics, status) "
        "VALUES (:n, :k, :v, :a, :fs, :ds, CAST(:hp AS jsonb), CAST(:m AS jsonb), :st) "
        "ON CONFLICT (name, version) DO UPDATE SET hyperparameters = EXCLUDED.hyperparameters, metrics = EXCLUDED.metrics RETURNING model_version_id"),
        {"n": mv.name, "k": kind, "v": mv.version, "a": bytes.fromhex(mv.artifact_sha256) if mv.artifact_sha256 else None,
         "fs": mv.feature_schema_id, "ds": mv.training_dataset_id, "hp": json.dumps(hp, default=str), "m": json.dumps(metrics, default=str),
         "st": mv.status}).scalar_one()


def list_models(conn: Connection) -> list[dict[str, Any]]:
    rows = conn.execute(text(
        "SELECT model_version_id, name, kind, version, encode(artifact_sha256,'hex') AS artifact_sha256, feature_schema_id, status, "
        "hyperparameters, metrics, created_at FROM model_versions ORDER BY created_at DESC")).mappings().all()
    return [json.loads(json.dumps(dict(r), default=str)) for r in rows]


def set_status(conn: Connection, model_version_id: UUID, status: str) -> None:
    if status not in ("candidate", "active", "retired"):
        raise ValueError("bad status")
    conn.execute(text("UPDATE model_versions SET status = :s WHERE model_version_id = :m"), {"s": status, "m": model_version_id})
