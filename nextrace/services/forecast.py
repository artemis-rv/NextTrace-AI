"""Immutable forecast history with a mutable 'current' pointer per sensor."""
from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from nextrace.contracts.v1 import ForecastResultV1


def input_fingerprint(result: ForecastResultV1) -> bytes:
    payload = {"states": sorted(str(s) for s in result.input_state_ids), "model": str(result.model_version_id),
               "progression_model": str(result.progression_model_version_id), "horizon": result.horizon_seconds}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).digest()


def record_run(conn: Connection, result: ForecastResultV1) -> UUID:
    """Persist a run and everything it produced in one transaction. Completed runs become current."""
    run_id = conn.execute(text(
        "INSERT INTO forecast_runs (sensor_id, model_version_id, progression_model_version_id, input_state_ids, "
        "input_window_start, input_window_end, input_sha256, horizon_seconds, started_at, completed_at, status, error) "
        "VALUES (:sensor, :model, :pmodel, CAST(:states AS uuid[]), :ws, :we, :h, :hz, :st, :ct, :status, :err) RETURNING run_id"),
        {"sensor": result.sensor_id, "model": result.model_version_id, "pmodel": result.progression_model_version_id,
         "states": [str(s) for s in result.input_state_ids], "ws": result.input_window_start, "we": result.input_window_end,
         "h": input_fingerprint(result), "hz": result.horizon_seconds, "st": result.started_at, "ct": result.completed_at,
         "status": result.status, "err": result.error}).scalar_one()

    prediction_ids: list[UUID] = []
    for p in result.predictions:
        pid = conn.execute(text(
            "INSERT INTO predictions (run_id, state_id, window_start, is_malicious, probability, category, attack_stage, technique_ids) "
            "VALUES (:r, :s, :w, :m, :p, :c, :a, CAST(:t AS text[])) RETURNING prediction_id"),
            {"r": run_id, "s": p.state_id, "w": p.window_start, "m": p.is_malicious, "p": p.probability,
             "c": p.category, "a": p.attack_stage, "t": p.technique_ids}).scalar_one()
        prediction_ids.append(pid)

    if result.progression:
        conn.execute(text(
            "INSERT INTO progression_forecasts (run_id, step, predicted_technique_id, predicted_tactic, target_host_id, probability, expected_within_s) "
            "VALUES (:r, :step, :tid, :tac, :host, :p, :exp)"),
            [{"r": run_id, "step": s.step, "tid": s.predicted_technique_id, "tac": s.predicted_tactic, "host": s.target_host_id,
              "p": s.probability, "exp": s.expected_within_s} for s in result.progression])

    for e in result.explanations:
        conn.execute(text(
            "INSERT INTO explanations (run_id, prediction_id, kind, model_version_id, content, artifact_sha256, prompt_sha256) "
            "VALUES (:r, :pid, :k, :m, CAST(:c AS jsonb), :art, :prompt)"),
            {"r": run_id, "pid": prediction_ids[e.prediction_index] if e.prediction_index is not None else None,
             "k": e.kind, "m": e.model_version_id, "c": json.dumps(e.content, default=str),
             "art": bytes.fromhex(e.artifact_sha256) if e.artifact_sha256 else None,
             "prompt": bytes.fromhex(e.prompt_sha256) if e.prompt_sha256 else None})

    if result.status == "completed":
        conn.execute(text(
            "INSERT INTO forecast_current (sensor_id, run_id) VALUES (:s, :r) "
            "ON CONFLICT (sensor_id) DO UPDATE SET run_id = EXCLUDED.run_id, updated_at = now()"),
            {"s": result.sensor_id, "r": run_id})
    return run_id


def current_run(conn: Connection, sensor_id: UUID) -> dict[str, Any] | None:
    row = conn.execute(text(
        "SELECT r.run_id, r.model_version_id, r.input_window_start, r.input_window_end, r.horizon_seconds, r.completed_at, "
        "c.updated_at FROM forecast_current c JOIN forecast_runs r USING (run_id) WHERE c.sensor_id = :s"),
        {"s": sensor_id}).mappings().first()
    if row is None:
        return None
    out = dict(row)
    out["predictions"] = [dict(p) for p in conn.execute(text(
        "SELECT prediction_id, state_id, window_start, is_malicious, probability, category, attack_stage, technique_ids "
        "FROM predictions WHERE run_id = :r ORDER BY window_start"), {"r": row["run_id"]}).mappings().all()]
    out["progression"] = [dict(p) for p in conn.execute(text(
        "SELECT step, predicted_technique_id, predicted_tactic, target_host_id, probability, expected_within_s "
        "FROM progression_forecasts WHERE run_id = :r AND simulation_id IS NULL ORDER BY step"), {"r": row["run_id"]}).mappings().all()]
    return out


def run_history(conn: Connection, sensor_id: UUID, limit: int = 50) -> list[dict[str, Any]]:
    rows = conn.execute(text(
        "SELECT run_id, model_version_id, status, input_window_start, input_window_end, completed_at, encode(input_sha256, 'hex') AS input_sha256 "
        "FROM forecast_runs WHERE sensor_id = :s ORDER BY run_id DESC LIMIT :n"), {"s": sensor_id, "n": limit}).mappings().all()
    return [dict(r) for r in rows]
