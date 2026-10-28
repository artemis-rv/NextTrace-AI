"""API: authentication, role and object-level authorization, injection resistance, limits, error hygiene."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from nextrace.api.app import create_app
from tests.backend_helpers import make_sensor, make_user


@pytest.fixture
def api(conn, ctx):
    ctx.settings = ctx.settings.model_copy(update={"api_rate_limit_per_minute": 1000})
    app = create_app(ctx)
    users = {r: make_user(conn, r) for r in ("viewer", "analyst", "dfir", "admin", "service")}
    users["analyst2"] = make_user(conn, "analyst")
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client, users, make_sensor(conn)


def _h(key):
    return {"x-api-key": key}


def test_authentication_and_health(api):
    client, users, sid = api
    assert client.get("/health").json().keys() == {"status", "version"}            # unauthenticated: status only
    assert client.get(f"/v1/dashboard/{sid}").status_code == 401
    assert client.get(f"/v1/dashboard/{sid}", headers=_h("wrong-key")).status_code == 401
    assert client.get(f"/v1/dashboard/{sid}", headers=_h("x" * 300)).status_code == 401
    r = client.get(f"/v1/dashboard/{sid}", headers=_h(users["viewer"][1]))
    assert r.status_code == 200 and r.json()["open_alerts"] == 0 and r.headers["x-request-id"]
    full = client.get("/health", headers=_h(users["viewer"][1])).json()
    assert "research_required" in full and full["enforcement_mode"] == "dry_run" and full["model_availability"]["detector"] == "heuristic_baseline"


def test_role_and_object_level_authorization(api, conn):
    client, users, sid = api
    body = {"case_number": "CASE-API1", "title": "t", "severity": "high"}
    assert client.post("/v1/investigations", json=body, headers=_h(users["viewer"][1])).status_code == 403
    r = client.post("/v1/investigations", json=body, headers=_h(users["analyst"][1]))
    assert r.status_code == 201
    cid = r.json()["investigation_id"]
    assert client.get(f"/v1/investigations/{cid}", headers=_h(users["analyst"][1])).status_code == 200      # opener
    assert client.get(f"/v1/investigations/{cid}", headers=_h(users["analyst2"][1])).status_code == 403     # BOLA: another analyst
    assert client.get(f"/v1/investigations/{cid}", headers=_h(users["admin"][1])).status_code == 200
    assert client.get(f"/v1/investigations/{uuid.uuid4()}", headers=_h(users["admin"][1])).status_code == 404
    # grants need dfir/admin; viewer cannot authorize response actions; audit is admin-only
    g = {"user_id": str(users["analyst2"][0]), "access_level": "metadata", "expires_in_hours": 24, "reason": "second analyst"}
    assert client.post(f"/v1/investigations/{cid}/grants", json=g, headers=_h(users["analyst"][1])).status_code == 403
    assert client.post(f"/v1/investigations/{cid}/grants", json=g, headers=_h(users["dfir"][1])).status_code == 201
    assert client.get(f"/v1/investigations/{cid}", headers=_h(users["analyst2"][1])).status_code == 200
    assert client.get("/v1/audit", headers=_h(users["dfir"][1])).status_code == 403
    a = client.get("/v1/audit", headers=_h(users["admin"][1]))
    assert a.status_code == 200 and a.json()["chain_intact"] is True
    # an update signed as someone else is refused
    upd = {"investigation_id": cid, "actor_id": str(users["admin"][0]), "action": "add_note", "note": "hi"}
    assert client.post(f"/v1/investigations/{cid}/updates", json=upd, headers=_h(users["analyst"][1])).status_code == 403
    upd["actor_id"] = str(users["analyst"][0])
    assert client.post(f"/v1/investigations/{cid}/updates", json=upd, headers=_h(users["analyst"][1])).status_code == 204


def test_injection_attempts_are_rejected_by_validation(api, conn):
    client, users, sid = api
    h = _h(users["admin"][1])
    for bad in ["' OR 1=1 --", "1;DROP TABLE alerts", "1 UNION SELECT api_key_hash FROM users", "%27%20OR%201%3D1"]:
        assert client.get(f"/v1/dashboard/{bad}", headers=h).status_code == 422
        assert client.get(f"/v1/alerts?status={bad}", headers=h).status_code == 422
    assert client.get("/v1/alerts?limit=100000", headers=h).status_code == 422
    r = client.post("/v1/investigations", json={"case_number": "x'); DROP TABLE investigations;--", "title": "t", "severity": "high"}, headers=h)
    assert r.status_code == 422
    assert conn.execute(text("SELECT count(*) FROM alerts")).scalar_one() >= 0  # tables still here
    bad_prop = {"action_type": "block_ip", "target": "not-an-ip", "enforcement_point": "dry-run", "justification": "long enough justification",
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}
    assert client.post("/v1/response-actions", json=bad_prop, headers=h).status_code == 422
    assert client.post("/v1/response-actions", json={**bad_prop, "target": "203.0.113.4", "extra": 1}, headers=h).status_code == 422  # extra=forbid


def test_response_action_flow_over_api(api):
    client, users, sid = api
    prop = {"action_type": "block_ip", "target": "203.0.113.4", "enforcement_point": "dry-run", "justification": "analyst saw a scan",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}
    assert client.post("/v1/response-actions", json=prop, headers=_h(users["viewer"][1])).status_code == 403
    r = client.post("/v1/response-actions", json=prop, headers=_h(users["analyst"][1]))
    assert r.status_code == 201 and r.json()["decision"]["decision"] == "allow_dry_run"
    aid = r.json()["action_id"]
    assert client.post(f"/v1/response-actions/{aid}/authorize", headers=_h(users["analyst"][1])).status_code == 403   # own proposal
    assert client.post(f"/v1/response-actions/{aid}/authorize", headers=_h(users["analyst2"][1])).status_code == 200
    assert client.post(f"/v1/response-actions/{aid}/execute", headers=_h(users["analyst2"][1])).status_code == 403   # execution needs dfir/admin/service
    ex = client.post(f"/v1/response-actions/{aid}/execute", headers=_h(users["dfir"][1]))
    assert ex.status_code == 200 and ex.json()["dry_run"] and ex.json()["enforced"] is False
    v = client.get(f"/v1/response-actions/{aid}", headers=_h(users["viewer"][1])).json()
    assert v["action"]["status"] == "executed" and v["action"]["enforced"] is False and len(v["history"]) == 4
    assert client.get("/v1/response-actions?status=executed", headers=_h(users["viewer"][1])).json()[0]["action_id"] == aid


def test_limits_and_error_hygiene(api, conn, ctx):
    client, users, sid = api
    big = {"x": "a" * (ctx.settings.api_max_body_bytes + 10)}
    r = client.post("/v1/investigations", json=big, headers=_h(users["admin"][1]))
    assert r.status_code == 413 and "Traceback" not in r.text
    assert client.get(f"/v1/forecasts/{sid}/current", headers=_h(users["admin"][1])).status_code == 404
    r = client.get(f"/v1/dashboard/{sid}", headers=_h(users["admin"][1]))
    assert r.status_code == 200
    # rate limit: a fresh limiter with a tiny budget
    from nextrace.api.app import create_app as mk
    ctx2 = ctx
    ctx2.settings = ctx.settings.model_copy(update={"api_rate_limit_per_minute": 2})
    from fastapi.testclient import TestClient
    with TestClient(mk(ctx2)) as c2:
        codes = [c2.get("/health").status_code for _ in range(4)]
    assert codes[:2] == [200, 200] and 429 in codes[2:]
    # ingestion endpoint is service-only and validates batches
    bad = {"sensor_id": str(sid), "batch_seq": 0, "produced_at": datetime.now(timezone.utc).isoformat(), "source": "csv", "flows": [{"src_ip": "x"}]}
    good = {**bad, "flows": []}
    assert client.post("/v1/ingest/flows", json=good, headers=_h(users["analyst"][1])).status_code == 403
    assert client.post("/v1/ingest/flows", json=bad, headers=_h(users["service"][1])).status_code == 422
    r = client.post("/v1/ingest/flows", json=good, headers=_h(users["service"][1]))
    assert r.status_code == 202 and r.json()["states_closed"] == 0
