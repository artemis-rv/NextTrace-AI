"""FastAPI application. Security posture (OWASP API Security Top 10:2023):
API1/API5 object- and function-level authorization through services.investigations and role checks; API2 API keys
compared as digests; API4 rate limit + body size cap + bounded queries; API7 no user-supplied URLs are fetched;
API8 generic error bodies, no stack traces; every mutation audited.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import Depends, FastAPI, File, Form, Header, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import text

from nextrace.contracts.errors import ContractViolation, Forbidden, NextraceError, NotFound, PayloadTooLarge, RateLimited
from nextrace.contracts.findings import AnalystFeedbackV1, DashboardSnapshotV1, InvestigationUpdateV1
from nextrace.contracts.forensics import ForensicJobRequestV1
from nextrace.contracts.models import SimulationRequestV1
from nextrace.contracts.observations import FlowBatchV1
from nextrace.contracts.ops import HealthReportV1, PageQueryV1
from nextrace.contracts.response import ActionExtensionRequestV1, ResponseActionViewV1, RevocationRequestV1
from nextrace.contracts.v1 import ResponseActionProposalV1
from nextrace.core.auth import Principal, authenticate, require_any_role, require_role
from nextrace.core.logging import actor_var, request_id_var
from nextrace.core.pipeline import Pipeline
from nextrace.core.ratelimit import RateLimiter
from nextrace.core.registry import list_models
from nextrace.modules.findings import alerts as alerts_mod
from nextrace.modules.forensics.engine import register_upload
from nextrace.services import audit, forecast, investigations
from nextrace.services.states import recent_states

log = logging.getLogger("nextrace.api")


class CaseCreate(BaseModel):
    case_number: str = Field(pattern=r"^[A-Z0-9-]{4,32}$")
    title: str = Field(min_length=1, max_length=256)
    severity: str = Field(pattern=r"^(low|medium|high|critical)$")


class GrantCreate(BaseModel):
    user_id: UUID
    access_level: str = Field(pattern=r"^(metadata|full_pcap)$")
    expires_in_hours: int = Field(ge=1, le=24 * 90)
    reason: str = Field(min_length=8, max_length=2000)


class AlertStatus(BaseModel):
    status: str = Field(pattern=r"^(acknowledged|escalated|closed)$")
    reason: str | None = Field(default=None, max_length=1000)


class Note(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


def create_app(ctx: Any) -> FastAPI:
    s = ctx.settings
    app = FastAPI(title="NEXTRACE AI", version="0.2.0", docs_url="/docs" if s.environment != "prod" else None, redoc_url=None)
    limiter = RateLimiter(s.api_rate_limit_per_minute)
    pipeline = Pipeline(ctx)

    # -- cross-cutting ------------------------------------------------------------------------
    @app.middleware("http")
    async def _guard(request: Request, call_next):
        rid = uuid.uuid4().hex[:16]
        request_id_var.set(rid)
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > max(s.api_max_body_bytes, s.upload_max_bytes if request.url.path.endswith("/uploads") else 0):
            return JSONResponse({"error": "payload too large", "request_id": rid}, status_code=413)
        key = request.headers.get("x-api-key") or (request.client.host if request.client else "anon")
        if not limiter.allow(f"{key[:16]}:{len(key)}"):
            return JSONResponse({"error": "rate limit exceeded", "request_id": rid}, status_code=429)
        t0 = time.perf_counter()
        try:
            resp = await call_next(request)
        except NextraceError as e:
            resp = JSONResponse({"error": e.public_message, "request_id": rid}, status_code=e.status_code)
        except Exception:  # noqa: BLE001
            log.exception("unhandled error", extra={"event": "api.error"})
            resp = JSONResponse({"error": "internal error", "request_id": rid}, status_code=500)
        resp.headers["x-request-id"] = rid
        log.info("request", extra={"event": "api.request", "stage": f"{request.method} {request.url.path} {resp.status_code} {int((time.perf_counter()-t0)*1000)}ms"})
        return resp

    @app.exception_handler(NextraceError)
    async def _nextrace_error(request: Request, e: NextraceError):
        return JSONResponse({"error": e.public_message, "request_id": request_id_var.get()}, status_code=e.status_code)

    @app.exception_handler(investigations.AuthorizationError)
    async def _authz_error(request: Request, e: Exception):
        return JSONResponse({"error": "forbidden", "request_id": request_id_var.get()}, status_code=403)

    @app.exception_handler(ValueError)
    async def _value_error(request: Request, e: ValueError):
        return JSONResponse({"error": "invalid request", "request_id": request_id_var.get()}, status_code=422)

    @app.exception_handler(LookupError)
    async def _lookup_error(request: Request, e: LookupError):
        return JSONResponse({"error": "not found", "request_id": request_id_var.get()}, status_code=404)

    def principal(x_api_key: str | None = Header(default=None)) -> Principal:
        with ctx.conn_factory() as conn:
            p = authenticate(conn, x_api_key)
        actor_var.set(p.username)
        return p

    # -- health and dashboard -----------------------------------------------------------------
    @app.get("/health")
    def health(x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
        rep: HealthReportV1 = ctx.health.report()
        if not x_api_key:
            return {"status": rep.status, "version": rep.version}
        with ctx.conn_factory() as conn:
            authenticate(conn, x_api_key)
        out = rep.model_dump(mode="json")
        out["model_availability"] = ctx.model_availability
        out["research_required"] = s.research_required()
        out["enforcement_mode"] = s.enforcement_mode
        return out

    @app.get("/v1/dashboard/{sensor_id}")
    def dashboard(sensor_id: UUID, p: Principal = Depends(principal)) -> DashboardSnapshotV1:
        with ctx.conn_factory() as conn:
            cur = forecast.current_run(conn, sensor_id)
            latest = conn.execute(text("SELECT max(window_start) FROM temporal_states WHERE sensor_id = :s"), {"s": sensor_id}).scalar()
            open_alerts = conn.execute(text("SELECT count(*) FROM alerts WHERE sensor_id = :s AND status <> 'closed'"), {"s": sensor_id}).scalar_one()
            enforced = conn.execute(text("SELECT count(*) FROM response_actions WHERE enforced")).scalar_one()
            pending = conn.execute(text("SELECT count(*) FROM response_actions WHERE status = 'proposed'")).scalar_one()
        return DashboardSnapshotV1(sensor_id=sensor_id, as_of=datetime.now(timezone.utc), current_run_id=cur["run_id"] if cur else None,
                                   latest_state_window_start=latest, cache_state_count=ctx.cache.state_count(sensor_id) if ctx.cache else 0,
                                   open_alerts=int(open_alerts), enforced_actions=int(enforced), pending_authorizations=int(pending),
                                   model_availability=ctx.model_availability)

    @app.get("/v1/forecasts/{sensor_id}/current")
    def current(sensor_id: UUID, p: Principal = Depends(principal)) -> Any:
        with ctx.conn_factory() as conn:
            cur = forecast.current_run(conn, sensor_id)
        if cur is None:
            raise NotFound("no forecast yet")
        return json.loads(json.dumps(cur, default=str))

    @app.get("/v1/forecasts/{sensor_id}/history")
    def history(sensor_id: UUID, limit: int = Query(default=50, ge=1, le=500), p: Principal = Depends(principal)) -> Any:
        with ctx.conn_factory() as conn:
            return json.loads(json.dumps(forecast.run_history(conn, sensor_id, limit), default=str))

    @app.get("/v1/states/{sensor_id}")
    def states(sensor_id: UUID, limit: int = Query(default=100, ge=1, le=2000), p: Principal = Depends(principal)) -> Any:
        with ctx.conn_factory() as conn:
            return [st.model_dump(mode="json") for st in recent_states(conn, sensor_id, limit)]

    @app.get("/v1/models")
    def models(p: Principal = Depends(principal)) -> Any:
        with ctx.conn_factory() as conn:
            return {"models": list_models(conn), "availability": ctx.model_availability}

    # -- ingestion from service producers --------------------------------------------------------
    @app.post("/v1/ingest/flows", status_code=202)
    def ingest(batch: FlowBatchV1, p: Principal = Depends(principal)) -> dict[str, Any]:
        require_any_role(p, ("service", "admin"))
        with ctx.conn_factory() as conn:
            states = pipeline.process_batch(conn, batch)
            outcomes = [pipeline.process_state(conn, st) for st in states]
        return {"accepted_flows": len(batch.flows), "states_closed": len(states),
                "runs": sum(1 for o in outcomes if o and o.run_id), "alerts": sum(len(o.alert_ids) for o in outcomes if o)}

    # -- alerts -------------------------------------------------------------------------------------
    @app.get("/v1/alerts")
    def alerts(sensor_id: UUID | None = None, status: str | None = Query(default=None, pattern=r"^(new|acknowledged|escalated|closed)$"),
               limit: int = Query(default=50, ge=1, le=500), cursor: UUID | None = None, p: Principal = Depends(principal)) -> Any:
        with ctx.conn_factory() as conn:
            return json.loads(json.dumps(alerts_mod.list_alerts(conn, sensor_id, status, limit, cursor), default=str))

    @app.get("/v1/alerts/{alert_id}")
    def alert(alert_id: UUID, p: Principal = Depends(principal)) -> Any:
        with ctx.conn_factory() as conn:
            return json.loads(json.dumps(alerts_mod.get_alert(conn, alert_id), default=str))

    @app.patch("/v1/alerts/{alert_id}")
    def alert_status(alert_id: UUID, body: AlertStatus, p: Principal = Depends(principal)) -> dict[str, str]:
        require_role(p, "analyst")
        with ctx.conn_factory() as conn:
            alerts_mod.set_alert_status(conn, alert_id, body.status, p.user_id, body.reason)
        return {"status": body.status}

    @app.post("/v1/predictions/{prediction_id}/feedback", status_code=201)
    def feedback(prediction_id: UUID, verdict: str = Query(pattern=r"^(true_positive|false_positive|benign_anomaly|unknown)$"),
                 body: Note | None = None, p: Principal = Depends(principal)) -> dict[str, str]:
        require_role(p, "analyst")
        fb = AnalystFeedbackV1(prediction_id=prediction_id, user_id=p.user_id, verdict=verdict, note=body.note if body else None)
        with ctx.conn_factory() as conn:
            fid = alerts_mod.record_feedback(conn, fb)
        return {"feedback_id": str(fid), "used_for_training": "false (default; requires a separate reviewed process)"}

    # -- investigations ---------------------------------------------------------------------------
    @app.post("/v1/investigations", status_code=201)
    def open_case(body: CaseCreate, p: Principal = Depends(principal)) -> dict[str, str]:
        require_role(p, "analyst")
        with ctx.conn_factory() as conn:
            cid = investigations.open_case(conn, body.case_number, body.title, body.severity, p.user_id)
        return {"investigation_id": str(cid)}

    @app.get("/v1/investigations/{investigation_id}")
    def case(investigation_id: UUID, p: Principal = Depends(principal)) -> Any:
        with ctx.conn_factory() as conn:
            return alerts_mod.investigation_view(conn, investigation_id, p.user_id)

    @app.post("/v1/investigations/{investigation_id}/updates", status_code=204)
    def case_update(investigation_id: UUID, body: InvestigationUpdateV1, p: Principal = Depends(principal)) -> Response:
        if body.investigation_id != investigation_id or body.actor_id != p.user_id:
            raise Forbidden("update must be for this case and signed by the caller")
        with ctx.conn_factory() as conn:
            alerts_mod.apply_update(conn, body)
        return Response(status_code=204)

    @app.post("/v1/investigations/{investigation_id}/grants", status_code=201)
    def grant(investigation_id: UUID, body: GrantCreate, p: Principal = Depends(principal)) -> dict[str, str]:
        with ctx.conn_factory() as conn:
            gid = investigations.grant_access(conn, investigation_id, body.user_id, body.access_level, p.user_id,
                                              datetime.now(timezone.utc) + timedelta(hours=body.expires_in_hours), body.reason)
        return {"grant_id": str(gid)}

    @app.get("/v1/investigations/{investigation_id}/evidence/{evidence_id}")
    def evidence(investigation_id: UUID, evidence_id: UUID, p: Principal = Depends(principal)) -> StreamingResponse:
        with ctx.conn_factory() as conn:
            row = conn.execute(text("SELECT investigation_id FROM evidence_items WHERE evidence_id = :e"), {"e": evidence_id}).first()
            if row is None or row.investigation_id != investigation_id:
                raise NotFound("evidence not found")
            ref = investigations.open_evidence(conn, ctx.store, evidence_id, p.user_id)
        return StreamingResponse(ctx.store.iter_chunks(ref), media_type="application/octet-stream",
                                 headers={"content-disposition": f'attachment; filename="{ref.hex}.bin"', "x-sha256": ref.hex})

    # -- response actions -------------------------------------------------------------------------
    @app.post("/v1/response-actions", status_code=201)
    def propose(body: ResponseActionProposalV1, p: Principal = Depends(principal)) -> dict[str, Any]:
        require_role(p, "analyst")
        with ctx.conn_factory() as conn:
            aid, decision = ctx.response.propose(conn, body, p.user_id, proposer_kind="analyst")
        return {"action_id": str(aid), "decision": decision.model_dump(mode="json")}

    @app.get("/v1/response-actions")
    def list_actions(status: str | None = Query(default=None, pattern=r"^[a-z_]{1,24}$"), limit: int = Query(default=50, ge=1, le=500),
                     p: Principal = Depends(principal)) -> list[ResponseActionViewV1]:
        with ctx.conn_factory() as conn:
            return ctx.response.list(conn, status, limit)

    @app.get("/v1/response-actions/{action_id}")
    def get_action(action_id: UUID, p: Principal = Depends(principal)) -> dict[str, Any]:
        with ctx.conn_factory() as conn:
            view = ctx.response.view(conn, action_id)
            hist = ctx.response.history(conn, action_id)
        return {"action": view.model_dump(mode="json"), "history": json.loads(json.dumps(hist, default=str))}

    @app.post("/v1/response-actions/{action_id}/authorize")
    def authorize(action_id: UUID, body: Note | None = None, p: Principal = Depends(principal)) -> dict[str, Any]:
        with ctx.conn_factory() as conn:
            decision = ctx.response.authorize(conn, action_id, p.user_id, body.note if body else None)
        return {"status": "authorized", "decision": decision.model_dump(mode="json")}

    @app.post("/v1/response-actions/{action_id}/reject")
    def reject(action_id: UUID, body: Note, p: Principal = Depends(principal)) -> dict[str, str]:
        require_role(p, "analyst")
        with ctx.conn_factory() as conn:
            ctx.response.reject(conn, action_id, p.user_id, body.note or "rejected")
        return {"status": "rejected"}

    @app.post("/v1/response-actions/{action_id}/execute")
    def execute(action_id: UUID, p: Principal = Depends(principal)) -> dict[str, Any]:
        require_any_role(p, ("dfir", "admin", "service"))
        with ctx.conn_factory() as conn:
            return json.loads(json.dumps(ctx.response.execute(conn, action_id, p.user_id), default=str))

    @app.post("/v1/response-actions/{action_id}/extend")
    def extend(action_id: UUID, body: ActionExtensionRequestV1, p: Principal = Depends(principal)) -> dict[str, str]:
        if body.action_id != action_id or body.requested_by != p.user_id:
            raise Forbidden("extension must be for this action and signed by the caller")
        with ctx.conn_factory() as conn:
            new_id = ctx.response.extend(conn, body)
        return {"action_id": str(new_id)}

    @app.post("/v1/response-actions/{action_id}/revoke")
    def revoke(action_id: UUID, body: RevocationRequestV1, p: Principal = Depends(principal)) -> dict[str, str]:
        if body.action_id != action_id or body.requested_by != p.user_id:
            raise Forbidden("revocation must be for this action and signed by the caller")
        with ctx.conn_factory() as conn:
            ctx.response.revoke(conn, body)
        return {"status": "revoked"}

    # -- simulation ---------------------------------------------------------------------------------
    @app.post("/v1/simulations")
    def simulate(body: SimulationRequestV1, p: Principal = Depends(principal)) -> Any:
        require_role(p, "analyst")
        res = ctx.simulator.simulate(body.model_copy(update={"requested_by": p.user_id}))
        return res.model_dump(mode="json")

    # -- forensics ----------------------------------------------------------------------------------
    @app.post("/v1/forensics/uploads", status_code=201)
    async def upload(file: UploadFile = File(...), media_type: str = Form(...), investigation_id: UUID | None = Form(default=None),
                     p: Principal = Depends(principal)) -> dict[str, str]:
        require_role(p, "analyst")
        with ctx.conn_factory() as conn:
            uid = register_upload(conn, ctx.store, p.user_id, file.filename or "upload.pcap", file.file, media_type, s.upload_max_bytes, investigation_id)
        return {"upload_id": str(uid)}

    @app.post("/v1/forensics/jobs", status_code=202)
    def submit_job(body: ForensicJobRequestV1, p: Principal = Depends(principal)) -> dict[str, str]:
        require_role(p, "analyst")
        if body.requested_by != p.user_id:
            raise Forbidden("requested_by must be the caller")
        return {"analysis_id": str(ctx.forensics.submit(body))}

    @app.get("/v1/forensics/jobs/{analysis_id}")
    def job_status(analysis_id: UUID, p: Principal = Depends(principal)) -> Any:
        return ctx.forensics.status(analysis_id).model_dump(mode="json")

    @app.get("/v1/forensics/jobs/{analysis_id}/report")
    def job_report(analysis_id: UUID, p: Principal = Depends(principal)) -> Any:
        return ctx.forensics.report(analysis_id, p.user_id).model_dump(mode="json")

    @app.post("/v1/forensics/findings/{finding_id}/link", status_code=204)
    def link_finding(finding_id: UUID, investigation_id: UUID = Query(...), body: Note | None = None, p: Principal = Depends(principal)) -> Response:
        ctx.forensics.link_finding(finding_id, investigation_id, p.user_id, body.note if body else None)
        return Response(status_code=204)

    # -- audit --------------------------------------------------------------------------------------
    @app.get("/v1/audit")
    def audit_log(limit: int = Query(default=100, ge=1, le=1000), p: Principal = Depends(principal)) -> Any:
        require_role(p, "admin")
        with ctx.conn_factory() as conn:
            rows = conn.execute(text("SELECT audit_id, at, actor_id, action, object_type, object_id, details FROM audit_log ORDER BY audit_id DESC LIMIT :n"),
                                {"n": limit}).mappings().all()
            intact = audit.verify_chain(conn) is None
        return {"chain_intact": intact, "entries": json.loads(json.dumps([dict(r) for r in rows], default=str))}

    return app
