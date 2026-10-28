"""Central pipeline orchestrator.

Live traffic -> capture -> FlowBatchV1 -> [persist flows] -> sequencer -> TemporalStateV1 -> [persist, cache, publish]
-> inference round (detector, forecaster, explainer) -> immutable run -> correlation -> risk -> alerts
-> system proposals (policy-gated, never executed here) -> live events.

Two bounded queues separate capture from processing so a slow model never stalls the sensor; the policy of each
queue is configuration. All stage logic is synchronous and testable (`process_batch`, `process_state`); `run`
wires the async workers around them.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from nextrace.contracts.errors import Forbidden, NextraceError
from nextrace.contracts.findings import AlertV1, CorrelatedEventV1
from nextrace.contracts.models import DetectionResultV1, ExplanationRequestV1, InferenceRequestV1, ProgressionForecastV1
from nextrace.contracts.observations import FlowBatchV1
from nextrace.contracts.ports import CaptureSource
from nextrace.contracts.v1 import ExplanationV1, ForecastResultV1, LiveEventV1, ResponseActionProposalV1, TemporalStateV1
from nextrace.core.bus import BoundedQueue
from nextrace.core.ids import uuid7
from nextrace.modules.temporal.repository import persist_states
from nextrace.services import forecast as forecast_svc
from nextrace.services import ingest as ingest_svc

log = logging.getLogger("nextrace.pipeline")


@dataclass
class PipelineStats:
    batches: int = 0
    flows_accepted: int = 0
    flows_rejected: int = 0
    states: int = 0
    inference_rounds: int = 0
    runs_recorded: int = 0
    inference_unavailable: int = 0
    alerts: int = 0
    proposals: int = 0
    proposals_denied: int = 0
    late_events: int = 0
    errors: int = 0
    last_unavailable_reason: str | None = None
    queue_health: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class InferenceOutcome:
    request_id: UUID
    detection: DetectionResultV1
    progression: ProgressionForecastV1 | None
    run_id: UUID | None
    events: list[CorrelatedEventV1]
    alert_ids: list[UUID]
    proposal_ids: list[UUID]


class Pipeline:
    def __init__(self, ctx: Any, persist_flows: bool = True):
        self.ctx = ctx
        self.s = ctx.settings
        self.persist_flows = persist_flows
        self.stats = PipelineStats()

    # -- stage: flows -> states ----------------------------------------------------------------
    def process_batch(self, conn: Connection, batch: FlowBatchV1) -> list[TemporalStateV1]:
        self.stats.batches += 1
        if self.persist_flows and batch.flows:
            bid = ingest_svc.create_batch(conn, batch.sensor_id, {"pcap_replay": "pcap", "live_capture": "api", "zeek_conn": "zeek_conn",
                                                                  "suricata_eve": "suricata_eve", "csv": "csv"}[batch.source])
            res = ingest_svc.ingest_flows(conn, batch.sensor_id, bid, batch.flows)
            self.stats.flows_accepted += res.accepted
            self.stats.flows_rejected += res.rejected
        else:
            self.stats.flows_accepted += len(batch.flows)
        states = self.ctx.sequencer.ingest(batch.flows, batch.sensor_id)
        self._emit_states(conn, states)
        return states

    def flush(self, conn: Connection, sensor_id: UUID) -> list[TemporalStateV1]:
        states = self.ctx.sequencer.flush(sensor_id)
        self._emit_states(conn, states)
        return states

    def _emit_states(self, conn: Connection, states: list[TemporalStateV1]) -> None:
        if not states:
            return
        persist_states(conn, states, self.ctx.feature_schema_id)
        self.stats.states += len(states)
        if self.ctx.cache is not None:
            self.ctx.cache.push_states(states)
            for st in states:
                self.ctx.cache.publish_state(st)

    # -- stage: state -> inference -> run -> alerts ----------------------------------------------
    def process_state(self, conn: Connection, state: TemporalStateV1) -> InferenceOutcome | None:
        seq = self.ctx.sequencer.sequence(state.sensor_id, self.s.sequence_length, up_to=state.window_start)
        if seq is None:
            return None
        self.stats.inference_rounds += 1
        started = datetime.now(timezone.utc)
        request = InferenceRequestV1(request_id=uuid7(), sensor_id=state.sensor_id, requested_at=started, sequence=seq,
                                     horizon_seconds=self.s.forecast_horizon_s)
        det = self.ctx.detector.detect(request)
        if det.status != "completed":
            self.stats.inference_unavailable += 1
            self.stats.last_unavailable_reason = det.reason
            log.info("inference unavailable", extra={"stage": "detect", "sensor_id": str(state.sensor_id), "event": det.status})
            return InferenceOutcome(request.request_id, det, None, None, [], [], [])
        prog = self.ctx.forecaster.forecast(request, det)
        explanations: list[ExplanationV1] = []
        malicious = [i for i, p in enumerate(det.predictions) if p.is_malicious]
        if malicious and self.ctx.explainer is not None:
            kind = "llm" if self.s.llm_enabled else "shap"
            er = self.ctx.explainer.explain(ExplanationRequestV1(request_id=uuid7(), kind=kind, sequence=seq, predictions=det.predictions,
                                                                 progression=prog.steps if prog.status == "completed" else [],
                                                                 prediction_index=malicious[-1]))
            if er.status == "completed" and er.explanation is not None:
                explanations.append(er.explanation)
        completed = datetime.now(timezone.utc)
        result = ForecastResultV1(
            sensor_id=state.sensor_id, model_version_id=det.model_version_id,
            progression_model_version_id=prog.model_version_id if prog.status == "completed" else None,
            input_state_ids=[s.state_id for s in seq.states], input_window_start=seq.states[0].window_start,
            input_window_end=seq.states[-1].window_start + timedelta(seconds=seq.window_seconds), horizon_seconds=request.horizon_seconds,
            started_at=started, completed_at=completed, status="completed", predictions=det.predictions,
            progression=prog.steps if prog.status == "completed" else [], explanations=explanations)
        run_id = forecast_svc.record_run(conn, result)
        self.stats.runs_recorded += 1
        if self.ctx.cache is not None:
            self.ctx.cache.set_current_forecast(state.sensor_id, {"run_id": str(run_id), "completed_at": completed.isoformat(),
                                                                  "n_malicious": len(malicious), "progression_steps": len(result.progression),
                                                                  "progression_status": prog.status})
            self.ctx.cache.publish(LiveEventV1(type="forecast", sensor_id=state.sensor_id, object_id=str(run_id), at=completed,
                                               payload={"n_malicious": len(malicious)}))
        events = self.ctx.correlator.correlate(run_id, state.sensor_id, det.predictions, completed)
        alert_ids, proposal_ids = [], []
        for ev in events:
            aid, pid = self._alert_and_propose(conn, run_id, ev, completed)
            alert_ids.append(aid)
            if pid is not None:
                proposal_ids.append(pid)
        return InferenceOutcome(request.request_id, det, prog, run_id, events, alert_ids, proposal_ids)

    def _alert_and_propose(self, conn: Connection, run_id: UUID, ev: CorrelatedEventV1, now: datetime) -> tuple[UUID, UUID | None]:
        crit = self._asset_criticality(conn, ev.entity.host_id) if ev.entity.host_id else None
        risk = self.ctx.risk.score(ev, crit)
        title = f"{','.join(ev.technique_ids) or 'suspicious activity'} ({ev.entity.kind})" + (f" matches {ev.matched_pattern_id}" if ev.matched_pattern_id else "")
        alert = AlertV1(run_id=run_id, sensor_id=ev.sensor_id, severity=risk.severity, title=title, event=ev, risk=risk)
        aid = self.ctx.alert_sink(conn, alert)
        self.stats.alerts += 1
        if self.ctx.cache is not None:
            self.ctx.cache.publish(LiveEventV1(type="alert", sensor_id=ev.sensor_id, object_id=str(aid), at=now,
                                               payload={"severity": risk.severity, "score": risk.score}))
        pid = None
        if risk.severity in ("high", "critical") and ev.entity.kind == "host" and ev.entity.host_id and self.ctx.response is not None:
            ip = conn.execute(text("SELECT host(ip) FROM hosts WHERE host_id = :h"), {"h": ev.entity.host_id}).scalar()
            if ip:
                proposal = ResponseActionProposalV1(action_type="block_ip", target=ip, enforcement_point="dry-run" if self.s.enforcement_mode == "dry_run" else "default",
                                                    justification=f"system proposal from alert {aid}: {title}; risk {risk.score} ({risk.weights_version})",
                                                    expires_at=now + timedelta(seconds=min(3600, self.s.policy_max_duration_s)), alert_id=aid, run_id=run_id)
                try:
                    pid, _decision = self.ctx.response.propose(conn, proposal, None, proposer_kind="system", risk_score=risk.score, asset_criticality=crit)
                    self.stats.proposals += 1
                except Forbidden:
                    self.stats.proposals_denied += 1
                except NextraceError:
                    self.stats.errors += 1
        return aid, pid

    @staticmethod
    def _asset_criticality(conn: Connection, host_id: UUID) -> float | None:
        """asset_tag convention 'crit:0.9' until an inventory integration exists (TODO(INTEGRATION))."""
        tag = conn.execute(text("SELECT asset_tag FROM hosts WHERE host_id = :h"), {"h": host_id}).scalar()
        if tag and tag.startswith("crit:"):
            try:
                return max(0.0, min(1.0, float(tag[5:])))
            except ValueError:
                return None
        return None

    def late_match(self, conn: Connection, now: datetime) -> int:
        n = 0
        for ev in self.ctx.correlator.late_match(now):
            run_id = ev.source_run_ids[-1]
            self._alert_and_propose(conn, run_id, ev, now)
            n += 1
        self.stats.late_events += n
        return n

    # -- async runner ----------------------------------------------------------------------------
    async def run(self, source: CaptureSource, max_batches: int | None = None) -> PipelineStats:
        q_batches: BoundedQueue[FlowBatchV1] = BoundedQueue("batches", self.s.queue_capacity, self.s.backpressure_policy)
        q_states: BoundedQueue[TemporalStateV1] = BoundedQueue("states", self.s.queue_capacity, "block")
        sensors: set[UUID] = set()
        # With pooled connections the two consumers overlap freely; with one shared connection (tests) they must not interleave savepoints.
        db_lock: asyncio.Lock | None = asyncio.Lock() if getattr(self.ctx, "single_connection", False) else None

        async def db_section(fn, *args):
            if db_lock is None:
                with self.ctx.conn_factory() as conn:
                    return await asyncio.to_thread(fn, conn, *args)
            async with db_lock:
                with self.ctx.conn_factory() as conn:
                    return await asyncio.to_thread(fn, conn, *args)

        async def produce() -> None:
            n = 0
            try:
                async for batch in source.batches():
                    await q_batches.put(batch)
                    n += 1
                    if max_batches is not None and n >= max_batches:
                        break
            finally:
                q_batches.close()

        async def consume_batches() -> None:
            try:
                while True:
                    b = await q_batches.get(timeout_s=0.5)
                    if b is None:
                        if q_batches.closed:
                            break
                        continue
                    sensors.add(b.sensor_id)
                    try:
                        states = await db_section(self.process_batch, b)
                        for st in states:
                            await q_states.put(st)
                    except Exception:  # noqa: BLE001
                        self.stats.errors += 1
                        log.exception("batch processing failed", extra={"stage": "batch", "sensor_id": str(b.sensor_id)})
                for sid in sensors:
                    for st in await db_section(self.flush, sid):
                        await q_states.put(st)
            finally:
                q_states.close()

        async def consume_states() -> None:
            while True:
                st = await q_states.get(timeout_s=0.5)
                if st is None:
                    if q_states.closed:
                        break
                    continue
                try:
                    await db_section(self.process_state, st)
                except Exception:  # noqa: BLE001
                    self.stats.errors += 1
                    log.exception("inference round failed", extra={"stage": "state", "sensor_id": str(st.sensor_id)})

        await asyncio.gather(produce(), consume_batches(), consume_states())
        self.stats.queue_health = {"batches": q_batches.health().metrics, "states": q_states.health().metrics}
        return self.stats
