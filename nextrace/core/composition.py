"""Explicit composition root: picks one implementation per port from configuration and injects it.

Nothing else in the codebase instantiates another module's classes. Tests build a context with overrides.
"""
from __future__ import annotations

import contextlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, ContextManager
from uuid import UUID

import redis
from sqlalchemy import text
from sqlalchemy.engine import Connection

from nextrace.config import Settings
from nextrace.contracts.findings import AlertV1
from nextrace.contracts.models import ModelVersionV1
from nextrace.core.health import HealthRegistry, component
from nextrace.core.registry import ensure_model_version
from nextrace.db.engine import get_engine, transaction
from nextrace.modules.correlation.correlator import SEED_PATTERNS, InMemoryCorrelator
from nextrace.modules.correlation.risk import WeightedRiskScorer
from nextrace.modules.detection.detector import HeuristicBaselineDetector, TorchDetector, UnavailableDetector
from nextrace.modules.explanation.llm import GuardedLLMExplainer, HttpProvider, NullProvider
from nextrace.modules.explanation.shap_explainer import UnavailableExplainer
from nextrace.modules.findings.alerts import emit_alert
from nextrace.modules.forecasting.forecaster import TransitionTableForecaster, UnavailableForecaster
from nextrace.modules.forecasting.world_model import MonteCarloSimulator, TechniqueTableTransition
from nextrace.modules.forensics.engine import DbForensicEngine
from nextrace.modules.response.connectors import DryRunConnector
from nextrace.modules.response.lifecycle import ResponseManager
from nextrace.modules.response.policy import RulePolicyEngine
from nextrace.modules.temporal.sequencer import StreamingSequencer
from nextrace.services.states import EDGE_FEATURES_V1, WINDOW_FEATURES_V1, register_feature_schema
from nextrace.storage.cache import StateCache
from nextrace.storage.object_store import LocalObjectStore, ObjectRef

log = logging.getLogger("nextrace.composition")
ConnFactory = Callable[[], ContextManager[Connection]]


@dataclass
class AppContext:
    settings: Settings
    conn_factory: ConnFactory
    store: LocalObjectStore
    cache: StateCache | None
    feature_schema_id: UUID
    edge_feature_schema_id: UUID
    sequencer: Any
    detector: Any
    forecaster: Any
    simulator: Any
    explainer: Any
    correlator: Any
    risk: Any
    policy: Any
    response: Any
    forensics: Any
    health: HealthRegistry
    alert_sink: Callable[[Connection, AlertV1], UUID] = emit_alert
    model_availability: dict[str, str] = field(default_factory=dict)
    single_connection: bool = False  # True when conn_factory hands out one shared connection (tests): DB stages are serialised


def default_conn_factory() -> ConnFactory:
    return lambda: transaction()


def _artifact_ref(conn: Connection, sha_hex: str | None) -> ObjectRef | None:
    if not sha_hex:
        return None
    r = conn.execute(text("SELECT size_bytes, storage_path FROM objects WHERE sha256 = :h AND deleted_at IS NULL"), {"h": bytes.fromhex(sha_hex)}).first()
    return None if r is None else ObjectRef(bytes.fromhex(sha_hex), int(r.size_bytes), r.storage_path)


def _model_version_for_artifact(conn: Connection, sha_hex: str) -> ModelVersionV1 | None:
    r = conn.execute(text("SELECT model_version_id, name, kind, version, feature_schema_id, hyperparameters, metrics, status FROM model_versions "
                          "WHERE artifact_sha256 = :h ORDER BY created_at DESC LIMIT 1"), {"h": bytes.fromhex(sha_hex)}).mappings().first()
    if r is None:
        return None
    hp = r["hyperparameters"] if isinstance(r["hyperparameters"], dict) else json.loads(r["hyperparameters"])
    kind = hp.get("kind_detail", r["kind"])
    return ModelVersionV1(model_version_id=r["model_version_id"], name=r["name"], kind=kind if kind in ("lstm_attention", "gnn", "world_model", "llm", "heuristic_baseline", "other") else "other",
                          version=r["version"], feature_schema_id=r["feature_schema_id"], artifact_sha256=sha_hex, hyperparameters=hp, status=r["status"])


def build_context(settings: Settings, conn_factory: ConnFactory | None = None, store: LocalObjectStore | None = None,
                  cache: StateCache | None | bool = True, overrides: dict[str, Any] | None = None) -> AppContext:
    overrides = overrides or {}
    conn_factory = conn_factory or default_conn_factory()
    store = store or LocalObjectStore(settings.object_store_root)
    health = HealthRegistry()
    availability: dict[str, str] = {}

    if cache is True:
        try:
            client = redis.Redis.from_url(settings.redis_url.get_secret_value(), socket_connect_timeout=1, socket_timeout=1)
            client.ping()
            cache = StateCache(client, settings.cache_max_states, settings.cache_ttl_seconds)
        except Exception as e:  # noqa: BLE001 - the cache is optional; PostgreSQL is the system of record
            log.warning("redis unavailable, running without live cache: %s", type(e).__name__)
            cache = None
    cache = None if cache is False else cache

    with conn_factory() as conn:
        fs = register_feature_schema(conn, "window", 1, WINDOW_FEATURES_V1)
        efs = register_feature_schema(conn, "edge", 1, EDGE_FEATURES_V1)
        feature_names = [f["name"] for f in WINDOW_FEATURES_V1]

        # detector slot
        detector = overrides.get("detector")
        if detector is None:
            ref = _artifact_ref(conn, settings.detection_model_sha256)
            mv = _model_version_for_artifact(conn, settings.detection_model_sha256) if ref else None
            if ref is not None and mv is not None:
                try:
                    detector = TorchDetector(store, ref, mv)
                    availability["detector"] = "active"
                except Exception as e:  # noqa: BLE001
                    log.error("detection artifact could not be loaded: %s", type(e).__name__)
                    detector = UnavailableDetector(f"artifact load failed: {type(e).__name__}")
                    availability["detector"] = "unavailable"
            elif settings.heuristic_baseline_enabled:
                mv = ModelVersionV1(name="heuristic-baseline", kind="heuristic_baseline", version="1", feature_schema_id=fs,
                                    hyperparameters={"failed_ratio_min": settings.heuristic_failed_ratio, "distinct_ports_min": settings.heuristic_min_distinct_ports,
                                                     "min_flows": settings.heuristic_min_flows}, status="active")
                mv_id = ensure_model_version(conn, mv)
                detector = HeuristicBaselineDetector(feature_names, mv_id, settings.heuristic_failed_ratio, settings.heuristic_min_distinct_ports, settings.heuristic_min_flows)
                availability["detector"] = "heuristic_baseline"
            else:
                detector = UnavailableDetector()
                availability["detector"] = "unavailable"

        # progression slot
        forecaster = overrides.get("forecaster")
        transition = None
        if forecaster is None:
            ref = _artifact_ref(conn, settings.progression_model_sha256)
            mv = _model_version_for_artifact(conn, settings.progression_model_sha256) if ref else None
            if ref is not None and mv is not None:
                with store.open(ref) as fh:
                    forecaster = TransitionTableForecaster.from_json(fh.read().decode(), mv.model_version_id)
                transition = TechniqueTableTransition(forecaster)
                availability["forecaster"] = "transition_table"
            else:
                forecaster = UnavailableForecaster()
                availability["forecaster"] = "unavailable"
        elif isinstance(forecaster, TransitionTableForecaster):
            transition = TechniqueTableTransition(forecaster)
            availability["forecaster"] = "transition_table"
        simulator = overrides.get("simulator") or MonteCarloSimulator(transition, store)
        availability["world_model"] = "template"

        explainer = overrides.get("explainer")
        if explainer is None:
            if settings.llm_enabled and settings.llm_endpoint:
                explainer = GuardedLLMExplainer(HttpProvider(settings.llm_endpoint, settings.llm_api_key.get_secret_value() if settings.llm_api_key else None),
                                                settings.llm_timeout_s)
                availability["explainer"] = "llm"
            else:
                explainer = UnavailableExplainer()
                availability["explainer"] = "unavailable"

    sequencer = overrides.get("sequencer") or StreamingSequencer(settings.state_window_seconds, settings.sequencer_allowed_lateness_s, fs)
    correlator = overrides.get("correlator") or InMemoryCorrelator(settings.correlation_window_s, settings.correlation_grace_s, SEED_PATTERNS)
    risk = overrides.get("risk") or WeightedRiskScorer(settings.risk_w_probability, settings.risk_w_pattern, settings.risk_w_asset, settings.risk_w_breadth,
                                                        settings.risk_sev_high, settings.risk_sev_medium, settings.risk_sev_low, settings.risk_weights_version)
    policy = overrides.get("policy") or RulePolicyEngine(settings)
    connectors = overrides.get("connectors") or {"dry-run": DryRunConnector()}
    response = overrides.get("response") or ResponseManager(connectors, policy, settings)
    forensics = overrides.get("forensics") or DbForensicEngine(conn_factory, store)

    ctx = AppContext(settings=settings, conn_factory=conn_factory, store=store, cache=cache, feature_schema_id=fs, edge_feature_schema_id=efs,
                     sequencer=sequencer, detector=detector, forecaster=forecaster, simulator=simulator, explainer=explainer, correlator=correlator,
                     risk=risk, policy=policy, response=response, forensics=forensics, health=health, model_availability=availability)
    _register_health(ctx, connectors)
    return ctx


def _register_health(ctx: AppContext, connectors: dict[str, Any]) -> None:
    h = ctx.health

    def db() -> Any:
        try:
            with ctx.conn_factory() as c:
                c.execute(text("SELECT 1"))
            return component("database", "ok")
        except Exception as e:  # noqa: BLE001
            return component("database", "down", type(e).__name__)

    def cache() -> Any:
        if ctx.cache is None:
            return component("cache", "degraded", "no redis; live window disabled")
        try:
            ctx.cache.r.ping()
            return component("cache", "ok")
        except Exception as e:  # noqa: BLE001
            return component("cache", "down", type(e).__name__)

    h.register("database", db)
    h.register("cache", cache)
    h.register("detector", ctx.detector.health)
    h.register("forecaster", ctx.forecaster.health)
    h.register("simulator", ctx.simulator.health)
    h.register("explainer", ctx.explainer.health)
    h.register("sequencer", lambda: component("sequencer", "ok", late_dropped=ctx.sequencer.late_flows_dropped(), states=ctx.sequencer.stats.states_emitted))
    h.register("correlator", lambda: component("correlator", "ok", open_groups=ctx.correlator.open_groups))
    for name, c in connectors.items():
        h.register(f"connector.{name}", c.health)
    h.register("config", lambda: component("config", "ok" if ctx.settings.enforcement_mode == "dry_run" else "degraded",
                                           f"enforcement={ctx.settings.enforcement_mode}; research_required={len(ctx.settings.research_required())} params"))


@contextlib.contextmanager
def savepoint_factory(conn: Connection):
    """For tests: every 'transaction' is a savepoint on one outer connection that the test rolls back."""
    with conn.begin_nested():
        yield conn


def engine_ready() -> bool:
    try:
        with get_engine().connect() as c:
            c.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001
        return False
