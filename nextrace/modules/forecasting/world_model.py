"""World model and scenario simulation (owner: Person 1).

A world model here means a learned transition model over network states: given the current graph/state and an
optional intervention, predict a distribution over the next state (Ha & Schmidhuber 2018; Hafner et al.
DreamerV3 2023 for the RSSM pattern). Whether enough labelled multi-stage network data exists to train one is
RESEARCH REQUIRED; until then the simulator runs over any `TransitionModel`, including the technique
transition baseline, and labels results as hypotheses.
"""
from __future__ import annotations

import hashlib
import json
import random
import time
from collections import Counter
from typing import Protocol, runtime_checkable
from uuid import UUID

from nextrace.contracts.models import InterventionV1, ModelVersionV1, SimulationRequestV1, SimulationResultV1
from nextrace.contracts.ops import ComponentHealthV1
from nextrace.contracts.v1 import ProgressionStepV1
from nextrace.core.health import component
from nextrace.storage.object_store import LocalObjectStore


@runtime_checkable
class TransitionModel(Protocol):
    """Minimal interface the simulator needs. Implementations: TransitionTableForecaster (via adapter), RSSM world model."""

    def sample_next(self, technique: str, rng: random.Random) -> str | None: ...
    def model_version(self) -> ModelVersionV1 | None: ...


class TechniqueTableTransition:
    """Adapter: uses a fitted TransitionTableForecaster as a stochastic transition model."""

    def __init__(self, table) -> None:
        self.table = table

    def sample_next(self, technique: str, rng: random.Random) -> str | None:
        dist = self.table.next_distribution(technique)
        if not dist:
            return None
        r, acc = rng.random(), 0.0
        for t, p in dist:
            acc += p
            if r <= acc:
                return t
        return dist[-1][0]

    def model_version(self) -> ModelVersionV1 | None:
        return self.table.model_version()


class MonteCarloSimulator:
    """Implements contracts.ports.Simulator. Rolls the transition model forward n times, applies interventions as
    absorbing states (a blocked/isolated host stops the chain), and aggregates hit frequencies."""

    def __init__(self, transition: TransitionModel | None, store: LocalObjectStore | None = None):
        self.transition = transition
        self.store = store

    def simulate(self, request: SimulationRequestV1) -> SimulationResultV1:
        t0 = time.perf_counter()
        if self.transition is None or self.transition.model_version() is None:
            return SimulationResultV1(simulation_id=request.simulation_id, status="unavailable",
                                      reason="no transition model available; train or fit one first")
        start_tech = request.start_technique_id
        if start_tech is None:
            return SimulationResultV1(simulation_id=request.simulation_id, status="refused",
                                      reason="simulation needs start_technique_id (the last observed technique)")
        rng = random.Random(request.seed)
        blocked_at = {iv.at_step for iv in request.interventions if iv.kind != "none"}
        per_step: list[Counter] = [Counter() for _ in range(request.horizon_steps)]
        lengths: list[int] = []
        rollouts: list[list[str]] = []
        for _ in range(request.n_rollouts):
            cur, path = start_tech, []
            for step in range(1, request.horizon_steps + 1):
                if step in blocked_at:
                    break  # intervention assumed effective at this step: chain stops (assumption recorded below)
                nxt = self.transition.sample_next(cur, rng)
                if nxt is None:
                    break
                per_step[step - 1][nxt] += 1
                path.append(nxt); cur = nxt
            lengths.append(len(path)); rollouts.append(path)
        progression = []
        for i, c in enumerate(per_step, start=1):
            if c:
                tech, n = c.most_common(1)[0]
                progression.append(ProgressionStepV1(step=i, predicted_technique_id=tech, probability=round(n / request.n_rollouts, 4)))
        summary = {"n_rollouts": request.n_rollouts, "mean_chain_length": sum(lengths) / len(lengths) if lengths else 0.0,
                   "technique_hit_rate": {t: round(sum(c[t] for c in per_step) / request.n_rollouts, 4) for t in {k for c in per_step for k in c}},
                   "assumptions": ["interventions are assumed effective at at_step and terminate the chain",
                                   "transition model is first-order over techniques; hosts are not modelled"],
                   "latency_ms": round((time.perf_counter() - t0) * 1000, 2)}
        sha = None
        if self.store is not None:
            ref = self.store.put_bytes(json.dumps({"rollouts": rollouts, "summary": summary}, sort_keys=True).encode(), "artifact")
            sha = ref.hex
        return SimulationResultV1(simulation_id=request.simulation_id, status="completed", model_version_id=self.transition.model_version().model_version_id,
                                  progression=progression, rollout_summary=summary, result_sha256=sha)

    def health(self) -> ComponentHealthV1:
        ok = self.transition is not None and self.transition.model_version() is not None
        return component("simulator.monte_carlo", "ok" if ok else "template", "transition model fitted" if ok else "no transition model")



class RSSMWorldModel:  # pragma: no cover - template
    """Template for a recurrent state-space world model over temporal states.

    Intended structure (DreamerV3-style, scaled down): encoder(state features + graph summary) -> posterior z_t;
    GRU deterministic h_t = f(h_{t-1}, z_{t-1}, a_{t-1}); prior over z_t from h_t; decoder reconstructs the next state
    features and a technique/stage head predicts the next progression step. Actions a_t are defender
    interventions (InterventionV1) so counterfactual rollouts are possible.

    TODO(PERSON1): implement with torch once a labelled multi-stage dataset with interventions exists, train with
    chronological splits (modules.temporal.splits), and register the artifact (kind='world_model'). Until then the
    class refuses to instantiate so nothing downstream can mistake it for a model.
    """

    def __init__(self, *_, **__):
        raise NotImplementedError("RSSM world model is a template; no trained artifact exists")


def simulation_id_for(base_run_id: UUID, scenario: dict) -> UUID:
    h = hashlib.sha256(json.dumps({"run": str(base_run_id), "scenario": scenario}, sort_keys=True, default=str).encode()).digest()
    return UUID(bytes=h[:16])
