"""Progression forecaster adapters implementing contracts.ports.ProgressionForecaster.

* UnavailableForecaster: the default when no artifact is configured.
* TransitionTableForecaster: first-order technique-transition baseline fitted on observed technique sequences
  (the lineage of HMM/automaton forecasting: PRISM, Băbălău & Nadeem 2024 rSPDFA; MITRE TIE uses the same
  "observed set -> next techniques" framing). Unavailable until `fit` has seen data; never ships built-in guesses.
* TorchGATForecaster: loads a trained GAT artifact; template until Person 1 trains one.
"""
from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from typing import Iterable
from uuid import UUID

from nextrace.contracts.models import DetectionResultV1, InferenceRequestV1, ModelVersionV1, ProgressionForecastV1
from nextrace.contracts.ops import ComponentHealthV1
from nextrace.contracts.v1 import ProgressionStepV1
from nextrace.core.health import component


class UnavailableForecaster:
    def __init__(self, reason: str = "no progression model artifact configured (NEXTRACE_PROGRESSION_MODEL_SHA256 empty)"):
        self.reason = reason

    def model_version(self) -> ModelVersionV1 | None:
        return None

    def forecast(self, request: InferenceRequestV1, detection: DetectionResultV1) -> ProgressionForecastV1:
        return ProgressionForecastV1(request_id=request.request_id, status="unavailable", reason=self.reason, horizon_seconds=request.horizon_seconds)

    def health(self) -> ComponentHealthV1:
        return component("forecaster", "template", self.reason)


class TransitionTableForecaster:
    """P(next technique | current technique) with additive smoothing, plus per-transition median delay when known."""

    def __init__(self, model_version_id: UUID, alpha: float = 0.5, max_steps: int = 5, tactic_map: dict[str, str] | None = None):
        self.alpha = alpha
        self.max_steps = max_steps
        self.counts: dict[str, Counter] = defaultdict(Counter)
        self.delays: dict[tuple[str, str], list[float]] = defaultdict(list)
        self.techniques: set[str] = set()
        self.n_sequences = 0
        self.tactic_map = tactic_map or {}
        self.mv_id = model_version_id

    def fit(self, sequences: Iterable[list[tuple[str, float]]]) -> "TransitionTableForecaster":
        """sequences: lists of (technique_id, unix_ts) in order, one list per attack campaign."""
        for seq in sequences:
            if len(seq) < 2:
                continue
            self.n_sequences += 1
            for (a, ta), (b, tb) in zip(seq, seq[1:]):
                self.counts[a][b] += 1
                self.techniques.update((a, b))
                if tb >= ta:
                    self.delays[(a, b)].append(tb - ta)
        return self

    def to_json(self) -> str:
        return json.dumps({"alpha": self.alpha, "max_steps": self.max_steps, "n_sequences": self.n_sequences,
                           "counts": {a: dict(c) for a, c in self.counts.items()},
                           "delays": {f"{a}>{b}": sorted(v) for (a, b), v in self.delays.items()}, "tactic_map": self.tactic_map})

    @classmethod
    def from_json(cls, payload: str, model_version_id: UUID) -> "TransitionTableForecaster":
        d = json.loads(payload)
        f = cls(model_version_id, d["alpha"], d["max_steps"], d.get("tactic_map"))
        f.n_sequences = d["n_sequences"]
        for a, c in d["counts"].items():
            f.counts[a] = Counter(c); f.techniques.add(a); f.techniques.update(c)
        for k, v in d["delays"].items():
            a, b = k.split(">"); f.delays[(a, b)] = list(v)
        return f

    def model_version(self) -> ModelVersionV1 | None:
        if not self.n_sequences:
            return None
        return ModelVersionV1(model_version_id=self.mv_id, name="technique-transition-baseline", kind="other", version="1",
                              hyperparameters={"alpha": self.alpha, "max_steps": self.max_steps},
                              evaluation={"n_sequences": self.n_sequences, "n_techniques": len(self.techniques),
                                          "note": "first-order transition frequencies; no held-out accuracy measured"}, status="candidate")

    def next_distribution(self, technique: str) -> list[tuple[str, float]]:
        row = self.counts.get(technique, Counter())
        k = len(self.techniques)
        total = sum(row.values()) + self.alpha * k
        if total == 0:
            return []
        return sorted(((t, (row[t] + self.alpha) / total) for t in self.techniques if t != technique), key=lambda x: -x[1])

    def forecast(self, request: InferenceRequestV1, detection: DetectionResultV1) -> ProgressionForecastV1:
        t0 = time.perf_counter()
        if not self.n_sequences:
            return ProgressionForecastV1(request_id=request.request_id, status="unavailable", reason="transition table not fitted",
                                         horizon_seconds=request.horizon_seconds)
        observed = [t for p in detection.predictions if p.is_malicious for t in p.technique_ids]
        if not observed:
            return ProgressionForecastV1(request_id=request.request_id, status="completed", model_version_id=self.mv_id, steps=[],
                                         horizon_seconds=request.horizon_seconds, uncertainty={"note": "no malicious techniques observed"},
                                         latency_ms=(time.perf_counter() - t0) * 1000)
        cur = observed[-1]
        steps: list[ProgressionStepV1] = []
        chain_p = 1.0
        for i in range(1, self.max_steps + 1):
            dist = self.next_distribution(cur)
            if not dist:
                break
            nxt, p = dist[0]
            chain_p *= p
            d = self.delays.get((cur, nxt))
            median = sorted(d)[len(d) // 2] if d else None
            steps.append(ProgressionStepV1(step=i, predicted_technique_id=nxt, predicted_tactic=self.tactic_map.get(nxt),
                                           probability=round(chain_p, 4), expected_within_s=int(median) if median and median >= 1 else None))
            cur = nxt
        entropy = 0.0
        dist0 = self.next_distribution(observed[-1])
        for _, p in dist0:
            if p > 0:
                entropy -= p * __import__("math").log(p)
        return ProgressionForecastV1(request_id=request.request_id, status="completed", model_version_id=self.mv_id, steps=steps,
                                     horizon_seconds=request.horizon_seconds,
                                     uncertainty={"first_step_entropy": round(entropy, 4), "n_sequences_fitted": self.n_sequences},
                                     latency_ms=(time.perf_counter() - t0) * 1000)

    def health(self) -> ComponentHealthV1:
        return component("forecaster.transition_table", "ok" if self.n_sequences else "template",
                         "fitted" if self.n_sequences else "not fitted", n_sequences=self.n_sequences)


class TorchGATForecaster:  # pragma: no cover - template until an artifact exists
    """TODO(PERSON1): load a trained GATProgressionModel artifact (torch.load weights_only=True), build node/edge tensors from
    request.graph, map per-node technique logits to ProgressionStepV1 with target_host_id, and report uncertainty
    (e.g. MC-dropout spread). Must refuse graphs whose edge_feature_schema_id differs from the training schema."""

    def __init__(self, *_, **__):
        raise NotImplementedError("GAT forecaster has no trained artifact yet")
