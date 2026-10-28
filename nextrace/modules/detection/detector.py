"""Detector adapters implementing contracts.ports.Detector.

TorchDetector loads a trained LSTM+Attention artifact from the object store. Without an artifact it reports
status 'unavailable'. HeuristicBaselineDetector is a deterministic rule set, registered as kind
'heuristic_baseline' so no one can mistake its output for a learned model's.
"""
from __future__ import annotations

import io
import time
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import numpy as np

from nextrace.contracts.models import DetectionResultV1, InferenceRequestV1, ModelVersionV1
from nextrace.contracts.ops import ComponentHealthV1
from nextrace.contracts.v1 import PredictionV1
from nextrace.core.health import component
from nextrace.modules.detection import model as mdl
from nextrace.storage.object_store import LocalObjectStore, ObjectRef

CATEGORY_NAMES_DEFAULT = ["benign", "malicious"]


class UnavailableDetector:
    """The honest default: no model, no predictions."""

    def __init__(self, reason: str = "no detection model artifact configured (NEXTRACE_DETECTION_MODEL_SHA256 empty)"):
        self.reason = reason

    def model_version(self) -> ModelVersionV1 | None:
        return None

    def detect(self, request: InferenceRequestV1) -> DetectionResultV1:
        return DetectionResultV1(request_id=request.request_id, status="unavailable", reason=self.reason)

    def health(self) -> ComponentHealthV1:
        return component("detector", "template", self.reason)


class HeuristicBaselineDetector:
    """Rules on the most recent state. Scores are rule outputs in [0,1], not calibrated probabilities.
    Parameters are configuration (RESEARCH REQUIRED); the model version records them."""

    def __init__(self, feature_names: list[str], model_version_id: UUID, failed_ratio_min: float, distinct_ports_min: int, min_flows: int):
        self.idx = {n: i for i, n in enumerate(feature_names)}
        for needed in ("n_flows", "distinct_dst_ports", "failed_ratio"):
            if needed not in self.idx:
                raise ValueError(f"baseline needs feature {needed}")
        self.mv = ModelVersionV1(model_version_id=model_version_id, name="heuristic-baseline", kind="heuristic_baseline", version="1",
                                 hyperparameters={"failed_ratio_min": failed_ratio_min, "distinct_ports_min": distinct_ports_min,
                                                  "min_flows": min_flows}, status="active",
                                 evaluation={"note": "deterministic rules; no measured precision/recall"})
        self.failed_ratio_min = failed_ratio_min
        self.distinct_ports_min = distinct_ports_min
        self.min_flows = min_flows

    def model_version(self) -> ModelVersionV1 | None:
        return self.mv

    def detect(self, request: InferenceRequestV1) -> DetectionResultV1:
        t0 = time.perf_counter()
        st = request.sequence.states[-1]  # one prediction per round, for the newest state (older ones were scored in earlier rounds)
        f = st.features
        n_flows, ports, failed = f[self.idx["n_flows"]], f[self.idx["distinct_dst_ports"]], f[self.idx["failed_ratio"]]
        scan_like = n_flows >= self.min_flows and (failed >= self.failed_ratio_min or ports >= self.distinct_ports_min)
        score = min(1.0, max(failed, ports / max(1.0, float(self.distinct_ports_min)))) if scan_like else min(failed, 0.49)
        preds = [PredictionV1(state_id=st.state_id, window_start=st.window_start, is_malicious=scan_like, probability=round(score, 4),
                              category="scan_like" if scan_like else None, attack_stage="reconnaissance" if scan_like else None,
                              technique_ids=["T1046"] if scan_like else [])]
        return DetectionResultV1(request_id=request.request_id, model_version_id=self.mv.model_version_id, status="completed",
                                 predictions=preds, calibrated=False, latency_ms=(time.perf_counter() - t0) * 1000)

    def health(self) -> ComponentHealthV1:
        return component("detector.heuristic_baseline", "ok", "rule-based baseline, not a learned model")


class TorchDetector:
    def __init__(self, store: LocalObjectStore, artifact: ObjectRef, model_version: ModelVersionV1, threshold: float = 0.5):
        if not mdl.torch_available():
            raise RuntimeError("torch is not installed; install the 'ml' extra")
        if model_version.feature_schema_id is None:
            raise ValueError("model version must declare its feature schema")
        with store.open(artifact) as fh:
            self.model, self.meta = mdl.load_artifact(io.BytesIO(fh.read()))
        self.mv = model_version
        self.mean = np.asarray(self.meta.get("scaler_mean"), dtype=np.float32)
        self.std = np.asarray(self.meta.get("scaler_std"), dtype=np.float32)
        self.temperature = float(self.meta.get("temperature", 1.0))
        self.categories: list[str] = list(self.meta.get("categories", CATEGORY_NAMES_DEFAULT))
        self.technique_map: dict[str, list[str]] = dict(self.meta.get("technique_map", {}))
        self.threshold = threshold

    def model_version(self) -> ModelVersionV1 | None:
        return self.mv

    def detect(self, request: InferenceRequestV1) -> DetectionResultV1:
        import torch

        t0 = time.perf_counter()
        seq = request.sequence
        if seq.feature_schema_id != self.mv.feature_schema_id:
            return DetectionResultV1(request_id=request.request_id, status="refused", model_version_id=self.mv.model_version_id,
                                     reason="feature schema mismatch between sequence and model")
        x = np.asarray([s.features for s in seq.states], dtype=np.float32)
        if x.shape[1] != self.mean.shape[0]:
            return DetectionResultV1(request_id=request.request_id, status="refused", model_version_id=self.mv.model_version_id,
                                     reason="feature width mismatch")
        x = (x - self.mean) / self.std
        with torch.no_grad():
            out = self.model(torch.from_numpy(x).unsqueeze(0))
        logit = float(out["logit"][0]) / self.temperature
        prob = float(1.0 / (1.0 + np.exp(-logit)))
        cat_idx = int(torch.argmax(out["category_logits"][0]))
        category = self.categories[cat_idx] if cat_idx < len(self.categories) else None
        attention = [round(float(w), 5) for w in out["attention"][0]]
        last = seq.states[-1]
        pred = PredictionV1(state_id=last.state_id, window_start=last.window_start, is_malicious=prob >= self.threshold, probability=prob,
                            category=category if prob >= self.threshold else None,
                            technique_ids=self.technique_map.get(category or "", []) if prob >= self.threshold else [])
        return DetectionResultV1(request_id=request.request_id, model_version_id=self.mv.model_version_id, status="completed",
                                 predictions=[pred], calibrated=self.temperature != 1.0,
                                 attention={"weights": attention, "window_starts": [s.window_start.isoformat() for s in seq.states]},
                                 latency_ms=(time.perf_counter() - t0) * 1000)

    def health(self) -> ComponentHealthV1:
        return component("detector.lstm_attention", "ok", f"{self.mv.name}:{self.mv.version}", temperature=self.temperature)


def artifact_meta(meta: dict[str, Any]) -> dict[str, Any]:
    return {k: meta.get(k) for k in ("trained_at", "split_manifest", "metrics", "temperature", "seed") if k in meta}


def now() -> datetime:
    return datetime.now(timezone.utc)
