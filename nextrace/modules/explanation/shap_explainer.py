"""SHAP attributions for the LSTM+Attention detector (GradientExplainer; needs torch, shap and a trained model).

SHAP's own documentation: attributions make correlations transparent, they do not make them causal. Output is
stored as an ExplanationV1 of kind 'shap' with top-k (step, feature) attributions; the full array goes to the
object store when large.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

import numpy as np

from nextrace.contracts.models import ExplanationRequestV1, ExplanationResultV1
from nextrace.contracts.ops import ComponentHealthV1
from nextrace.contracts.v1 import ExplanationV1
from nextrace.core.health import component
from nextrace.storage.object_store import LocalObjectStore


class UnavailableExplainer:
    def __init__(self, reason: str = "no SHAP background set / trained detector available"):
        self.reason = reason

    def explain(self, request: ExplanationRequestV1) -> ExplanationResultV1:
        return ExplanationResultV1(request_id=request.request_id, status="unavailable", reason=self.reason)

    def health(self) -> ComponentHealthV1:
        return component("explainer.shap", "template", self.reason)


class ShapExplainer:
    def __init__(self, detector: Any, background: np.ndarray, feature_names: list[str], store: LocalObjectStore | None = None, top_k: int = 10):
        """detector: a TorchDetector (needs .model, .mean, .std, .mv). background: (n, T, F) raw features from the training split."""
        try:
            import shap  # noqa: F401
            import torch  # noqa: F401
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("shap and torch are required for ShapExplainer") from e
        if background.ndim != 3:
            raise ValueError("background must be (n, T, F)")
        self.detector = detector
        self.background = ((background - detector.mean) / detector.std).astype(np.float32)
        self.feature_names = feature_names
        self.store = store
        self.top_k = top_k

    def explain(self, request: ExplanationRequestV1) -> ExplanationResultV1:
        import shap
        import torch

        if request.kind != "shap" or request.sequence is None:
            return ExplanationResultV1(request_id=request.request_id, status="refused", reason="shap explanations need a sequence")
        x = np.asarray([s.features for s in request.sequence.states], dtype=np.float32)
        x = ((x - self.detector.mean) / self.detector.std).astype(np.float32)[None]
        if x.shape[1] != self.background.shape[1]:
            return ExplanationResultV1(request_id=request.request_id, status="refused", reason="sequence length differs from background")

        class _Logit(torch.nn.Module):
            def __init__(self, m):
                super().__init__(); self.m = m

            def forward(self, t):
                return self.m(t)["logit"].unsqueeze(-1)

        try:
            explainer = shap.GradientExplainer(_Logit(self.detector.model), torch.from_numpy(self.background))
            values = explainer.shap_values(torch.from_numpy(x))
            arr = np.asarray(values[0] if isinstance(values, list) else values).reshape(x.shape[1], x.shape[2])
        except Exception as e:  # noqa: BLE001 - explanation failure must never break the pipeline
            return ExplanationResultV1(request_id=request.request_id, status="failed", reason=f"shap failed: {type(e).__name__}")
        flat = [(int(t), int(f), float(arr[t, f])) for t in range(arr.shape[0]) for f in range(arr.shape[1])]
        flat.sort(key=lambda z: -abs(z[2]))
        top = [{"step": t, "window_start": request.sequence.states[t].window_start.isoformat(), "feature": self.feature_names[f],
                "attribution": round(v, 6)} for t, f, v in flat[: self.top_k]]
        sha = None
        if self.store is not None:
            ref = self.store.put_bytes(json.dumps({"shap_values": arr.tolist(), "features": self.feature_names}).encode(), "shap")
            sha = ref.hex
        content = {"method": "GradientExplainer", "top_attributions": top, "sum_attributions": round(float(arr.sum()), 6),
                   "caveat": "attributions describe the model, not the network; correlation is not causation"}
        exp = ExplanationV1(kind="shap", model_version_id=self.detector.mv.model_version_id, prediction_index=request.prediction_index,
                            content=content, artifact_sha256=sha)
        return ExplanationResultV1(request_id=request.request_id, status="completed", explanation=exp)

    def health(self) -> ComponentHealthV1:
        return component("explainer.shap", "ok", f"background={self.background.shape[0]}")


def content_hash(content: dict) -> str:
    return hashlib.sha256(json.dumps(content, sort_keys=True, default=str).encode()).hexdigest()
