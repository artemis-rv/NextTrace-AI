"""Transparent risk scoring. Every score carries its inputs, weights, formula and weights version so an analyst
can recompute it. Weights are configuration and unvalidated (vendor playbooks multiply likelihood, severity and
asset criticality; no SOC-specific standard exists, see docs/backend/research.md)."""
from __future__ import annotations

import math

from nextrace.contracts.findings import CorrelatedEventV1, RiskScoreV1

FORMULA = "score = w_p*max_probability + w_m*pattern_match + w_a*asset_criticality + w_b*breadth; breadth = min(1, ln(1+predictions)/ln(51))"


class WeightedRiskScorer:
    def __init__(self, w_probability: float, w_pattern: float, w_asset: float, w_breadth: float, sev_high: float, sev_medium: float,
                 sev_low: float, weights_version: str, default_asset_criticality: float = 0.5):
        if abs(w_probability + w_pattern + w_asset + w_breadth - 1.0) > 1e-6:
            raise ValueError("weights must sum to 1")
        self.w = {"probability": w_probability, "pattern_match": w_pattern, "asset_criticality": w_asset, "breadth": w_breadth}
        self.bands = (sev_high, sev_medium, sev_low)
        self.version = weights_version
        self.default_asset = default_asset_criticality

    def score(self, event: CorrelatedEventV1, asset_criticality: float | None) -> RiskScoreV1:
        inputs = {
            "probability": event.max_probability,
            "pattern_match": event.pattern_match_score or 0.0,
            "asset_criticality": self.default_asset if asset_criticality is None else asset_criticality,
            "breadth": min(1.0, math.log1p(event.prediction_count) / math.log1p(50)),
        }
        s = sum(self.w[k] * inputs[k] for k in self.w)
        s = max(0.0, min(1.0, s))
        hi, med, lo = self.bands
        sev = "critical" if s >= hi else "high" if s >= med else "medium" if s >= lo else "low"
        return RiskScoreV1(score=round(s, 4), severity=sev, inputs={k: round(v, 4) for k, v in inputs.items()}, weights=self.w,
                           formula=FORMULA, weights_version=self.version)
