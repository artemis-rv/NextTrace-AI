"""Probability calibration (temperature scaling, Guo et al. ICML 2017) and expected calibration error. numpy only."""
from __future__ import annotations

import numpy as np


def sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-z))


def nll(logits: np.ndarray, y: np.ndarray, temperature: float) -> float:
    p = np.clip(sigmoid(logits / temperature), 1e-7, 1 - 1e-7)
    return float(-np.mean(y * np.log(p) + (1 - y) * np.log(1 - p)))


def fit_temperature(val_logits: np.ndarray, val_labels: np.ndarray, grid: np.ndarray | None = None) -> float:
    """Single scalar T > 0 minimising validation NLL. Fitted on the validation split only, never on test."""
    if len(val_logits) != len(val_labels) or len(val_logits) == 0:
        raise ValueError("logits and labels must be non-empty and aligned")
    grid = np.exp(np.linspace(np.log(0.05), np.log(20.0), 400)) if grid is None else grid
    losses = [nll(val_logits, val_labels, float(t)) for t in grid]
    return float(grid[int(np.argmin(losses))])


def expected_calibration_error(probs: np.ndarray, labels: np.ndarray, n_bins: int = 15) -> float:
    """Binned |accuracy - confidence| weighted by bin mass, for the positive-class probability."""
    probs = np.asarray(probs, dtype=float)
    labels = np.asarray(labels, dtype=float)
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (probs > lo) & (probs <= hi) if lo > 0 else (probs >= lo) & (probs <= hi)
        if not m.any():
            continue
        ece += m.mean() * abs(labels[m].mean() - probs[m].mean())
    return float(ece)
