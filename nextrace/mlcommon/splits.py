"""Leakage-free dataset splitting for sequence and graph models (owner: Person 2, shared).

Rules enforced here (Arp et al., USENIX Security 2022, "temporal snooping"; NetFlow DL review arXiv 2602.05594):
  * splits are chronological: every training timestamp precedes every validation timestamp, which precedes test;
  * an optional embargo gap keeps a sequence from straddling two splits;
  * normalisation statistics are fitted on the training split only (`fit_scaler`);
  * a hard check refuses sequences whose timestamps are not strictly increasing (future leakage inside a sample).
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Sequence
from uuid import UUID

import numpy as np

from nextrace.contracts.temporal import SplitManifestV1


def chronological_split(timestamps: Sequence[datetime], train_frac: float = 0.6, val_frac: float = 0.2,
                        gap: timedelta = timedelta(0)) -> tuple[np.ndarray, np.ndarray, np.ndarray, tuple[datetime, datetime, datetime]]:
    """Index arrays (train, val, test) by time quantiles, then embargo `gap` around the cut points."""
    if not (0 < train_frac < 1 and 0 < val_frac < 1 and train_frac + val_frac < 1):
        raise ValueError("fractions must be in (0,1) and sum below 1")
    ts = np.array([t.timestamp() for t in timestamps])
    order = np.argsort(ts, kind="stable")
    n = len(ts)
    t_train_end = ts[order[int(n * train_frac) - 1]]
    t_val_end = ts[order[int(n * (train_frac + val_frac)) - 1]]
    g = gap.total_seconds()
    train = order[ts[order] <= t_train_end]
    val = order[(ts[order] > t_train_end + g) & (ts[order] <= t_val_end)]
    test = order[ts[order] > t_val_end + g]
    tz = timestamps[0].tzinfo
    bounds = (datetime.fromtimestamp(t_train_end, tz), datetime.fromtimestamp(t_val_end, tz), datetime.fromtimestamp(ts.max(), tz))
    return train, val, test, bounds


def assert_no_overlap(train_ts: np.ndarray, val_ts: np.ndarray, test_ts: np.ndarray) -> None:
    if len(train_ts) and len(val_ts) and train_ts.max() >= val_ts.min():
        raise ValueError("temporal leakage: training data overlaps validation in time")
    if len(val_ts) and len(test_ts) and val_ts.max() >= test_ts.min():
        raise ValueError("temporal leakage: validation data overlaps test in time")


def assert_sequences_causal(seq_ts: np.ndarray) -> None:
    """seq_ts: (N, T) timestamps per step; each row must be strictly increasing."""
    if seq_ts.ndim != 2:
        raise ValueError("expected (N, T)")
    if np.any(np.diff(seq_ts, axis=1) <= 0):
        raise ValueError("a sequence contains non-increasing timestamps (future steps mixed into the past)")


def fit_scaler(x_train: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Mean/std over the training split only. Apply with (x - mean) / std to every split."""
    flat = x_train.reshape(-1, x_train.shape[-1])
    mean = flat.mean(axis=0)
    std = flat.std(axis=0)
    std[std == 0] = 1.0
    return mean, std


def manifest(dataset_id: UUID, bounds: tuple[datetime, datetime, datetime], counts: dict[str, int], gap: timedelta) -> SplitManifestV1:
    return SplitManifestV1(dataset_id=dataset_id, train_end=bounds[0], validation_end=bounds[1], test_end=bounds[2],
                           gap_seconds=int(gap.total_seconds()), row_counts=counts)
