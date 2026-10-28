"""Reproducible training/evaluation for the LSTM+Attention detector (owner: Person 2).

Usage:
  python -m nextrace.modules.detection.train --dataset data.npz --out artifact.pt --metrics metrics.json [--epochs 20 --seed 7]

The .npz must contain: X (N, T, F) float32 window features oldest-first, y (N,) {0,1}, ts (N, T) unix seconds per step,
optional cat (N,) int category labels and `categories` (K,) str names.
Protocol: chronological split with an embargo gap; scaler fitted on train; temperature fitted on validation;
metrics reported on test only. The script writes what it measured; it never claims anything else.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

import numpy as np

from nextrace.mlcommon.calibration import expected_calibration_error, fit_temperature, sigmoid
from nextrace.mlcommon.splits import assert_no_overlap, assert_sequences_causal, chronological_split, fit_scaler


def _metrics(probs: np.ndarray, y: np.ndarray, threshold: float = 0.5) -> dict[str, float]:
    pred = (probs >= threshold).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    # AUC by rank statistic (Mann-Whitney), no sklearn dependency
    order = np.argsort(probs)
    ranks = np.empty(len(probs)); ranks[order] = np.arange(1, len(probs) + 1)
    n_pos, n_neg = int(y.sum()), int(len(y) - y.sum())
    auc = (ranks[y == 1].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg) if n_pos and n_neg else float("nan")
    return {"precision": prec, "recall": rec, "f1": f1, "auc": float(auc), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "fpr": fp / (fp + tn) if fp + tn else 0.0, "ece": expected_calibration_error(probs, y)}


def train(args: argparse.Namespace) -> dict:
    import torch
    from torch import nn

    from nextrace.modules.detection.model import LSTMAttentionClassifier, save_artifact

    torch.manual_seed(args.seed); np.random.seed(args.seed)
    torch.use_deterministic_algorithms(True, warn_only=True)
    d = np.load(args.dataset, allow_pickle=False)
    X, y, ts = d["X"].astype(np.float32), d["y"].astype(np.int64), d["ts"].astype(np.float64)
    cat = d["cat"].astype(np.int64) if "cat" in d else y.copy()
    categories = [str(c) for c in d["categories"]] if "categories" in d else ["benign", "malicious"]
    assert_sequences_causal(ts)
    last_ts = [datetime.fromtimestamp(t, tz=timezone.utc) for t in ts[:, -1]]
    gap = timedelta(seconds=args.gap_seconds)
    tr, va, te, bounds = chronological_split(last_ts, args.train_frac, args.val_frac, gap)
    assert_no_overlap(ts[tr, -1], ts[va, -1], ts[te, -1])
    mean, std = fit_scaler(X[tr])
    Xn = (X - mean) / std

    model = LSTMAttentionClassifier(X.shape[2], args.hidden, args.layers, len(categories), args.dropout)
    opt = torch.optim.Adam(model.parameters(), lr=args.lr)
    pos_weight = torch.tensor([(len(tr) - y[tr].sum()) / max(1, y[tr].sum())], dtype=torch.float32)  # imbalance handling
    bce = nn.BCEWithLogitsLoss(pos_weight=pos_weight); ce = nn.CrossEntropyLoss()
    xt, yt, ct = torch.from_numpy(Xn[tr]), torch.from_numpy(y[tr]).float(), torch.from_numpy(cat[tr])
    history = []
    for epoch in range(args.epochs):
        model.train(); perm = torch.randperm(len(tr)); total = 0.0
        for i in range(0, len(tr), args.batch_size):
            idx = perm[i:i + args.batch_size]
            out = model(xt[idx])
            loss = bce(out["logit"], yt[idx]) + args.category_weight * ce(out["category_logits"], ct[idx])
            opt.zero_grad(); loss.backward(); opt.step(); total += float(loss) * len(idx)
        model.eval()
        with torch.no_grad():
            vl = model(torch.from_numpy(Xn[va]))["logit"].numpy()
        history.append({"epoch": epoch, "train_loss": total / len(tr), "val": _metrics(sigmoid(vl), y[va])})
    with torch.no_grad():
        val_logits = model(torch.from_numpy(Xn[va]))["logit"].numpy()
        test_logits = model(torch.from_numpy(Xn[te]))["logit"].numpy()
    T = fit_temperature(val_logits, y[va]) if len(va) else 1.0
    report = {
        "arch": model.hparams, "seed": args.seed, "trained_at": datetime.now(timezone.utc).isoformat(),
        "split": {"train_end": bounds[0].isoformat(), "validation_end": bounds[1].isoformat(), "test_end": bounds[2].isoformat(),
                  "gap_seconds": args.gap_seconds, "rows": {"train": int(len(tr)), "validation": int(len(va)), "test": int(len(te))}},
        "temperature": T,
        "metrics": {"validation": _metrics(sigmoid(val_logits / T), y[va]) if len(va) else None,
                    "test": _metrics(sigmoid(test_logits / T), y[te]) if len(te) else None,
                    "test_uncalibrated_ece": expected_calibration_error(sigmoid(test_logits), y[te]) if len(te) else None},
        "history": history, "categories": categories,
        "caveats": ["metrics are on this dataset's chronological test split only",
                    "no claim about live traffic performance; see docs/backend/implementation-status.md"],
    }
    save_artifact(model, args.out, {"scaler_mean": mean.tolist(), "scaler_std": std.tolist(), "temperature": T, "categories": categories,
                                    "trained_at": report["trained_at"], "split_manifest": report["split"], "metrics": report["metrics"],
                                    "seed": args.seed, "technique_map": json.loads(args.technique_map)})
    with open(args.metrics, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", required=True); p.add_argument("--out", required=True); p.add_argument("--metrics", required=True)
    p.add_argument("--epochs", type=int, default=20); p.add_argument("--batch-size", type=int, default=64)
    p.add_argument("--hidden", type=int, default=64); p.add_argument("--layers", type=int, default=1)
    p.add_argument("--dropout", type=float, default=0.1); p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--category-weight", type=float, default=0.5); p.add_argument("--seed", type=int, default=7)
    p.add_argument("--train-frac", type=float, default=0.6); p.add_argument("--val-frac", type=float, default=0.2)
    p.add_argument("--gap-seconds", type=int, default=0)
    p.add_argument("--technique-map", default='{"malicious": []}', help='JSON {category: [technique ids]}')
    args = p.parse_args(argv)
    try:
        import torch  # noqa: F401
    except ImportError:
        print("torch is required: pip install 'nextrace-ai[ml]'", file=sys.stderr)
        return 2
    rep = train(args)
    print(json.dumps({"test": rep["metrics"]["test"], "temperature": rep["temperature"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
