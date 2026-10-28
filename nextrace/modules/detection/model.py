"""LSTM + additive attention over a sequence of temporal states (owner: Person 2).

Input  x: (batch, T, F) standardised window features, oldest first. A boolean `mask` (batch, T) marks real steps;
missing windows (gaps) are masked out of the attention rather than imputed, so the model never sees invented data.
Output: binary logit (malicious vs. not), category logits, and the attention weights (for explanation only).
The attention is over the input window, which is entirely in the past relative to the prediction time, so it is causal.
torch is imported lazily so the rest of the backend runs without it.
"""
from __future__ import annotations

from typing import Any

try:  # pragma: no cover - import guard
    import torch
    from torch import nn
except Exception:  # noqa: BLE001
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]

ARCH_NAME = "lstm_attention_v1"


def torch_available() -> bool:
    return torch is not None


if torch is not None:

    class AdditiveAttention(nn.Module):
        def __init__(self, hidden: int):
            super().__init__()
            self.w = nn.Linear(hidden, hidden)
            self.v = nn.Linear(hidden, 1, bias=False)

        def forward(self, h: "torch.Tensor", mask: "torch.Tensor | None") -> tuple["torch.Tensor", "torch.Tensor"]:
            scores = self.v(torch.tanh(self.w(h))).squeeze(-1)  # (B, T)
            if mask is not None:
                scores = scores.masked_fill(~mask, float("-inf"))
            weights = torch.softmax(scores, dim=-1)
            weights = torch.nan_to_num(weights, nan=0.0)  # all-masked rows
            context = torch.bmm(weights.unsqueeze(1), h).squeeze(1)
            return context, weights

    class LSTMAttentionClassifier(nn.Module):
        def __init__(self, n_features: int, hidden: int = 64, layers: int = 1, n_categories: int = 2, dropout: float = 0.1):
            super().__init__()
            self.hparams: dict[str, Any] = {"arch": ARCH_NAME, "n_features": n_features, "hidden": hidden, "layers": layers,
                                            "n_categories": n_categories, "dropout": dropout}
            self.lstm = nn.LSTM(n_features, hidden, num_layers=layers, batch_first=True, dropout=dropout if layers > 1 else 0.0)
            self.attn = AdditiveAttention(hidden)
            self.drop = nn.Dropout(dropout)
            self.binary_head = nn.Linear(hidden, 1)
            self.category_head = nn.Linear(hidden, n_categories)

        def forward(self, x: "torch.Tensor", mask: "torch.Tensor | None" = None) -> dict[str, "torch.Tensor"]:
            h, _ = self.lstm(x)
            ctx, weights = self.attn(h, mask)
            ctx = self.drop(ctx)
            return {"logit": self.binary_head(ctx).squeeze(-1), "category_logits": self.category_head(ctx), "attention": weights}

    def save_artifact(model: "LSTMAttentionClassifier", path: str, extra: dict[str, Any]) -> None:
        torch.save({"hparams": model.hparams, "state_dict": model.state_dict(), **extra}, path)

    def load_artifact(path_or_file: Any) -> tuple["LSTMAttentionClassifier", dict[str, Any]]:
        """weights_only=True refuses pickled code: artifacts are data, not executables (OWASP deserialization)."""
        blob = torch.load(path_or_file, map_location="cpu", weights_only=True)
        hp = dict(blob["hparams"])
        if hp.get("arch") != ARCH_NAME:
            raise ValueError(f"artifact architecture {hp.get('arch')!r} is not {ARCH_NAME}")
        model = LSTMAttentionClassifier(hp["n_features"], hp["hidden"], hp["layers"], hp["n_categories"], hp["dropout"])
        model.load_state_dict(blob["state_dict"])
        model.eval()
        meta = {k: v for k, v in blob.items() if k not in ("state_dict",)}
        return model, meta
