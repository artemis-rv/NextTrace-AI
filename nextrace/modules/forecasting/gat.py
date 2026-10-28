"""Graph attention layers for progression forecasting (owner: Person 1). Template architecture: the layer is
implemented and unit-tested for shapes; the training objective and target encoding are the owner's decision.

Target under consideration (RESEARCH REQUIRED): per-node next-technique distribution over the next k windows, learned
from labelled multi-stage captures. Alternatives documented in docs/backend/algorithm-and-architecture-decisions.md.
"""
from __future__ import annotations

try:  # pragma: no cover
    import torch
    from torch import nn
    import torch.nn.functional as F
except Exception:  # noqa: BLE001
    torch = None  # type: ignore[assignment]

ARCH_NAME = "gat_progression_v0_template"

if torch is not None:

    class GATLayer(nn.Module):
        """Dense multi-head graph attention (Velickovic et al. 2018) with edge features folded into the attention logits.
        Dense adjacency is fine for per-window graphs of a few thousand hosts; switch to sparse ops beyond that."""

        def __init__(self, in_dim: int, out_dim: int, edge_dim: int, heads: int = 4, dropout: float = 0.1):
            super().__init__()
            self.heads, self.out_dim = heads, out_dim
            self.w = nn.Linear(in_dim, heads * out_dim, bias=False)
            self.we = nn.Linear(edge_dim, heads, bias=False)
            self.a_src = nn.Parameter(torch.empty(heads, out_dim)); self.a_dst = nn.Parameter(torch.empty(heads, out_dim))
            nn.init.xavier_uniform_(self.a_src); nn.init.xavier_uniform_(self.a_dst)
            self.drop = nn.Dropout(dropout)

        def forward(self, x: "torch.Tensor", edge_index: "torch.Tensor", edge_attr: "torch.Tensor") -> "torch.Tensor":
            n = x.shape[0]
            h = self.w(x).view(n, self.heads, self.out_dim)                      # (N, H, D)
            e_src = (h * self.a_src).sum(-1)                                      # (N, H)
            e_dst = (h * self.a_dst).sum(-1)
            src, dst = edge_index[0], edge_index[1]
            logits = F.leaky_relu(e_src[src] + e_dst[dst] + self.we(edge_attr), 0.2)  # (E, H)
            # softmax over incoming edges per destination node
            logits = logits - logits.max()
            weights = torch.exp(logits)
            denom = torch.zeros(n, self.heads, device=x.device).index_add_(0, dst, weights) + 1e-9
            alpha = self.drop(weights / denom[dst])                              # (E, H)
            out = torch.zeros(n, self.heads, self.out_dim, device=x.device).index_add_(0, dst, alpha.unsqueeze(-1) * h[src])
            out = out + h  # self-connection
            return out.reshape(n, self.heads * self.out_dim)

    class GATProgressionModel(nn.Module):
        """Node encoder (2 GAT layers) + per-node technique head. Outputs logits over `n_techniques` for each node:
        'which technique is this host most likely to be involved in next'. Untrained template."""

        def __init__(self, node_dim: int, edge_dim: int, n_techniques: int, hidden: int = 32, heads: int = 4):
            super().__init__()
            self.hparams = {"arch": ARCH_NAME, "node_dim": node_dim, "edge_dim": edge_dim, "n_techniques": n_techniques,
                            "hidden": hidden, "heads": heads}
            self.g1 = GATLayer(node_dim, hidden, edge_dim, heads)
            self.g2 = GATLayer(hidden * heads, hidden, edge_dim, heads)
            self.head = nn.Linear(hidden * heads, n_techniques)

        def forward(self, x, edge_index, edge_attr):
            h = F.elu(self.g1(x, edge_index, edge_attr))
            h = F.elu(self.g2(h, edge_index, edge_attr))
            return self.head(h)
