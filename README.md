# NextTrace-AI

AI-based network attack forecasting and forensic platform.

This repository contains:

* the **database and storage layer** (PostgreSQL 18 schema and migrations, bounded Redis cache, content-addressed
  object store, retention, legal holds, verified firewall-action state machine) — start at
  [docs/database/README.md](docs/database/README.md);
* the **backend**: versioned contracts, a modular-monolith pipeline (capture → temporal states → detection →
  progression forecasting → correlation → alerts → policy-gated response), a separate forensics pipeline, an HTTP
  API, and the four-person ownership map — start at [docs/backend/README.md](docs/backend/README.md).

Models ship as typed slots: a deterministic baseline runs today, the LSTM+Attention detector trains with the included
script, and the GNN/world-model slots are honest templates that report `unavailable` until a validated artifact exists.
Nothing in the pipeline substitutes fake predictions for a missing model.
