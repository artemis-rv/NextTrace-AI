# NEXTRACE AI backend

Modular-monolith backend for the AI network-attack forecaster: capture → temporal states → detection → progression
forecasting → correlation → alerts → policy-gated, verified firewall response, with a separate historical forensics
pipeline. Built on the storage layer documented in [../database/](../database/README.md).

| Document | What it answers |
|---|---|
| [research.md](research.md) | Sources (with dates) behind each algorithm and architecture choice; what was not found |
| [architecture.md](architecture.md) | Shape of the system, packages, composition root, processes, backpressure, what is real vs template |
| [module-contracts.md](module-contracts.md) | Every contract and port, per-module specification, change policy and log |
| [data-flow.md](data-flow.md) | Live path, post-detection workflow, historical path, storage touchpoints, dashboard queries |
| [security-and-failure-handling.md](security-and-failure-handling.md) | OWASP mapping, LLM guardrails, firewall safety, failure behaviour |
| [engineering-ownership.md](engineering-ownership.md) | Who owns what, the integration-owner role (team decision required), branch and approval rules |
| [implementation-status.md](implementation-status.md) | What is implemented, tested, measured; templates; blockers; test results |
| [algorithm-and-architecture-decisions.md](algorithm-and-architecture-decisions.md) | Alternatives, selections, evidence, trade-offs, unresolved decisions (final deliverable) |

## Quick start (local, no containers)

```bash
pip install -r requirements.txt            # add torch/shap/scikit-learn for the ML extras
cp .env.example .env                       # database URL, 32+ char pepper, object store root
python -m alembic upgrade head
python -m nextrace.workers bootstrap --sensor-name lab --username admin      # prints the API key once
python -m nextrace.workers replay --pcap path/to/capture.pcap --sensor-name lab
python -m nextrace.workers api             # http://127.0.0.1:8000/docs
python -m nextrace.workers maintenance --once
```

Tests (PostgreSQL 18 required; Redis is faked):

```bash
NEXTRACE_TEST_DATABASE_URL=postgresql+psycopg2://postgres:postgres@127.0.0.1:5432/nextrace_test python -m pytest
```
