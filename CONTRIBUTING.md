# Contributing to NEXTRACE AI

Read this first. It tells you how to get running, what you own, what to build next, and how to brief an AI coding
assistant so it stays inside your module.

## 1. Day one (about 30 minutes)

1. Read, in order: [README.md](README.md), [docs/backend/README.md](docs/backend/README.md),
   [docs/backend/engineering-ownership.md](docs/backend/engineering-ownership.md), and the row for your module in
   [docs/backend/module-contracts.md](docs/backend/module-contracts.md).
2. Install PostgreSQL 18 and Python 3.12. Redis is optional for local work.
3. Set up and prove the repo works on your machine:

```bash
git clone https://github.com/artemis-rv/NextTrace-AI.git
cd NextTrace-AI
pip install -r requirements.txt
cp .env.example .env
createdb nextrace_test
NEXTRACE_TEST_DATABASE_URL=postgresql+psycopg2://postgres:postgres@127.0.0.1:5432/nextrace_test python -m pytest
```

All tests must pass before you change anything. If they do not, fix your setup, not the tests.

4. See the whole pipeline run once over a capture file:

```bash
python -m alembic upgrade head
python -m nextrace.workers bootstrap --sensor-name lab --username me
python -m nextrace.workers replay --pcap any_capture.pcap --sensor-name lab
python -m nextrace.workers api
```

## 2. What you own

| Person | Your packages | Do not touch without review |
|---|---|---|
| Person 1, GNN and world models | `nextrace/modules/forecasting/` | contracts, other modules, migrations |
| Person 2, LSTM and sequencing | `nextrace/modules/temporal/`, `nextrace/modules/detection/`, `nextrace/mlcommon/` | `WINDOW_FEATURES_V1` without a schema version bump |
| Person 3, forensics | `nextrace/modules/forensics/` | authorization logic in `services/investigations.py` |
| Person 4, live capture | `nextrace/modules/capture/`, `nextrace/parsing/` | anything that writes to the database |
| Integration owner | `contracts/`, `core/`, `api/`, `services/`, `storage/`, `migrations/`, correlation, explanation, findings, response | n/a, but every contract change needs the affected owner's approval |

The integration owner is not yet named. The team must decide this before parallel work starts.

## 3. What to implement next

Each owner's backlog, in priority order. Items marked `TODO(ROLE)` already have a marked extension point in the code.

**Person 1**
1. Prepare multi-stage technique sequences and fit `TransitionTableForecaster`; register it as an artifact so the pipeline stops reporting the forecaster as unavailable.
2. Implement `TorchGATForecaster` in `modules/forecasting/forecaster.py` (TODO(PERSON1)) and a training script that uses `nextrace.mlcommon.splits`.
3. Compare the GAT against the transition table under one protocol and record both in the model registry.
4. Only if a dataset with defender interventions exists: `RSSMWorldModel` in `world_model.py` (TODO(PERSON1)).

**Person 2**
1. Build a labelled dataset of state sequences in the `.npz` format described in `modules/detection/train.py`.
2. Train the LSTM+Attention detector, register the artifact, and set `NEXTRACE_DETECTION_MODEL_SHA256`.
3. Measure calibration on the test split and record it in the model version. Do not assume it.
4. Sweep window length and sequence length and report the results; these are open research parameters.
5. Dashboard and API changes, agreed with the integration owner.

**Person 3**
1. Add an `ioc_match` analysis (currently reported as not implemented).
2. Add an authorised export endpoint for forensic reports and artifacts, with custody events.
3. Forensic UI integration against the existing `/v1/forensics/*` endpoints.
4. Tune the scan and beacon rule parameters on real historical captures.

**Person 4**
1. Implement `LiveCaptureSource._reader()` and `_drops()` in `modules/capture/sources.py` (TODO(PERSON4)).
2. Add a snaplen option so only headers are captured unless full PCAP is authorised.
3. Run a throughput benchmark on a real capture host. The 2.5 Gbps figure is a target, not a result.
4. Add Zeek `conn.log` and Suricata EVE adapters that emit `FlowBatchV1`.

**Integration owner**
1. Test `NftablesConnector` on a staging host (TODO(INTEGRATION)) before any `enforce` mode.
2. Asset inventory integration to replace the `crit:0.9` tag convention (TODO(INTEGRATION)).
3. Persist correlator groups in Redis if restarts prove frequent (TODO(INTEGRATION)).
4. Wire `ShapExplainer` once Person 2 has a trained detector.

The full list of open research questions is in [docs/backend/implementation-status.md](docs/backend/implementation-status.md).

## 4. How to work

* One branch per change, prefixed with your role: `p1/...`, `p2/...`, `p3/...`, `p4/...`, `int/...`.
* A pull request touches one owner's package plus tests. Contract changes are separate pull requests with two
  approvals and a line in the change log in `module-contracts.md`.
* Develop against fixtures, not against each other. `tests/backend_helpers.py` builds deterministic pcaps, and
  `build_context(..., overrides={...})` swaps any port implementation.
* Never return a `completed` result without a real model behind it. Return `unavailable` with a reason.
* `python -m pytest` must pass before you open a pull request. The module-isolation test will fail if you import
  another module's package.

## 5. Prompt template for an AI coding assistant

Copy this, fill in the bracketed parts, and paste it as the first message in a new session opened at the repo root.

```text
You are working on NEXTRACE AI, a modular-monolith network attack forecasting platform. I am [Person N, ROLE].

Before writing code, read these files and confirm in two or three sentences what you understood:
- CONTRIBUTING.md
- docs/backend/engineering-ownership.md
- docs/backend/module-contracts.md (my module's row and the ports I implement)
- nextrace/contracts/ports.py and the contract models my module produces or consumes
- the existing code in [MY PACKAGE PATHS]
- the tests that cover my module: [TEST FILES]

Task: [ONE BACKLOG ITEM FROM CONTRIBUTING.md SECTION 3, OR THE TODO(ROLE) LOCATION]
Done means: [OBSERVABLE OUTCOME, e.g. "the pipeline reports detector=active and the new tests pass"]

Rules:
1. Only edit files under [MY PACKAGE PATHS] and tests. Do not edit nextrace/contracts, nextrace/core,
   migrations, or another module's package. If you believe a contract must change, stop and write a short
   proposal (field, type, reason, who consumes it) instead of changing it.
2. Talk to other modules only through nextrace.contracts models and ports. Never read another module's tables
   or import its package.
3. Never fabricate model output. If a model or artifact is missing, return status "unavailable" with a reason.
4. Use parameterised SQL, validate all input with the contract models, and never log secrets or packet payloads.
5. Mark any value that is not backed by evidence as RESEARCH REQUIRED and make it configuration, not a constant.
6. Add focused tests. Run: python -m pytest. Report the actual result, including failures.

When finished, tell me: what changed (files), test results, anything left undone, and any contract proposal.
```

Fill-in hints per role:

| Role | MY PACKAGE PATHS | TEST FILES |
|---|---|---|
| Person 1 | `nextrace/modules/forecasting/` | `tests/test_models.py` |
| Person 2 | `nextrace/modules/temporal/`, `nextrace/modules/detection/`, `nextrace/mlcommon/` | `tests/test_temporal.py`, `tests/test_models.py` |
| Person 3 | `nextrace/modules/forensics/` | `tests/test_forensics.py` |
| Person 4 | `nextrace/modules/capture/`, `nextrace/parsing/` | `tests/test_capture_parsing.py` |
| Integration | the shared packages listed in section 2 | `tests/test_backend_contracts.py`, `tests/test_api_security.py`, `tests/test_pipeline_e2e.py` |
