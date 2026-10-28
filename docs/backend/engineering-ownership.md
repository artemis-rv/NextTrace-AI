# Engineering ownership

Four engineers own four modules. Everything they share is owned by one explicit **integration owner** role.
Nobody owns "the backend"; the backend is the sum of the modules plus the integration layer.

## Who owns what

| Owner | Package(s) | Produces | Consumes (through contracts only) | Must not |
|---|---|---|---|---|
| **Person 1** AI/ML, GNN + world models | `nextrace/modules/forecasting/` | `GraphSnapshotV1` builder, `ProgressionForecastV1`, `SimulationResultV1`, model artifacts (`kind` gnn / world_model) | `InferenceRequestV1` (states + graph), `DetectionResultV1`, `mlcommon` splits/calibration | Redefine packet, flow or temporal-state contracts; write to tables other than through `core.registry` / `services.forecast` |
| **Person 2** AI/ML + full-stack, LSTM+Attention and sequencing | `nextrace/modules/temporal/`, `nextrace/modules/detection/`, `nextrace/mlcommon/` | `TemporalStateV1` stream, `StateSequenceV1`, `DetectionResultV1`, training script and artifacts (`kind` lstm_attention), dashboard/API changes agreed with the integration owner | `FlowRecordV1` batches | Change `WINDOW_FEATURES_V1` without a feature-schema version bump and a contract review with Persons 1 and 4 |
| **Person 3** cybersecurity + full-stack, forensics | `nextrace/modules/forensics/` | uploads, `ForensicJobStatusV1`, `ForensicReportV1`, `ForensicFindingV1` rows, authorised links into investigations | `nextrace/parsing` (shared parser), `services.investigations` for every authorisation decision | Read live queues or live tables directly; bypass `investigations.require_access` |
| **Person 4** cybersecurity + network, live capture | `nextrace/modules/capture/`, `nextrace/parsing/` | `FlowBatchV1`, `CaptureHealthV1`, rolling PCAP segments (via `storage.pcap`) | nothing from other modules | Decide the temporal-state algorithm; change model feature definitions; write flows to the database (the pipeline does) |
| **Integration owner** (role, see below) | `nextrace/contracts/`, `nextrace/core/`, `nextrace/api/`, `nextrace/modules/correlation/`, `nextrace/modules/explanation/`, `nextrace/modules/findings/`, `nextrace/modules/response/`, `nextrace/services/`, `nextrace/storage/`, `nextrace/db/`, `migrations/`, `nextrace/config.py`, `nextrace/workers.py` | canonical contracts and versioning, composition root, pipeline, auth/authz, audit, policy and connectors, alerts/findings lifecycle, release validation | every module's public contract | Reach into a module's internals; merge a contract change without the affected owner's approval |

### The integration-owner role — TEAM DECISION REQUIRED

The brief says a fifth engineer may not exist and that no module owner may silently become responsible for the whole
backend. This document therefore makes the assignment explicit and leaves the name blank for the team to fill in:

* **Default recommendation:** assign the role to **Person 3**. The integration layer is dominated by security-critical
  code (authentication, case-level authorization, audit, policy, connectors), the forensic module is the most
  self-contained of the four, and Person 3's profile matches. Reduce Person 3's forensic scope accordingly
  (e.g. `ioc_match` and `custom` analyses move to "later").
* **Alternative:** Person 2 takes API/dashboard integration (already full-stack) while Person 3 keeps security-critical
  shared code. This splits ownership of `nextrace/api/` from `nextrace/core/auth.py`; acceptable only if contract
  changes still need both signatures.
* Whoever holds the role is the **first approver on every contract change**; the second approver is the owner of each
  module the change touches.

## File boundaries and the rule that is tested

`tests/test_backend_contracts.py::test_modules_do_not_import_each_other` fails the build if any file under
`nextrace/modules/<a>/` imports `nextrace.modules.<b>`. Allowed imports for a module: `nextrace.contracts`,
`nextrace.core` (health, ids, bus, logging), `nextrace.services`, `nextrace.storage`, `nextrace.db`, `nextrace.parsing`,
`nextrace.mlcommon`, `nextrace.config`. A second test checks that `services`, `storage` and `contracts` never import
`nextrace.modules`, so the dependency direction stays one-way: modules → shared layers, pipeline → modules.

Shared libraries with a single owner but several consumers:

| Library | Owner | Consumers | Why shared |
|---|---|---|---|
| `nextrace/parsing/` (header decode, flow assembly) | Person 4 | capture, forensics | one flow shape for live and historical data |
| `nextrace/mlcommon/` (chronological splits, calibration) | Person 2 | detection, forecasting | one evaluation protocol for every model |

## Branch and merge conventions

* `main` is always runnable: migrations apply, `python -m pytest` passes against a local PostgreSQL 18.
* One branch per module per change: `p1/graph-builder-node-features`, `p3/beacon-rule-v2`, `int/contract-v1.2-host-ids`.
* A pull request may touch **one owner's package** plus tests, or it is an integration PR. Integration PRs that change
  `nextrace/contracts/` need two approvals (integration owner + each affected module owner) and a line in
  `module-contracts.md` under "Change log".
* Migrations are integration-owned. A module that needs a column opens an issue with the contract field first; the
  migration follows the contract, never the other way round.
* No `TODO` without a role tag: `TODO(PERSON1|PERSON2|PERSON3|PERSON4|INTEGRATION):` plus what must be implemented.

## Contract-change approval

1. Propose: open a PR that adds the field/model **additively** (optional field, or a new `V2` model next to `V1`).
2. Review: integration owner + affected module owners. Breaking changes (rename, removal, type change, tighter validation)
   require a `V2` model and a migration note; `V1` keeps working for one release.
3. Land: contract first, implementations second, in separate PRs where possible, so parallel branches rebase cleanly.

## Working independently

Each owner can develop and test without the others:

| Owner | Fixture / adapter to use |
|---|---|
| Person 1 | `TemporalStateV1`/`GraphSnapshotV1` from `tests/test_models.py::_seq` and `InMemoryGraphBuilder`; `TransitionTableForecaster` as the reference implementation of the port |
| Person 2 | `PcapReplaySource` over `tests/backend_helpers.scenario_packets`; `tests/test_temporal.py::test_python_features_match_sql_builder` guards feature parity with SQL |
| Person 3 | `register_upload` + `DbForensicEngine` with the test database; `savepoint_factory` for transactional tests |
| Person 4 | `nextrace.parsing` unit tests; `LiveCaptureSource` template with a fake `_reader` pushing `FlowBatchV1` into the bounded queue |
| Integration | `build_context(..., overrides={...})` to swap any port implementation; `UnavailableDetector`/`UnavailableForecaster` prove the pipeline never fabricates |
