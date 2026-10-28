# Module contracts

Every contract is a pydantic v2 model in `nextrace/contracts/` with `extra="forbid"`, timezone-aware timestamps,
regex allow-lists on free text, bounded list lengths, and a `version` literal. Ports are `typing.Protocol`s in
`nextrace/contracts/ports.py`. This file is the human index; the code is the authority.

## 1. Contract catalogue

| Contract | File | Producer → Consumer | Validation worth knowing |
|---|---|---|---|
| `FlowRecordV1` | `v1.py` | capture, forensics, Zeek/Suricata adapters → pipeline, sequencer | ports 0–65535, non-negative counters, `ts_end ≥ ts_start`, no future timestamps, `features` ⇔ `feature_schema_id` |
| `PacketObservationV1` | `observations.py` | parser (internal to capture/forensics) | header fields only; `payload_len` counted, bytes never carried; `caplen ≤ wirelen` |
| `FlowBatchV1` | `observations.py` | capture → pipeline / `POST /v1/ingest/flows` | ordered by `ts_start`, ≤ 50 000 flows, monotonic `batch_seq` per sensor (gaps mean loss) |
| `CaptureHealthV1` | `observations.py` | capture → health, dashboard | `drop_counters_available` must be honest; `queue_depth ≤ queue_capacity` |
| `TemporalStateV1` | `v1.py` | sequencer / SQL builder → cache, models | one row per `(sensor, window_start, window_seconds)`; `features` ordered by `WINDOW_FEATURES_V1` |
| `FeatureSnapshotV1` | `temporal.py` | any feature producer → models | finite values; schema id + version |
| `StateSequenceV1` | `temporal.py` | sequencer → detector | strictly increasing, single sensor and window length, `missing_windows` listed explicitly (never zero-filled here) |
| `GraphSnapshotV1`, `GraphSequenceV1` | `temporal.py` | graph builder → forecaster, simulator | nodes carry pseudonyms only; edge indices validated |
| `SplitManifestV1` | `temporal.py` | training scripts → model registry | train < validation < test in time |
| `ModelVersionV1` | `models.py` | training scripts → `core.registry` | kinds: lstm_attention, gnn, world_model, llm, heuristic_baseline, other; `evaluation` is what was measured |
| `InferenceRequestV1` | `models.py` | pipeline → detector, forecaster | one request id per round; horizon bounded to 7 days |
| `DetectionResultV1` | `models.py` | detector → pipeline | `completed` requires a model version; non-completed carries a reason and **no predictions** |
| `ProgressionForecastV1` | `models.py` | forecaster → pipeline | same honesty rules; `uncertainty` free-form but recorded |
| `SimulationRequestV1`, `SimulationResultV1` | `models.py` | API → simulator | ≤ 10 000 rollouts, ≤ 64 steps; result carries a disclaimer and the rollouts' hash |
| `ExplanationRequestV1`, `ExplanationResultV1` | `models.py` | pipeline/API → explainer | `guardrail_flags` list every violation found in LLM output |
| `InferenceRunV1` | `models.py` | pipeline (provenance) | compact: request, detection, progression, explanations, timings |
| `CorrelatedEventV1` | `findings.py` | correlator → risk, alerts | entity, dedupe counts, technique sequence, pattern match, `late_matched` |
| `RiskScoreV1` | `findings.py` | risk scorer → alerts, policy | inputs, weights, formula and weights version always present |
| `AlertV1`, `FindingV1` | `findings.py` | pipeline / analysts → DB | findings with basis `analyst_confirmed` or `forensic` must cite evidence |
| `InvestigationUpdateV1` | `findings.py` | API → `findings.alerts.apply_update` | action-specific required fields; authorization enforced in the handler |
| `AnalystFeedbackV1` | `findings.py` | API → DB | stored with `eligible_for_training=false` |
| `DashboardSnapshotV1` | `findings.py` | API | current state only; history is in immutable runs |
| `ForensicJobRequestV1`, `ForensicJobStatusV1`, `ForensicReportV1`, `ForensicFindingV1`, `ForensicArtifactV1` | `forensics.py` | API ↔ forensic engine | exactly one source (upload or evidence); artifacts are content-addressed and name their tool version |
| `PolicyInputV1`, `PolicyDecisionV1` | `response.py` | response manager ↔ policy engine | inputs are numeric/enumerated only; decision lists `rules_fired` |
| `ConnectorCommandV1`, `ConnectorResultV1` | `response.py` | response manager ↔ connector | idempotency key; `accepted` ≠ enforced |
| `ResponseActionProposalV1`, `VerificationResultV1` | `v1.py` | analysts/system → response manager; connector → manager | expiry in the future; `block_pair` needs a peer |
| `ActionExtensionRequestV1`, `RevocationRequestV1`, `ResponseActionViewV1` | `response.py` | API ↔ response manager | reasons ≥ 8 chars |
| `AuditEventV1`, `ComponentHealthV1`, `HealthReportV1`, `TimeRangeQueryV1`, `PageQueryV1` | `ops.py` | modules → audit/health; API queries | query spans capped (default 7 days, max 90) |
| `LiveEventV1`, `EvidenceManifestV1`, `ForecastResultV1`, `PredictionV1`, `ProgressionStepV1`, `ExplanationV1` | `v1.py` | storage-facing (unchanged from the database layer) | `PredictionV1.host_ids` added in v1.1 (additive) |

## 2. Ports (module interfaces)

| Port | Methods | Implemented by | Called by |
|---|---|---|---|
| `CaptureSource` | `batches()` async iterator, `health()`, `stop()` | `PcapReplaySource`, `LiveCaptureSource` (template) | pipeline |
| `TemporalSequencer` | `ingest(flows, sensor) → closed states`, `flush(sensor)`, `sequence(sensor, length, up_to)`, `late_flows_dropped()` | `StreamingSequencer` | pipeline |
| `Detector` | `model_version()`, `detect(request)`, `health()` | `TorchDetector`, `HeuristicBaselineDetector`, `UnavailableDetector` | pipeline |
| `GraphBuilder` | `build(state)` | `DbGraphBuilder`, `InMemoryGraphBuilder` | forecaster owner, API |
| `ProgressionForecaster` | `model_version()`, `forecast(request, detection)`, `health()` | `TransitionTableForecaster`, `UnavailableForecaster`, `TorchGATForecaster` (template) | pipeline |
| `Simulator` | `simulate(request)`, `health()` | `MonteCarloSimulator` | API |
| `Explainer` | `explain(request)`, `health()` | `ShapExplainer`, `GuardedLLMExplainer`, `UnavailableExplainer` | pipeline, API |
| `Correlator` | `correlate(run_id, sensor, predictions, now)`, `late_match(now)` | `InMemoryCorrelator` | pipeline, maintenance |
| `RiskScorer` | `score(event, asset_criticality)` | `WeightedRiskScorer` | pipeline |
| `PolicyEngine` | `evaluate(PolicyInputV1)` | `RulePolicyEngine` | response manager |
| `FirewallConnector` | `execute(command)`, `verify(command)`, `health()` | `DryRunConnector`, `InMemoryConnector`, `NftablesConnector` (template) | response manager |
| `ForensicEngine` | `submit`, `run_next`, `status`, `report` (+ `link_finding`) | `DbForensicEngine` | API, forensics worker |
| `AlertSink` | `emit(alert)` | `findings.alerts.emit_alert` | pipeline |

Module isolation is enforced by `tests/test_backend_contracts.py` (no `nextrace.modules.<a>` imports
`nextrace.modules.<b>`; shared layers never import modules; every implementation exposes its port's methods).

## 3. Per-module specification

| Module | Inputs | Outputs | Validation | Dependencies | Errors | Configuration | Tests | Integration point |
|---|---|---|---|---|---|---|---|---|
| capture (P4) | packets from file/socket | `FlowBatchV1`, `CaptureHealthV1` | contract validation on emit; malformed packets counted never raised | `nextrace.parsing`, `core.bus`, `storage.pcap` | `Backpressure` when a `reject` queue is full | batch size, realtime/speed, inactive/active timeouts, queue policy | `test_capture_parsing.py` | `Pipeline.run(source)` |
| temporal (P2) | `FlowRecordV1` | `TemporalStateV1`, `StateSequenceV1` | window binning identical to SQL (`test_python_features_match_sql_builder`) | `services.states.WINDOW_FEATURES_V1`, `core.ids` | `ContractViolation` when open windows exceed the bound | `STATE_WINDOW_SECONDS`, `SEQUENCER_ALLOWED_LATENESS_S`, `SEQUENCE_LENGTH` | `test_temporal.py` | `Pipeline.process_batch` |
| detection (P2) | `InferenceRequestV1` | `DetectionResultV1` | feature schema id and width checked; artifact loaded with `weights_only` | torch (optional), `mlcommon` | returns `refused`/`unavailable`, never raises into the pipeline | `DETECTION_MODEL_SHA256`, heuristic parameters | `test_models.py` | `Pipeline.process_state` |
| forecasting (P1) | `InferenceRequestV1`, `DetectionResultV1`, `SimulationRequestV1` | `ProgressionForecastV1`, `SimulationResultV1`, `GraphSnapshotV1` | technique ids regex; unfitted model → `unavailable` | torch (GAT only), `services.security.pseudonymize_ip` | as above | `PROGRESSION_MODEL_SHA256`, `WORLD_MODEL_SHA256`, `FORECAST_HORIZON_S` | `test_models.py` | `Pipeline.process_state`, `POST /v1/simulations` |
| correlation (integration) | predictions per run | `CorrelatedEventV1`, `RiskScoreV1` | pattern ids regex; weights sum to 1 | none | none | `CORRELATION_WINDOW_S`, `CORRELATION_GRACE_S`, `RISK_*` | `test_correlation_explanation.py` | `Pipeline._alert_and_propose`, maintenance `late_match` |
| explanation (integration) | `ExplanationRequestV1` | `ExplanationResultV1` | output sanitised; flags; prompt hash | shap/torch (SHAP), httpx (LLM) | provider errors → `unavailable`; guardrail hits → `refused` | `LLM_*`, `SHAP_BACKGROUND_ROWS` | `test_correlation_explanation.py` | pipeline after detection |
| findings (integration) | `AlertV1`, `InvestigationUpdateV1`, `AnalystFeedbackV1` | rows, audit entries | state machine for alert status; case-level authz on every update | `services.investigations`, `services.audit` | `Conflict`, `Forbidden`, `NotFound` | none | `test_api_security.py`, `test_pipeline_e2e.py` | pipeline, API |
| response (integration) | proposals, authorizations, connector results | `PolicyDecisionV1`, action state, audit | DB trigger state machine + manager invariants (two-person, roles, caps) | `services.response`, connectors | `Forbidden`, `Conflict`, `ConnectorError` | `ENFORCEMENT_MODE`, `POLICY_*`, `VERIFICATION_*` | `test_policy_response.py` | pipeline (system proposals), API, maintenance |
| forensics (P3) | uploads, `ForensicJobRequestV1` | job rows, findings, report objects | signature + size + filename checks; hash verified before and after | `nextrace.parsing`, `storage.object_store`, `services.investigations` | `ContractViolation`, `PayloadTooLarge`, `Forbidden`, `NotFound`; failures recorded on the row | `UPLOAD_MAX_BYTES`, packet budget | `test_forensics.py` | API, forensics worker, authorised linking |

## 4. Change policy

* **Additive** (new optional field, new enum value accepted on input): allowed in `V1`, noted in the change log, no
  version bump of the model. Consumers must tolerate unknown-but-optional fields by construction (they are typed).
* **Breaking** (remove/rename a field, change a type, tighten validation, change semantics): add `XV2` alongside
  `XV1`, adapt producers first, keep `V1` accepted for one release, record the migration in the change log.
* Approvals: integration owner + every affected module owner. Contract PRs contain only `nextrace/contracts/`, docs and
  tests.
* The ATT&CK vocabulary (`TechniqueRef.attack_version`, default 20.0 released 2026-10-13) is a data version, not a
  contract version; bump it in data, not in code.

### Change log

| Date | Change | Kind | Approvers |
|---|---|---|---|
| 2026-10-28 | Backend contracts introduced: observations, temporal, models, findings, forensics, response, ops, ports, errors | additive (new modules) | integration (initial) |
| 2026-10-28 | `PredictionV1.host_ids` (optional) so correlation can group by host | additive | integration (initial) |
| 2026-10-28 | `SimulationRequestV1.start_technique_id` (optional) | additive | integration (initial) |
| 2026-10-28 | `TemporalSequencer.sequence(..., up_to=None)` so a round scores its own state | additive | integration (initial) |
