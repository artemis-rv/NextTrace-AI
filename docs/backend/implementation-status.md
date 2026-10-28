# Implementation status

Date: 2026-10-28. Everything below was run on this machine against a throwaway PostgreSQL 18 cluster; Redis was
faked in tests and absent in the smoke run (the pipeline runs without the live cache and says so in `/health`).

## 1. Status by component

| Component | Owner | Status | Evidence |
|---|---|---|---|
| Contracts (`nextrace/contracts/*`), ports, errors | integration | **implemented** | `test_backend_contracts.py` (honesty rules, ordering, isolation, port conformance) |
| Bounded queues, health registry, rate limiter, auth, JSON logging, uuid7 | integration | **implemented** | `test_capture_parsing.py::test_bounded_queue_policies`, `test_api_security.py` |
| Header decoder + flow assembler (`nextrace/parsing`) | Person 4 | **implemented** | decode of TCP/UDP/VLAN/IPv6, malformed/truncated handling, conn_state approximation, timeouts, eviction |
| `PcapReplaySource` | Person 4 | **implemented** | ordered batches, honest health (drop counters `None`) |
| `LiveCaptureSource` | Person 4 | **template** — structure, queue policy, health; `_reader()` raises `NotImplementedError` | `test_live_source_is_a_template_not_a_fake` |
| `StreamingSequencer` (event time, watermark, allowed lateness, refire/drop) | Person 2 | **implemented** | `test_temporal.py`; Python features equal the SQL builder's on the same flows |
| `mlcommon.splits`, `mlcommon.calibration` | Person 2 | **implemented** | leakage checks raise; temperature scaling lowers NLL and ECE on synthetic logits |
| LSTM+Attention model, artifact save/load (`weights_only`), training script | Person 2 | **implemented, untrained on real data** | shapes, masking, reproducible two-run training on a synthetic set (identical AUC), schema-mismatch refusal |
| `HeuristicBaselineDetector` | Person 2 / integration | **implemented** (rules, labelled `heuristic_baseline`) | e2e replay produces T1046 alerts for the synthetic scan |
| `TorchDetector` | Person 2 | **implemented**, no production artifact | loads the test-trained artifact from the object store |
| Graph builders (DB, in-memory) | Person 1 | **implemented** (not exercised end-to-end) | import + contract validation only |
| GAT layer / `GATProgressionModel` | Person 1 | **template with working forward pass** | shape test |
| `TorchGATForecaster` | Person 1 | **template** (raises) | — |
| `TransitionTableForecaster` | Person 1 / integration | **implemented**, unfitted by default | fit/forecast/serialise tests; `unavailable` until fitted |
| `MonteCarloSimulator`, `TechniqueTableTransition` | Person 1 | **implemented** over the transition baseline | determinism with seed, interventions, refusal without start technique |
| `RSSMWorldModel` | Person 1 | **template** (refuses to instantiate) | `RESEARCH REQUIRED` |
| Correlator (dedupe, grouping, pattern coverage, delayed matching) | integration | **implemented**, in-memory state | `test_correlation_explanation.py` |
| Risk scorer | integration | **implemented**, weights unvalidated | inputs/weights/formula recorded |
| SHAP explainer | integration | **implemented**, not wired by default (needs trained detector + background) | not tested end-to-end |
| LLM explainer with guardrails | integration | **implemented**, off by default | injection text refused, benign text accepted, prompt hash recorded |
| Policy engine | integration | **implemented** | rule tests incl. determinism, dry-run, auto-allow off |
| Response manager (authorise, execute, verify, retry, escalate, expire, remove, revoke, extend) | integration | **implemented** | full lifecycle tests with a faulty connector and a dry-run connector |
| Connectors | integration | `DryRunConnector`, `InMemoryConnector` **implemented**; `NftablesConnector` **template, untested** | — |
| Alerts, feedback, investigation updates | integration | **implemented** | API tests |
| Forensic engine (uploads, jobs, scan/beacon/timeline rules, flow export, report, linking) | Person 3 | **implemented**; `ioc_match`/`custom` not implemented (reported in limitations) | `test_forensics.py` |
| API | integration | **implemented** | `test_api_security.py` |
| Workers (`bootstrap`, `replay`, `api`, `forensics`, `maintenance`) | integration | **implemented** | smoke run below |
| Composition root | integration | **implemented** | every test builds a context through it |

## 2. Test results

Command: `NEXTRACE_TEST_DATABASE_URL=postgresql+psycopg2://postgres@127.0.0.1:5433/nextrace_test python -m pytest -p no:warnings -q`

Result: **99 passed, 0 failed** (49 storage-layer tests from the database work plus 50 backend tests), in about two
minutes. Warnings: pytest-asyncio loop-scope deprecation; a torch `float(loss)` warning in the training script.

| File | Covers |
|---|---|
| `test_backend_contracts.py` | results cannot fake completion; batch ordering; sequence/split validation; port conformance; **module isolation** (no cross-module imports; shared layers never import modules) |
| `test_capture_parsing.py` | decode (payload never copied), malformed/truncated/VLAN/unknown link, bidirectional assembly and conn_state, timeouts, table-full eviction, replay batches and health, queue policies (reject/shed/block), live-source template |
| `test_temporal.py` | date_bin-compatible binning, watermark closing, late refire and drop, gap reporting, **Python = SQL feature parity**, chronological split with embargo, causal sequence check, calibration |
| `test_models.py` | unavailable detector/forecaster; heuristic baseline; LSTM shapes/masking/artifact round-trip and refusal of pickled code; reproducible training; TorchDetector via object store with schema refusal; GAT shapes; transition table fit/forecast/serialise; simulator determinism, interventions, refusal; RSSM template refuses |
| `test_correlation_explanation.py` | dedupe counts, host vs sensor grouping, episode windows, prefix coverage, delayed matching and expiry, risk transparency and bands, prompt has no IPs, sanitiser flags, injection refused, null provider unavailable |
| `test_policy_response.py` | every policy rule, determinism, enforce refused in dev, full verified lifecycle through expiry/removal, accepted-but-not-enforced → retry → failed + escalation, refused command, dry-run never verified and closed at expiry, revocation, third-person capped extension, LLM/system-without-risk denied |
| `test_forensics.py` | upload signature/type/size/filename validation, job authorisation, scan+beacon+timeline findings with sequential numbering, report authorisation, case-scoped upload and authorised linking, failed job never left running |
| `test_pipeline_e2e.py` | replay → flows/states persisted → baseline runs → alerts → no proposals without host attribution; unavailable model records nothing; host-attributed detection yields a `proposed` dry-run action with policy rules recorded |
| `test_api_security.py` | 401 paths, minimal unauthenticated health, role checks, BOLA on cases, grants, admin-only audit with intact chain, signed updates, injection payloads rejected by typing, extra fields refused, response-action flow over HTTP, 413 body cap, 429 rate limit, service-only ingestion |

## 3. Smoke run (workers, real database, no Redis)

```
python -m nextrace.workers bootstrap --sensor-name demo --username demoadmin   -> sensor id, user id, API key (printed once)
python -m nextrace.workers replay --pcap demo.pcap --sensor-name demo
  {'batches': 2, 'flows_accepted': 521, 'states': 35, 'runs_recorded': 35, 'alerts': 1, 'proposals': 0, 'errors': 0}
  model_availability: detector=heuristic_baseline, forecaster=unavailable, world_model=template, explainer=unavailable
python -m nextrace.workers maintenance --once -> late_events 0, nothing due
API (TestClient over the same context): /health degraded (cache absent), dashboard/alerts/history/models answer, 401 without key, 422 on bad ids, audit chain intact
```

The demo pcap is synthetic (300 benign web flows, a 200-port SYN scan, a 20-beat beacon); the single alert is the
baseline's T1046 "scan_like" rule firing on the scan window. Wall time for the replay was about 4 s, dominated by
per-state inference rounds against PostgreSQL; this is **not** a throughput measurement.

## 4. Benchmarks

Only the storage benchmark exists (`bench/benchmark.py`, results in `docs/database/algorithm-and-architecture-decisions.md`:
COPY ≈ 37 k flows/s vs executemany ≈ 6.6 k flows/s, 343 B/flow including indexes). No capture, sequencer or model
throughput has been measured. The 2.5 Gbps target is untested; a packet-level benchmark needs a real capture host.

## 5. Unresolved research questions (also in the decisions document)

1. Window length and sequence length for this network (defaults 10 s / 20 states; literature shows large sensitivity).
2. Allowed lateness and correlation window/grace for real sensors.
3. Forecast horizon with measurable lead time.
4. Whether any dataset supports training a network-state world model; what its action space is.
5. Risk weights and severity bands; auto-allow threshold (auto-allow stays disabled).
6. A validated multi-stage pattern library (seed patterns are illustrative).
7. Calibration behaviour of the LSTM on real flows (ECE must be measured, not assumed).

## 6. Integration blockers

| Blocker | Owner | Unblocks |
|---|---|---|
| No labelled flow/state dataset for this environment | Person 2 (+ Person 4 for capture) | training the detector; measuring calibration; replacing the heuristic baseline |
| No multi-stage labelled sequences | Person 1 | fitting the transition table; GAT training; any world-model work |
| No privileged capture host | Person 4 | `LiveCaptureSource._reader`, drop counters, throughput benchmark |
| No staging firewall | integration | `NftablesConnector` test, `enforcement_mode=enforce` in staging |
| Asset inventory | integration | real `asset_criticality` (today: `hosts.asset_tag` convention `crit:0.9`) |
| Integration-owner assignment | team | contract approvals, release validation |
| Redis on the dev machines | integration | live window and pub/sub in local runs (tests fake it) |

## 7. Known limitations

* Correlator state is in-memory; a restart loses open (unmatched) groups. Alerts and runs are durable.
* The heuristic baseline attributes to the sensor, not a host, so it never triggers system proposals; host attribution
  needs a model (or rule) that names hosts (`PredictionV1.host_ids`).
* `enforce` mode requires `environment` staging/prod and a tested connector; the only shipped connectors simulate.
* `ShapExplainer` is not wired in composition (it needs a trained detector and a background set from the training split).
* Forensic rules are heuristics with configurable parameters; they are findings of basis `rule`, not detections of record.
