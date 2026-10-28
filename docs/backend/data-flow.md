# Data flow

## 1. Live path

```
packets ──decode──► PacketObservationV1 ──FlowAssembler──► FlowRecordV1 ──► FlowBatchV1
   │ (Person 4)                                                                 │
   │                                                                   queue.batches (bounded)
   │                                                                            ▼
   │                                   Pipeline.process_batch: ingest_flows (COPY) ─► flows table (6-month FIFO)
   │                                                           StreamingSequencer.ingest ─► closed TemporalStateV1
   │                                                           persist_states (upsert) ─► temporal_states
   │                                                           cache.push_states / publish ─► Redis window + nt:v1:live
   │                                                                            │
   │                                                                   queue.states (bounded)
   │                                                                            ▼
   │   Pipeline.process_state (one round per closed state):
   │     sequencer.sequence(up_to=state)      → StateSequenceV1 (gaps listed, never filled)
   │     detector.detect(InferenceRequestV1)  → DetectionResultV1   (Person 2)
   │     forecaster.forecast(req, detection)  → ProgressionForecastV1 (Person 1)
   │     explainer.explain(...)               → ExplanationResultV1 (optional; never evidence)
   │     forecast.record_run(ForecastResultV1)→ forecast_runs / predictions / progression_forecasts / explanations (immutable)
   │                                          → forecast_current (mutable pointer), Redis current forecast, live event
   │     correlator.correlate(...)            → CorrelatedEventV1 (dedupe, entity-time groups, pattern coverage)
   │     risk.score(event, asset_criticality) → RiskScoreV1 (inputs + weights recorded)
   │     emit_alert(AlertV1)                  → alerts (+ audit 'alert.emit', live event)
   │     high/critical + host entity          → ResponseManager.propose(system)  → policy → response_actions (status 'proposed')
   ▼
 rolling PCAP segments (storage.pcap.register_segment) — headers by default; full PCAP only where authorised
```

Timing: the sequencer closes a window when the sensor's watermark (max event time − allowed lateness) passes its end;
late flows inside the lateness bound re-fire the window (same `state_id`, DB upsert, cache replace); flows later than
that are counted and dropped. Every count is in `/health`.

## 2. Post-detection workflow

```
alert (new) ─ analyst ─► acknowledged ─► escalated ─► closed
   │
   ├─ link_alert ─► investigation (case-level authorization: opener, grants, admin metadata)
   │                   ├─ evidence: carve_pcap_evidence (full_pcap grant), uploads, forensic artifacts, custody events
   │                   ├─ legal hold: place → preserve → release (two-person; vetoes retention)
   │                   └─ findings: predicted | rule | analyst_confirmed (needs evidence) | forensic
   │
   └─ response action: proposed ─policy─► authorized (second person, role per decision) ─► executing ─► executed (command accepted)
                                                     │                                       │
                                                     └─ rejected                              ├─ verified (read-back says enforced)  ─► expired ─► removed ─► removal_verified
                                                                                              │        └─ extend (third person, capped)   revoke ─────┘
                                                                                              └─ verification_failed ─retry≤N─► failed (+ audit 'response.escalate')
   dry_run mode: stops at executed, marked unverified, closed as failed at expiry; nothing is ever enforced.
```

## 3. Historical path (separate from live)

```
analyst upload (API, size-bounded, signature-checked) ─► objects(kind=upload) + uploads(validated)
   └─ ForensicJobRequestV1 ─► forensic_analyses(queued) ─worker─► running ─► completed | failed
          run: verify hash → copy out → parse (shared nextrace.parsing) → rules (scan, beacon, timeline) → forensic_findings
               → artifacts (flow table) and ForensicReportV1 (object kind=report, result_sha256)
   └─ link_finding(finding, investigation, actor) ─ require_access(metadata) ─► investigation_links(forensic_finding)
```

The historical engine never reads live queues or live tables; it reads objects it was pointed at and writes its own
rows. The only bridge to live investigations is the authorised link.

## 4. Storage touchpoints

| Data | Written by | Store | Lifetime |
|---|---|---|---|
| flows | pipeline (`ingest_flows`) | PostgreSQL daily partitions | 183 days FIFO, legal holds veto |
| temporal states / edges | pipeline (`persist_states`), SQL builder | PostgreSQL daily partitions | 183 / 14 days |
| recent window, current forecast, live events | pipeline | Redis (bounded, TTL) | ≤ `CACHE_MAX_STATES`, `CACHE_TTL_SECONDS` |
| runs, predictions, progression, explanations | pipeline | PostgreSQL (immutable rows) | 365 days unless referenced |
| alerts, investigations, evidence, holds, actions, events | findings/response/forensics | PostgreSQL | case lifetime |
| PCAP segments, uploads, model artifacts, SHAP arrays, reports, exports | capture/forensics/training | content-addressed object store | budget FIFO (pcap), holds, case lifetime |
| audit log | every mutation | PostgreSQL hash chain | 730 days |

## 5. Dashboard and reporting queries

`DashboardSnapshotV1` (`GET /v1/dashboard/{sensor}`) is assembled from `forecast_current`, the latest state, the
Redis window count, open alerts, enforced actions, pending authorizations and model availability. History comes from
`GET /v1/forecasts/{sensor}/history` (immutable runs) and `GET /v1/states/{sensor}`. All list queries are bounded
(`limit ≤ 500`, cursors on uuidv7 ids, time spans ≤ 90 days).
