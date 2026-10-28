# Storage policy and pipeline-storage map

## 1. Components

| Component | Role | Why this and nothing more |
|---|---|---|
| PostgreSQL 18 | System of record for every structured record: flows, temporal states, model/feature registry, forecast history, alerts, investigations, evidence manifests, custody, holds, response actions, audit log | One transactional store covers every access pattern measured so far (append-heavy telemetry, point lookups by host, case workflows). Partition drops give cheap FIFO retention. Native `uuidv7()`, `inet`, arrays, JSONB and `sha256()` remove the need for extensions. |
| Redis 7+ / Valkey | Bounded cache of the most recent temporal states per sensor, current-forecast snapshot, pub/sub channel for WebSocket live updates | Only what the live dashboard reads. Every key has a TTL, every window is trimmed to `NEXTRACE_CACHE_MAX_STATES`; it is rebuilt from PostgreSQL after loss. Redis persistence is irrelevant because nothing durable lives there. |
| Local object store (`nextrace/storage/object_store.py`) | Content-addressed files: PCAP segments, uploads, legal-hold exports, model weights, SHAP arrays, forensic artifacts, reports | Large binaries do not belong in rows. SHA-256 names give de-duplication and integrity verification. The interface is five methods so S3/MinIO with Object Lock can replace it. |

Not introduced (see decisions doc for the evidence): TimescaleDB, ClickHouse, Elasticsearch, a message queue.
Each is a documented trigger: adopt when a measurement, not a preference, demands it.

## 2. Data inventory and lifecycle

Retention values are configuration (`.env.example`); the baselines below are the defaults.

| Data | Producer | Transformation | Destination and format | Consumers | Retention / deletion | Preservation |
|---|---|---|---|---|---|---|
| Raw packets (live) | Capture sensor (Zeek/Suricata/NDR, not in this repo) | Headers-only capture (snaplen ≈ 96–128 B) continuously; full payload into a short ring | Object store `pcap/…` as pcap files; indexed by `pcap_segments` (sensor, time range, kind, snaplen, hash) | Forensic carving for cases | Headers 183 days or byte budget (`NEXTRACE_PCAP_BUDGET_BYTES`), oldest first; full payload 72 h; never a relational row | Legal hold increments `hold_count`; held segments are skipped by reclaim. Carved slices become evidence objects that retention never touches |
| Uploaded PCAP/PCAPNG/CSV | Analyst via UI | Size limit, media-type allow-list, filename sanitised, SHA-256 | Object store `upload/…`; `uploads` row | Forensic engine | Kept while the linked investigation is open; retention policy for orphaned uploads is TBD (default: keep) | Evidence of kind `upload` on a case |
| Flow records | Sensor adapter (Zeek `conn.log`, Suricata `flow`, CICFlowMeter CSV) | Contract validation (`FlowRecordV1`), host upsert, COPY | `flows`, daily range partitions; btree (src_ip, ts), (dst_ip, ts), (sensor, ts); BRIN on ts; partial index on community_id | State builder, investigations, model training exports | 183-day FIFO by `DROP` of the day partition | A pending legal hold on an overlapping range vetoes the drop; `preserve_hold` exports in-scope rows to an immutable gzip JSONL evidence object, after which the partition may go |
| Per-flow feature vectors | Feature extractor (future) | `real[]` tied to a `feature_schemas` row | `flows.features` (nullable) | Sequence/graph models | Same as flows | Same as flows |
| Hosts | Ingestion | IP + HMAC-SHA256 pseudonym | `hosts` | Edges, exports, explanations | Kept (small); pruning of hosts unseen for > 1 year is TBD | n/a |
| Temporal network states (primary analysis unit) | State builder (`services/states.py`) from flows | `date_bin` aggregation per (sensor, window); 10 window-level features; summary JSON | `temporal_states`, daily partitions, unique (sensor, window_start, window_seconds) | Forecast engine (sequence input), dashboard, investigations | 183 days | Exported with legal holds |
| State graph edges | State builder | host→host aggregates with 5 edge features | `state_edges`, daily partitions, FK to the state | GNN training/inference, lateral-movement views | 14 days (rebuildable from flows) | Rebuildable; not preserved separately |
| Recent states (live) | State builder → cache | `TemporalStateV1` JSON | Redis ZSET `nt:v1:states:{sensor}` scored by window start | WebSocket fan-out, dashboard | `max_states` entries, TTL 1 h | Never; PostgreSQL is the source |
| Feature schemas, datasets, model versions | ML engineering | Canonical JSON hash; artifacts in object store | `feature_schemas`, `datasets`, `model_versions` | Every run references them | Permanent (provenance) | n/a |
| Forecast runs, predictions, progression steps, explanations | Forecasting engine (LSTM+attention, GNN, SHAP, LLM) | `ForecastResultV1`; input fingerprint (sha256 of state ids + model + horizon) | `forecast_runs` and children; large SHAP arrays as `shap/…` objects referenced by hash | Dashboard (`forecast_current`), alerts, investigations, model evaluation | 365 days for runs nothing references; runs linked to alerts, cases, feedback, actions or simulations are kept | Immutable by trigger; deletion only by the retention job |
| Current forecast pointer | `record_run` | upsert | `forecast_current` (one row per sensor) + Redis snapshot | Dashboard | Overwritten by the next completed run | History stays in `forecast_runs` |
| Simulations | Analyst "what if" | Scenario JSON, result artifact | `simulations`, `progression_forecasts.simulation_id` | Dashboard | Same as forecasts | |
| Analyst feedback | Analyst | verdict | `analyst_feedback` (`eligible_for_training = false` by default) | Triage quality reports; a reviewed, separate training process only when flagged | Permanent | |
| Alerts | Backend from predictions above threshold | | `alerts` | SOC triage, SIEM export (future) | Permanent while referenced; policy TBD | |
| Investigations, links, grants | Analysts/DFIR | | `investigations`, `investigation_links`, `case_grants` | Authorisation, reporting | Permanent | |
| Evidence items and custody events | DFIR via `services/investigations.py` | Hash, manifest, custody row per acquire/verify/access/export/release | `evidence_items`, `custody_events` (append-only), objects | Investigations, legal | Permanent; objects referenced by evidence are never reclaimed | Legal hold |
| Forensic analyses and findings | Forensic engine (historical pipeline) | Artifacts to object store; structured findings | `forensic_analyses`, `forensic_findings` | Linked to cases via `investigation_links` when authorised | With the case | |
| Response (firewall) actions and events | Analyst/system proposal → connector → verifier | State machine in DB trigger; every transition appended to `response_action_events` | `response_actions`, `response_action_events` | SOC, audit, dashboard | Permanent | Append-only events |
| Audit log | Every service call | Hash chain computed in DB | `audit_log` | Compliance, incident review | 730 days (deletion only by retention job; chain verifiable over the remainder) | |

## 3. End-to-end pipeline map

```
 Sensor (Zeek/Suricata/NDR) ──flows (FlowRecordV1)──▶ ingest.ingest_flows ──COPY──▶ flows (partition per day)
        │                                                   │
        │ headers-only pcap / full-payload ring             └─▶ hosts (ip + pseudonym)
        ▼
 pcap.register_segment ──▶ object store + pcap_segments
                                                        states.build_states (date_bin windows)
                                                                │
                                                                ├─▶ temporal_states, state_edges
                                                                └─▶ StateCache.push_state ──▶ Redis window + live channel
 Forecasting engine (gRPC) ◀── recent states (cache; warm from DB on miss)
        │  ForecastResultV1 (predictions, progression, SHAP/LLM explanations)
        ▼
 forecast.record_run ──▶ forecast_runs + predictions + progression_forecasts + explanations (immutable)
        │                 └─▶ forecast_current (pointer) ──▶ Redis snapshot ──▶ dashboard
        ▼
 alerts ──▶ analyst triage ──▶ investigations.open_case ──▶ case_grants (metadata / full_pcap)
                                     │
                                     ├─▶ evidence: carve_pcap_evidence / add_evidence ──▶ objects + custody_events
                                     ├─▶ legal hold: place_hold ──▶ preserve_hold ──▶ flow_export evidence
                                     ├─▶ forensic_analyses over uploads/evidence ──▶ forensic_findings ──▶ investigation_links
                                     └─▶ response.propose ──▶ authorize (second person) ──▶ execute ──▶ verify ──▶ expire ──▶ remove
 retention.enforce (daily) ──▶ drop old partitions (unless pending hold) · reclaim pcap (age, budget, never held) · trim forecasts · verify objects
```

### What happens after a forecast or detection

1. A completed run becomes the current forecast; predictions above the alert threshold create `alerts`.
2. An analyst acknowledges or escalates the alert and opens an investigation; the opener has metadata
   access to the case, and a DFIR/admin user grants others access with an expiry and a reason. Reading
   packet payloads requires a separate `full_pcap` grant that the recipient cannot give themselves.
3. Evidence is carved from retained captures or exported from flows/states; each acquisition, verification
   and access is a custody event; the object hash is re-verified before every access.
4. A legal hold freezes FIFO expiry for a scoped range and sensor; the hold is approved by a second person
   and, once preserved into an evidence object, lets normal retention resume.
5. A response action is proposed (by the system from a forecast, or by an analyst), authorised by a
   different person, executed by the firewall connector, and then verified independently (rule read-back,
   probe, or traffic observation). Only `verified` counts as enforced; `executed` does not. Every action
   carries an expiry; `expire-actions` flips verified actions past their expiry so the connector removes
   the rule and a second verification confirms removal.
6. Analyst feedback on predictions is recorded but is not used for model adaptation unless explicitly
   flagged and consumed by a reviewed training process.

## 4. Formats, indexes, partitioning, caching

- Keys are `uuidv7()`: time-ordered, so B-tree inserts are append-mostly (RFC 9562 §6.11).
- `flows`, `temporal_states`, `state_edges` are range-partitioned by day. `ensure-partitions` pre-creates
  `NEXTRACE_PARTITION_DAYS_AHEAD` days; an insert for a day without a partition fails loudly rather than
  landing in a default partition that retention could never reason about.
- Time-range scans use BRIN (24 KB for 220 k rows in the benchmark versus 8.9 MB for the B-tree primary
  key). Host lookups use B-trees on (ip, ts): p50 0.33 ms, p95 0.48 ms on 200 k rows.
- Indexes are 49 % of flow storage (benchmark). Dropping the `(sensor_id, ts_start)` index is the first
  lever if growth outpaces the window; the second is a columnar cold tier (decisions doc).
- Enumerations are `text` + `CHECK`, so adding a state is a constraint change, not a type rebuild.
- Redis: ZSET per sensor, score = window start; `ZREMRANGEBYRANK` keeps the newest N; `EXPIRE` refreshed on
  every write; same-window rebuilds replace the earlier member. Recommended server config:
  `maxmemory` set, `maxmemory-policy allkeys-lru`. Live events carry ids and counters, never packet bytes.
- Object store paths are `kind/aa/bb/<sha256>`; writes go to a temp file, are fsynced, renamed atomically
  and made read-only; paths are validated to stay under the root; symlinks are refused.

## 5. Legal holds

- `place_hold(case, scope_start, scope_end, reason, requested_by, approved_by, sensor?, host_ips?)`:
  requester and approver must differ (CHECK), approver must be DFIR/admin, PCAP segments overlapping the
  range become `held`.
- While `pending`, `retention.enforce` skips any partition that overlaps the range (reported in
  `skipped_for_hold`) and never reclaims held segments.
- `preserve_hold` exports every in-scope flow and state (`row_to_json`, gzip JSONL) into an immutable
  evidence object with a custody record, then marks the hold `preserved`; retention may then drop the
  partitions. `release_hold` (DFIR/admin) decrements segment hold counts.
- Objects referenced by any evidence item are excluded from reclaim regardless of hold state.

## 6. Backups and recovery

Nothing durable lives in Redis, so backup covers PostgreSQL and the object store, and they must be
restored to a consistent pair.

1. PostgreSQL: `wal_level=replica`, `archive_mode=on`, an `archive_command` that returns zero only on
   success and refuses to overwrite, `archive_timeout=60`. Base backups with pgBackRest (full weekly,
   incremental daily, repository encryption on, retention of two full sets) or `pg_basebackup --incremental`
   on PostgreSQL 17+. `pg_dump` is for logical exports only; it is not a recovery mechanism.
2. Object store: nightly `rsync`/`robocopy /MIR` of `kind/` directories to a second volume or an
   S3/MinIO bucket with Object Lock. Because objects are content-addressed and immutable, incremental
   copies are trivial and a copy can be verified with `nextrace.cli verify` against the same database.
3. Recovery order: restore the database to a point in time, then confirm every `objects` row with
   `deleted_at IS NULL` is present and verifies (`verify` exits 2 otherwise). A missing object is
   reported, never silently recreated.
4. Restore drill: quarterly, restore to a scratch cluster, run `alembic current`, `verify`, and the test
   suite against it. The drill result is itself an audit entry (`backup.restore_drill`).
5. Recovery objectives are a deployment decision (TBD); with `archive_timeout=60` the database loss
   window is about a minute; object-store loss window equals the sync interval.

## 7. Security controls (OWASP Top 10:2025 mapping)

| Risk | Control in this layer | Tested |
|---|---|---|
| A01 Broken access control | Deny-by-default `has_access`; case-level grants with expiry, revocation and a two-person rule; `full_pcap` separate from `metadata`; denied attempts audited | tests/test_evidence_authz.py |
| A05 Injection | Only bound parameters; identifiers are code constants; contracts whitelist characters for names, services, filenames; hostile strings tested against filters and `inet` casts | tests/test_ingest_states.py, test_contracts.py |
| A04 Cryptographic failures | API keys stored as SHA-256 only; IP pseudonyms are HMAC-SHA256 with a 32+ char pepper from the environment; secrets never in logs (`RedactingFilter`, `Settings.safe_dict`) | test_object_store_security.py |
| A08 Software/data integrity | Content addressing, verification before every evidence access, append-only triggers, hash-chained audit log, write-once decision fields on response actions | test_forecast_audit.py, test_response_actions.py |
| A09 Logging and alerting | Audit entries for grants, access, denials, evidence, holds, retention, response transitions; chain verification in `verify` | test_forecast_audit.py |
| A02 Misconfiguration | Validated settings (fail fast on weak pepper or wrong driver); least-privilege roles in `scripts/create_roles.sql` | nextrace/config.py |
| A10 Exceptional conditions | Rejected records are counted with messages, never echoed; integrity failures refuse access instead of serving bytes; retention reports what it skipped | tests |
| Uploads | Media-type allow-list, filename regex, size limit setting, rename to hash, outside any web root | schema CHECKs |
| Deserialization | JSON only; no pickle anywhere in the storage path | by construction |

Not yet implemented (out of this layer): HTTP authentication middleware, TLS termination, rate limiting.
Row-level security is deliberately not enabled: access decisions are case-scoped and evaluated in one
function with an audit trail; RLS would be a second, harder-to-test policy surface.

## 8. Configuration

| Variable | Default | Meaning |
|---|---|---|
| `NEXTRACE_DATABASE_URL` | required | SQLAlchemy URL (psycopg2) |
| `NEXTRACE_REDIS_URL` | redis://127.0.0.1:6379/0 | Cache |
| `NEXTRACE_OBJECT_STORE_ROOT` | ./var/objects | Object store root |
| `NEXTRACE_PSEUDONYM_PEPPER` | required, ≥ 32 chars | HMAC key for host pseudonyms |
| `NEXTRACE_FLOW_RETENTION_DAYS` / `STATE_RETENTION_DAYS` | 183 | Six-month metadata FIFO |
| `NEXTRACE_STATE_EDGE_RETENTION_DAYS` | 14 | Derived edges |
| `NEXTRACE_FORECAST_RETENTION_DAYS` | 365 | Unreferenced forecast history |
| `NEXTRACE_AUDIT_RETENTION_DAYS` | 730 | Audit log |
| `NEXTRACE_HEADER_PCAP_RETENTION_DAYS` | 183 | Headers-only captures |
| `NEXTRACE_FULL_PCAP_RETENTION_HOURS` | 72 | Full-payload ring |
| `NEXTRACE_PCAP_BUDGET_BYTES` | 100 GiB | Oldest-first reclaim threshold |
| `NEXTRACE_STATE_WINDOW_SECONDS` | 10 | Temporal state window (tunable; stored on each state) |
| `NEXTRACE_CACHE_MAX_STATES` / `CACHE_TTL_SECONDS` | 360 / 3600 | Redis bounds |
| `NEXTRACE_UPLOAD_MAX_BYTES` | 2 GiB | Upload limit |

## 9. Integration assumptions and gaps

- No capture, adapter, model, API or UI code exists in the repository. The contracts in
  `nextrace/contracts/v1.py` are the integration surface; adapters must emit `FlowRecordV1`, the forecasting
  engine must return `ForecastResultV1`, the firewall connector must call `record_execution` and then
  `record_verification` with a `VerificationResultV1`.
- Packet capture, packet loss and capture-to-storage latency cannot be measured here; the 2.5 Gbps target
  remains a benchmark target, not a result.
- Replaying historical datasets (e.g. CIC-IDS2017) as live traffic requires re-basing timestamps at
  ingestion; otherwise their partitions are older than the retention window and will be dropped. Historical
  analysis belongs in the forensic pipeline (`forensic_analyses`), not in `flows`.
- Zeek and Suricata must share the same Community ID seed for cross-sensor correlation.
