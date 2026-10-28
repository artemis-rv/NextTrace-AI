# Algorithm and architecture decisions

Final deliverable. Each decision lists the alternatives, the evidence (see research.md for sources and
dates), what was selected, and the trade-off accepted. "Measured" means a number produced in this
repository; "reported" means a number from a cited source.

## 1. Storage architecture

### D1. PostgreSQL 18 as the single system of record

| Alternative | Evidence | Verdict |
|---|---|---|
| PostgreSQL + partitioning (selected) | Partition drop is the documented cheap retention path; COPY measured at 37 100 flows/s on a laptop-class Windows machine; host lookup p50 0.33 ms; native `uuidv7()`, `inet`, arrays, `sha256()`; transactional workflows (cases, holds, actions) need ACID anyway | Meets every measured requirement with one engine |
| TimescaleDB | Compression and retention policies are TSL-licensed features; extension not available in the local build; adds upgrade coupling | Rejected for now: nothing measured requires it |
| ClickHouse for flows | Reported 517 M VPC flow rows in 2.30 GiB (≈ 4.8 B/row) vs. our measured 343 B/row; but updates are heavy mutations, sorting-key columns immutable, and it would be a second database with its own backup, auth and retention | Deferred: adopt as a *cold tier* only when the measured flow rate makes the six-month window infeasible in PostgreSQL (trigger: sustained > ~2 000 flows/s, which is ≈ 10 TB per window) |
| Elasticsearch/OpenSearch (Arkime-style sessions) | Hot/warm/cold tiering is mature, but we have no full-text requirement; Arkime itself keeps packets on disk and only metadata in the index | Rejected: no full-text search need |

Trade-off accepted: at high flow rates PostgreSQL's row overhead (49 % of it indexes) is the limiting
factor. The first lever is dropping the `(sensor_id, ts_start)` B-tree (BRIN covers time scans); the second
is the cold tier above.

### D2. Packets are files, flows are rows

Arkime and Stenographer, the two reference full-packet systems, both keep packets as large files deleted
oldest-first, with an index elsewhere and a "locked" mechanism to protect files. At 2.5 Gbps full capture
would be ≈ 27 TB/day (Arkime's reported 11 TB/day per Gbps). Per-packet rows are therefore not an option.

Selected: headers-only capture segments (small snaplen) retained six months subject to a byte budget;
full-payload capture as a 72-hour ring; both content-addressed and indexed by `pcap_segments`; evidence
slices carved into new immutable objects on case authorisation. Flows (Zeek `conn.log`-shaped records,
which Suricata `flow` and CICFlowMeter outputs map onto) are the relational unit.

Trade-off: packet-level questions older than 72 h can only be answered from headers or from slices that
a case preserved in time. This is the same trade Stenographer and Arkime users make.

### D3. Daily range partitions, BRIN on time, B-trees on hosts, uuidv7 keys

Measured on 220 k rows: BRIN(ts_start) 24 KB vs. 8.9 MB for the B-tree primary key; range count over five
minutes 32 ms; host lookups sub-millisecond via (ip, ts) B-trees. Daily partitions give 183 partitions per
table for the six-month window, well inside the documented "few thousand" comfort zone, and let retention
drop a day without a VACUUM debt. uuidv7 keys keep inserts append-mostly (RFC 9562).

Rejected: weekly partitions (coarser FIFO, bigger drops under holds); a DEFAULT partition (would silently
absorb bad timestamps that retention could never reason about); hash partitioning (defeats pruning).

### D4. Redis as a bounded window, never a source of truth

Redis docs: TTLs are cleared only by overwrite/delete; `allkeys-lru` is the recommended default; RDB loses
minutes, AOF `everysec` loses a second. Selected: one ZSET per sensor trimmed to N entries with a refreshed
TTL, a current-forecast key with TTL, pub/sub for live events, and `warm()` from PostgreSQL. Tested: trim,
replacement of a rebuilt window, recovery after `flushall`.

Rejected: Redis Streams (`MAXLEN` trimming is approximate and gives no time-based retention); storing
forecasts only in Redis (would violate the immutable-history requirement); Valkey vs. Redis is a licensing
choice with identical semantics for this use (both supported by the client).

### D5. Content-addressed object store with a five-method interface

SHA-256 naming gives de-duplication, integrity checks on every access, and a trivially incremental backup.
Writes are temp-file + fsync + atomic rename + read-only. The interface (`put_stream`, `open`, `verify`,
`delete`, `exists`) is what S3/MinIO Object Lock would implement later; compliance-mode WORM and legal-hold
flags map directly onto `evidence_items` and `legal_holds`.

## 2. Integrity, authorisation and workflow decisions

### D6. Immutability by trigger, deletion only by a marked retention session

Forecast history, custody events, response events and the audit log reject UPDATE always and DELETE
unless the session set `nextrace.retention_job = 'on'`. Tested for all four tables. The alternative,
relying on role grants alone, fails against a mis-scoped credential; both are used (`create_roles.sql`).

### D7. Hash-chained audit log computed in the database

Each entry's hash covers the previous hash and its canonical fields; an advisory lock serialises inserts
so the chain cannot fork. Tested: a forged edit made with the trigger disabled is detected by
`nt_audit_verify()`. Rejected: hashing in the application (any writer bypassing the service could break
the chain unnoticed).

### D8. Case-level authorisation with two-person rules

Deny by default; grants have an expiry, a reason and a granter who must differ from the grantee; packet
access needs `full_pcap`, which `metadata` does not imply, and admins do not get it implicitly; denials
are audited. Holds and response authorisations also require two different people. This follows the
OWASP authorisation guidance (object-level checks, deny by default, log failures) and the SWGDE custody
requirements (who, when, every transfer).

### D9. Legal holds: veto first, preserve, then let FIFO resume

NIST SP 800-92 distinguishes retention from preservation. A pending hold vetoes partition drops over its
range; `preserve_hold` copies the in-scope rows into an immutable evidence object with a custody record;
preserved holds no longer block retention. Tested end-to-end. Rejected: copying held rows into a separate
"held" table (duplicates schema, still mutable); keeping whole partitions forever (unbounded).

### D10. Firewall actions: executed is not enforced

SP 800-41 requires testing that rules work, not just reviewing them. The state machine separates
`executed` (the connector's API returned success) from `verified` (an independent read-back, probe or
traffic observation), and only `verified` is `enforced` (a virtual generated column). Every block has a
mandatory expiry; expiry leads to removal and a second verification that the rule is gone. Tested across
the full lifecycle, including retry after a failed verification and rejection of illegal transitions in
both the service and the database.

### D11. Pseudonymise, do not hash, identifiers that must stay searchable

IPs stay as `inet` in `flows` because investigations and firewall actions must search and act on them.
What leaves the system (explanations, exports to the LLM, reports) uses HMAC-SHA256 pseudonyms with an
environment pepper, stable for joins, not reversible without the key. Plain hashing was rejected: the IPv4
space is small enough to invert a keyless hash by brute force.

### D12. Analyst feedback is recorded, not learned from

`eligible_for_training` defaults to false and no code path reads it. Adaptation from unreviewed feedback
would let a single analyst's error (or an attacker influencing triage) retrain the detector.

## 3. Algorithm choices and what the storage provides for them

The brief fixes LSTM + attention for malicious-activity classification and a GNN/GAT (or research-selected
alternative) for progression. The storage layer must make the data they need available without presuming
unresolved details. Where the literature disagrees, the design stores both representations so the model
team can decide empirically.

### A1. Temporal network state = fixed-length window snapshot per sensor

| Alternative | Evidence | Verdict |
|---|---|---|
| Discrete snapshots (selected as the primary unit) | DySAT and EvolveGCN consume snapshot sequences; PPT-GNN reaches practical detection with 5 s windows and a 5-window memory; graph-NIDS replication studies show window length is a first-order hyper-parameter with best values from 75 s to 2 h | Store one state per (sensor, window) with `window_seconds` on every row, defaulting to 10 s; keep the window tunable, never assume it |
| Continuous event stream (TGN/TGAT) | TGN keeps per-node memory and consumes timed edges; the flow table *is* that event stream | Supported without extra storage: `flows` ordered by `ts_start`, hosts as stable node ids |
| Whole-dataset graphs (E-GraphSAGE, Anomal-E) | Strong offline results, but PPT-GNN's authors note full-dataset graphs cannot be assumed online | Only for offline training from exported datasets |

Cardinality: states are cheap (8 640/day/sensor at 10 s); edges are not bounded by design and are kept
14 days as a rebuildable derivative. Edge count per window on real traffic is a required measurement.

### A2. Sequence model input

The CIC-IDS2017 sequence study found T = 20 steps best or indistinguishable from best with 76 features per
step. A 10-second window gives a 200-second context at T = 20; the Redis window of 360 states (one hour)
and `recent_states()` from PostgreSQL both exceed it. Per-flow features (`flows.features`, tied to a
`feature_schemas` row) support the alternative of 5-tuple-grouped flow sequences.

### A3. Graph model input

E-GraphSAGE and Anomal-E place flow features on edges and give nodes constant features; `state_edges`
stores per-pair aggregates with a feature array and stable `host_id`s, which is the per-window version of
that construction. Node features can be added as a column without redesign.

### A4. Progression forecasting

MITRE CTID's Technique Inference Engine predicts next techniques from the *set* of observed techniques
with a recommender trained on CTI reports; kill-chain and stage-wise GNN papers feed earlier-stage
detections into later-stage prediction. The schema stores observed `technique_ids` on every prediction
and `(step, technique, tactic, target_host, probability, expected_within_s)` per progression step, so a
TIE-style recommender, a kill-chain classifier or a host-graph model can all write the same records.
Scenario simulation reuses the same rows under a `simulation_id`. ATT&CK ids are validated against the
`T####(.###)` format; ATT&CK itself (v20.0, STIX bundles, biannual releases) is reference data loaded from
the versioned bundle, not stored per prediction.

### A5. Explanations

SHAP docs: attributions sum to output minus base value and explain correlations, not causes. Explanations
are stored as top-k attributions in JSONB with full arrays as objects, a hash of the LLM prompt, and a
mandatory disclaimer. Hosts in explanation content are pseudonyms.

## 4. Validation results

Environment: Windows 11, Python 3.12.5, PostgreSQL 18.3 (throwaway cluster, port 5433, trust auth),
Redis faked with fakeredis 2.40 (no Redis server was available on the machine).

```
python -m pytest            -> 49 passed (schema/migration round trip, contracts, ingestion, state build,
                               injection resistance, authorization, evidence custody and tamper detection,
                               PCAP carving incl. pcapng, retention, legal holds, PCAP budget/age/hold,
                               forecast immutability, audit chain, Redis bounds/TTL/recovery, firewall states)
python -m alembic upgrade head / downgrade base / upgrade head -> clean on an empty database
python -m nextrace.cli config | ensure-partitions | verify | expire-actions | retention -> all run
python bench/benchmark.py --flows 200000 -> bench/results/20261028T074801Z.json
```

| Benchmark (200 000 synthetic flows, 2 000 clients × 500 servers) | Result |
|---|---|
| Contract validation | 73 000 flows/s (2.72 s) |
| COPY load (after validation) | 37 100 flows/s |
| End-to-end ingest incl. host upsert and partition check | 34 800 flows/s |
| Batched multi-row INSERT (same data) | 6 600 flows/s |
| Temporal state + edge build, 100 s of traffic (11 states, 66 000 edges) | 5.2 s |
| Host lookup by IP over one hour | p50 0.33 ms, p95 0.48 ms |
| Five-minute range count | 32 ms |
| Storage per flow incl. indexes | 343 B (49 % indexes) |
| Storage per edge | ≈ 300 B |

Not measured, and why: packet loss and capture-to-storage latency (no capture path exists in the
repository); pipeline latency through the forecasting engine (no engine); real Redis throughput (no server);
the 2.5 Gbps target (benchmark target only). The state-build figure is from a single-threaded run on a
laptop and includes edge construction for an unrealistically dense synthetic graph.

## 5. Remaining risks, assumptions and research-dependent items

1. **Flow rate at 2.5 Gbps is unknown.** At 343 B/flow, 1 000 flows/s fills 5.4 TB per six months;
   10 000 flows/s fills 54 TB. Measure early; the cold-tier decision (D1) hinges on it.
2. **Edge cardinality** per window is unbounded; a busy sensor could produce 10⁴–10⁵ edges per 10 s window.
   Edge retention is short for this reason; capping or sampling is a model-team decision.
3. **Window length** is an assumption (10 s). The cited studies show it moves average precision by tens of
   percent; the model team must sweep it on this deployment's traffic and may need overlapping windows.
4. **Feature sets** (`WINDOW_FEATURES_V1`, `EDGE_FEATURES_V1`) are placeholders; the registry allows new
   versions without schema changes.
5. **Firewall verification** assumes the connector can read back rules or probe; where it cannot, the
   `manual` method requires a human to record what was observed, and the action stays `executed`
   (unenforced) until then.
6. **Legal-hold export format** (gzip JSONL of `row_to_json`) is self-describing but not a court-recognised
   container; a hashed manifest and custody record accompany it, which is what SWGDE requires.
7. **No HTTP layer exists**: authentication of callers, TLS and rate limits are outside this work; the
   `users.api_key_hash` column and role model are ready for it.
8. **Retention edge cases**: hosts never seen again, orphaned uploads, closed-case alerts are kept by
   default pending a compliance decision.
9. **Local PostgreSQL password** was not available, so tests ran on a throwaway cluster; the migration and
   suite should be re-run against the target instance.
10. **Research sources marked UNVERIFIED** (M-21-31's 72-hour PCAP figure, SP 800-86/800-41 wording) were
    read only as excerpts; defaults derived from them are conservative and configurable.
