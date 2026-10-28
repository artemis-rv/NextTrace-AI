# Algorithm and architecture decisions (backend)

Final deliverable for the backend work. Each decision lists the alternatives considered, what was selected, the
evidence (see [research.md](research.md) for sources), trade-offs, and what remains open. Storage decisions D1–D12 and
algorithm notes A1–A5 from the database work are in
[../database/algorithm-and-architecture-decisions.md](../database/algorithm-and-architecture-decisions.md) and are not
repeated. **Research Required** marks a decision that is implemented as a configurable default without validation.

## 1. Architecture

### B1. Modular monolith with enforced boundaries, no broker
* **Alternatives:** microservices per module; monolith with a message broker (Kafka/Redis Streams); plain monolith.
* **Selected:** one codebase, one process type, four owned module packages plus an integration layer; modules talk only
  through `nextrace.contracts`; a test fails the build on cross-module imports; bounded in-process `asyncio` queues
  with explicit policies replace a broker.
* **Evidence:** Fowler's monolith-first observation; practitioner guidance that a modular monolith without enforced
  boundaries is not modular; the only fast producer (capture) is handled by a bounded queue with shed/block/reject.
* **Trade-offs:** a process crash loses in-flight queue items (everything persisted is safe); horizontal scaling means
  running more processes per sensor, not per stage. A broker is justified only by a measured need.

### B2. Contracts first, ports second, implementations last
* **Alternatives:** shared ORM models; each module defining its own input/output types.
* **Selected:** pydantic contracts with `extra="forbid"`, tz-aware times, regex allow-lists and bounded lists; `Protocol`
  ports per module; explicit composition root (`core.composition`) as the only place that instantiates modules.
* **Evidence:** the team-boundary rule in the brief (three teams, three formats, one person converting). Port
  conformance and isolation are tested, so a drift shows up in CI rather than in integration week.
* **Trade-offs:** some duplication between contracts and SQL (handled by the storage layer's reflection); every new
  field is a small PR with two approvals.

### B3. Honest model slots
* **Alternatives:** stub models returning random/constant predictions "for now"; disabling the pipeline without models.
* **Selected:** every result carries a status (`completed | unavailable | failed | refused`); non-completed results
  cannot carry predictions (validated); the pipeline records nothing when a slot is unavailable and counts it; a
  deterministic baseline labelled `heuristic_baseline` runs so the post-detection workflow can be exercised.
* **Evidence:** the brief's rule against fake predictions; graph-NIDS evaluations showing simple baselines compete with
  complex models under a fair protocol.
* **Trade-offs:** no alerts until a model or rule exists; the baseline's single rule (scan-like) produces only T1046.

### B4. Deterministic policy engine in front of every firewall action
* **Alternatives:** LLM-assisted triage deciding on actions; threshold-only automation; human-only.
* **Selected:** rules R01–R10 over numeric/enumerated inputs; decision + rules fired recorded in the audit log;
  dry-run default; auto-allow disabled until thresholds are validated; two-person rule in both DB and manager; role
  escalation for critical assets, isolation and repeated targets; duration caps.
* **Evidence:** NIST SP 800-207 split of policy engine / enforcement point; CISA/ASD SIEM-SOAR guidance (secondary) on
  automation acting on inaccurate signals; OWASP LLM06 excessive agency.
* **Trade-offs:** slower response in exchange for no unexplained blocks; thresholds (R09) are **Research Required**.

### B5. Executed is not enforced; dry-run never verifies
* **Alternatives:** trusting connector exit codes; marking dry-run actions as verified for demo purposes.
* **Selected:** connector `execute()` reports acceptance; `verify()` is an independent read-back; only `enforced=True`
  reaches `verified`; dry-run stops at `executed` and is closed as `failed` at expiry; bounded retries then escalation;
  expiry → removal → removal verified; revocation; third-person extension capped by policy.
* **Evidence:** NIST SP 800-41 (test that rules work); the database layer's state machine (D10).
* **Trade-offs:** more states to understand; the DB trigger and the manager encode the same machine (kept in sync by tests).

### B6. Historical forensics as a separate pipeline with one bridge
* **Alternatives:** reusing the live pipeline on uploaded files; separate storage for forensic results.
* **Selected:** the forensic engine reads objects (uploads, carved evidence), uses the shared parser, writes its own
  rows and report objects, and reaches investigations only through `investigations.link_object` under case-level
  authorization. Jobs run under `FOR UPDATE SKIP LOCKED`; failures are recorded on the row.
* **Evidence:** the brief's separation requirement; OWASP file-upload guidance.
* **Trade-offs:** no streaming of forensic results into live alerts (by design).

## 2. Algorithms

### A6. Temporal sequencing: event-time windows with allowed lateness — Research Required (parameters)
* **Alternatives:** processing-time windows; session windows per host; dropping all late data; unbounded buffering.
* **Selected:** fixed `window_seconds` bins (same `date_bin` rule as the SQL builder), per-sensor watermark = max event
  time − allowed lateness, late flows within the bound re-fire the window idempotently, later ones are counted and
  dropped; sequences list missing windows instead of filling them.
* **Evidence:** Flink's allowed-lateness semantics; window sensitivity results (38.3 % AP swing) argue for making the
  window a stored, configurable parameter; the NetFlow review's deployment constraints (bounded state).
* **Open:** window length, allowed lateness and sequence length for this network (defaults 10 s, 30 s, 20).

### A7. Detection: LSTM + additive attention over state sequences, calibrated — Research Required (data)
* **Alternatives:** per-flow classifiers (ignore multi-flow structure); Transformers (data-hungry); GRU without
  attention; tree ensembles on aggregated features.
* **Selected:** `LSTMAttentionClassifier` (binary head + category head + attention weights for explanation only),
  masked attention for gaps, standardisation fitted on the training split, temperature scaling fitted on validation,
  class-imbalance via `pos_weight`, chronological split with embargo, metrics on the test split only, artifacts loaded
  with `weights_only=True`.
* **Evidence:** attention-augmented RNNs are current practice (2025 hybrid paper, abstract only); Arp et al. pitfalls;
  Guo et al. calibration; T=20 result on CIC-IDS2017.
* **Open:** no training data for this environment; calibration must be measured; category taxonomy and
  technique mapping (`technique_map` in the artifact) depend on labelled data. Until then the heuristic baseline runs.

### A8. Progression: technique-transition baseline now, GAT later — Research Required (model)
* **Alternatives:** HMM/automaton forecasters (rSPDFA); recommender over technique sets (MITRE TIE); GAT/dynamic GNN
  over host graphs (Jbeil-style link prediction); no progression model.
* **Selected:** first-order technique transition table with additive smoothing and median delays, fitted only on
  provided campaign sequences (`unavailable` otherwise), emitting `ProgressionStepV1` chains with chain probability and
  first-step entropy; a GAT layer and per-node technique head as the typed template for the learned model; inductive
  node handling required because hosts churn.
* **Evidence:** rSPDFA top-3 accuracy 67 % one step ahead (shows the framing works and its ceiling); TIE's set→next
  framing; Jbeil's inductive temporal-graph results on authentication data.
* **Open:** training data; evaluation protocol (per-host next-technique within k windows); whether a graph model beats
  the transition table under one protocol (the CCS 2026 result suggests testing the simple baseline first).

### A9. World model and simulation: Monte Carlo over any transition model — Research Required (feasibility)
* **Alternatives:** DreamerV3-style RSSM trained on state trajectories with defender actions; digital-twin emulation;
  no simulation.
* **Selected:** `MonteCarloSimulator` runs n rollouts over a `TransitionModel` (today the technique table), treats
  interventions as absorbing states, aggregates hit rates, lists assumptions, stores rollouts by hash and labels the
  result a hypothesis; `RSSMWorldModel` is a template that refuses to instantiate; world-model output never reaches the
  policy engine.
* **Evidence:** Ha & Schmidhuber / DreamerV3 define the pattern; no 2024–2025 paper applies learned world models to
  attack progression; *False Prophets* shows world-model predictions can be steered by an attacker, which is why the
  policy engine ignores them; Monte Carlo over probabilistic transitions is the common twin-simulation primitive.
* **Open:** dataset with interventions; action space; validation method (twin replay).

### A10. Correlation and delayed matching
* **Alternatives:** per-prediction alerts; graph/provenance correlation (dependency explosion); fixed windows only.
* **Selected:** dedupe by (techniques, category) inside an entity-time window; groups per host (when predictions carry
  `host_ids`) or per sensor; ordered-subsequence **prefix** coverage against patterns; a grace period during which
  unmatched groups are re-scored (delayed matching) and after which they expire.
* **Evidence:** ROSCA/alert-graph literature uses attribute aggregation + time windows; none addresses late evidence,
  so the grace mechanism is our design and its parameters are **Research Required**.
* **Trade-offs:** in-memory state (documented restart behaviour); seed patterns are illustrative only (the only
  stage-aware synthetic dataset found, S-DAPT-2026, was withdrawn).

### A11. Risk scoring: transparent weighted sum — Research Required (weights)
* **Alternatives:** opaque ML scoring; CVSS-style multiplicative formula; severity from probability alone.
* **Selected:** `score = w_p·probability + w_m·pattern + w_a·asset + w_b·breadth`, every input/weight/formula/version
  recorded on the score; severity bands from configuration.
* **Evidence:** no standard exists; vendor playbooks combine likelihood, severity and asset criticality; transparency
  lets analysts audit and the team re-derive weights once outcomes are labelled.

### A12. Explanations: SHAP for the model, guard-railed LLM for narrative, neither as evidence
* **Alternatives:** attention weights as explanation; free-form LLM analysis with tool access.
* **Selected:** `GradientExplainer` attributions with the SHAP causality caveat recorded; LLM prompts contain contract
  data only, output sanitised and flagged, refused on IP literals, no tools, no write path; prompt and output hashed.
* **Evidence:** SHAP documentation; OWASP LLM Top 10 2025 (LLM01, LLM05, LLM06, LLM10).

### A13. Capture and parsing
* **Alternatives:** scapy full dissection; Zeek/Suricata as the only sources; no in-house parser.
* **Selected:** a small pure-Python header decoder (Ethernet/VLAN/IPv4/IPv6/TCP/UDP) that measures payload length and
  never copies payload bytes; bidirectional 5-tuple assembly with IPFIX-style expiry (inactive 15 s / active 1800 s,
  configurable), Zeek-like `conn_state` from flags; `FlowRecordV1` as the single flow shape shared with Zeek/Suricata
  adapters; honest drop reporting (`None` when counters are unavailable).
* **Evidence:** libpcap `pcap_stats` semantics; IPFIX RFC 7011; Zeek conn.log vocabulary.
* **Open:** live socket implementation and a real throughput benchmark; the 2.5 Gbps target is unmeasured.

## 3. Security and operations decisions

| Decision | Choice | Why |
|---|---|---|
| Authentication | API keys as SHA-256 digests, constant-time compare, roles viewer/analyst/dfir/admin/service | simple, auditable, no password storage; OAuth can wrap later |
| Authorization | role per route + case-level deny-by-default through `services.investigations` | OWASP API1/API5 |
| Limits | rate limit per key, body cap, upload cap, bounded queries and queues | OWASP API4 / LLM10 |
| Logging | JSON, request id, actor, redaction, CR/LF stripped | OWASP logging guidance |
| Artifacts | content-addressed, re-verified, `weights_only` loading | integrity / deserialization |
| Feedback | recorded, never trains by default | brief requirement |
| Configuration | pydantic settings, `enforce` refused in dev/test, `research_required()` surfaced in `/health` | operators see which numbers are provisional |

## 4. Unresolved decisions

| # | Decision | Owner | Needed to resolve |
|---|---|---|---|
| U1 | Integration-owner assignment | team | a name (see engineering-ownership.md) |
| U2 | Window / sequence / lateness parameters | Person 2 | labelled captures from this network; sweep under one protocol |
| U3 | Detector training data and category taxonomy | Person 2 | dataset; technique mapping |
| U4 | Progression target and model (transition table vs GAT) | Person 1 | multi-stage sequences; evaluation protocol |
| U5 | World-model feasibility and action space | Person 1 | dataset with interventions |
| U6 | Risk weights, bands, auto-allow threshold | integration | labelled outcomes; auto-allow stays off |
| U7 | Pattern library | integration | curated ATT&CK sequences from observed campaigns |
| U8 | Live capture backend (libpcap vs AF_PACKET vs Npcap) and snaplen policy | Person 4 | capture host |
| U9 | First real connector and verification method | integration | staging firewall |
| U10 | Correlator state durability (Redis) | integration | observed restart frequency |
