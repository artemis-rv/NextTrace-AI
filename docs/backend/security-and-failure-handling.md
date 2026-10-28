# Security and failure handling

## 1. Threat posture in one paragraph

Packet contents, alerts, uploaded files, model artifacts, retrieved documents and LLM output are all **untrusted
data**. Only an authenticated principal with a role, acting through the API, can change state; only a second person
can authorise what the first proposed; only an independent read-back can call a firewall rule enforced; and nothing
an LLM says can reach the policy engine. Every mutation is audited in a hash chain computed by the database.

## 2. Controls by OWASP category

| Risk | Control | Where |
|---|---|---|
| API1 / A01 Broken object-level access | deny-by-default case access (opener, explicit grants with expiry, admin metadata only); every evidence, upload, job and link goes through `require_access`; API returns 403/404 without existence leaks beyond the id | `services.investigations`, `modules/findings/alerts.py`, `modules/forensics/engine.py`, `api/app.py` |
| API2 / A07 Authentication | API keys ≥ random 32 bytes, stored as SHA-256, compared in constant time; inactive users rejected; keys never logged (redacting filter) | `core/auth.py`, `services/security.py`, `core/logging.py` |
| API5 Function-level authorization | role ladder viewer < analyst < dfir < admin, `service` only for producers; per-route checks; policy decisions can raise the required role | `core/auth.py`, `modules/response/policy.py` |
| API4 / LLM10 Resource consumption | token-bucket rate limit per key, request body cap, upload cap, bounded list/time-range queries, bounded queues, packet budget for forensic jobs, LLM token/time limits | `core/ratelimit.py`, `api/app.py`, `contracts/ops.py`, `core/bus.py`, `modules/forensics/engine.py`, `modules/explanation/llm.py` |
| A05 Injection | parameterised SQL everywhere (identifiers are code constants); path/query ids typed as UUID; regex allow-lists on free text; `extra="forbid"` on every contract; nft commands built as argument lists with validated addresses | all `services/*`, `modules/*`, `contracts/*`, `modules/response/connectors.py` |
| A08 Software/data integrity, unsafe deserialization | artifacts loaded with `torch.load(weights_only=True)`; JSON only across boundaries; objects content-addressed and re-verified before use; reports hashed | `modules/detection/model.py`, `storage/object_store.py`, `modules/forensics/engine.py` |
| API7 SSRF | the only outbound HTTP call is the LLM provider at a configuration-only endpoint; no request-supplied URLs are ever fetched | `modules/explanation/llm.py` |
| File upload | signature check (pcap/pcapng magic), declared media type must match, size cap enforced while streaming, filename sanitised and never used as a path, parse-before-accept, stored under its hash | `modules/forensics/engine.py::register_upload` |
| A09 Logging | structured JSON logs with request id and actor, CR/LF stripped, secrets redacted, access-control failures audited (`case.access_denied`, `response.authorize_denied`, `response.policy_deny`) | `core/logging.py`, `services/audit.py` |
| A10 Exceptional conditions | typed error taxonomy mapped to status codes with generic bodies; unhandled errors logged with a request id and returned as 500 `internal error`; module failures never crash the pipeline (counted, logged) | `contracts/errors.py`, `api/app.py`, `core/pipeline.py` |
| Sensitive-data exposure | graphs and explanations carry HMAC pseudonyms, never raw IPs; packet payloads are measured, not copied; the LLM prompt contains contract fields only | `modules/forecasting/graph.py`, `parsing/decode.py`, `modules/explanation/llm.py` |
| LLM01 / LLM05 / LLM06 | prompts label input as data; output sanitised, length-capped, flagged for IPs / instructions / URLs; refused on `contains_ip` or empty; the LLM has no tools, no write path, and policy rule R01 denies LLM-sourced proposals | `modules/explanation/llm.py`, `modules/response/policy.py` |
| Firewall safety | deterministic policy with recorded rules; two-person rule (DB check + manager); role escalation for critical assets, isolation, repeated targets; duration caps; dry-run default, enforce refused in dev/test; command acceptance ≠ enforcement; retries bounded then escalation; expiry → removal → removal verified; revocation; extension by a third person | `modules/response/*`, `migrations/sql/0001_initial.sql` |
| Evidence and retention | legal holds veto FIFO drops; full PCAP needs a `full_pcap` grant; custody events on acquire/verify/access; retention only via a marked session | `docs/database/storage-policy.md` |
| Model governance | models never trained on analyst feedback by default (`eligible_for_training=false`); model versions record split, metrics, calibration and code ref; unavailable slots are reported, never faked | `modules/findings/alerts.py`, `core/registry.py`, `core/composition.py` |

## 3. Failure handling

| Failure | Behaviour | Visibility |
|---|---|---|
| Consumer slower than capture | `queue.batches` policy: `block` (default; replay slows), `shed_oldest` (live ring; counted), `reject` (API ingestion gets 503) | `/health` `queue.*` metrics, `PipelineStats` |
| Kernel/interface drops | reported as counters when the platform exposes them; `drop_counters_available=false` otherwise, never silently zero | `CaptureHealthV1` |
| Malformed or truncated packets | marked, counted, skipped; never raise out of the decoder | `CaptureHealthV1.packets_malformed/truncated` |
| Flow table pressure | oldest flow evicted and emitted, counted | `AssemblerStats.evicted_table_full` |
| Late or out-of-order flows | within allowed lateness: window re-fired (idempotent upsert); beyond: counted and dropped | sequencer stats in `/health` |
| Gaps in states | listed in `StateSequenceV1.missing_windows`; the model owner decides masking vs imputation | contract |
| Model unavailable / refuses input | round records nothing, reason kept, counter incremented; no alert, no run | `PipelineStats.inference_unavailable`, `/health` model slots |
| Model raises | caught per round, counted, logged with request id; pipeline continues | `PipelineStats.errors` |
| Explanation fails | result `failed`/`unavailable`; run still recorded without it | `ExplanationResultV1.reason` |
| DB unavailable | batch/state round fails and is counted; API returns 500 with request id; health `database: down` | `/health` |
| Redis unavailable | composition runs without the live cache (PostgreSQL remains the source of truth); dashboard counts fall back to 0 for the window | health `cache: degraded/down` |
| Connector refuses | action `failed`, escalation audited | `response.escalate` |
| Rule accepted but not enforced | `verification_failed`, bounded retries, then `failed` + escalation; never `verified` | action history |
| Rule still present after removal | `removed` not confirmed, escalation audited, `removal_stuck` in maintenance output | maintenance log |
| Dry-run actions reach expiry | closed as `failed` ("expired without verification") so nothing lingers as executed | `run_due` output |
| Forensic job crashes | row set to `failed` with the error class; never left `running`; next job proceeds | `ForensicJobStatusV1.error` |
| Object hash mismatch | access refused, custody event with `hash_verified=false`, job fails | audit, custody |
| Process restart | queues are in-memory: in-flight batches are lost but flows up to the last persisted batch, states, runs and alerts are in PostgreSQL; the Redis window is rebuilt from rows (`cache.warm`); open correlation groups are lost (documented TODO: Redis-backed groups) | `docs/database/storage-policy.md` |

## 4. Secrets and configuration

Secrets (database URL, Redis URL, pepper, LLM key) are `SecretStr` fields read from the environment, redacted in
`Settings.safe_dict()` and in every log line. Research-dependent parameters are listed by `Settings.research_required()`
and shown in `/health` so operators can see which numbers are provisional. `enforcement_mode=enforce` is rejected by
validation in `dev`/`test` environments.
