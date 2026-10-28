# Research notes

Researched 2026-10-28. Every item below was read on the cited page unless marked **UNVERIFIED**
(seen only in a search excerpt, or a PDF that could not be opened). Nothing here is inferred from
memory. Section 7 separates verified facts, recommendations we adopt, and assumptions we make.

## 1. Logging, retention and evidence guidance

| Source | Date | Facts used |
|---|---|---|
| NIST SP 800-92 Rev. 1 (initial public draft), *Cybersecurity Log Management Planning Guide*, https://csrc.nist.gov/pubs/sp/800/92/r1/ipd | Published 2023-10-11; still a draft (project page updated 2025-11-20) | Log management = generating, transmitting, storing, accessing, disposing; records must be stored for the required period; informed by OMB M-21-31. Replaces SP 800-92 (2006). |
| NIST SP 800-92 (2006), https://csrc.nist.gov/pubs/sp/800/92/final | Sept 2006 | Distinguishes log *retention* (routine) from log *preservation* (keeping logs of interest that would otherwise be discarded); per-file message digests stored securely for integrity. **UNVERIFIED wording** (PDF excerpt). |
| NIST SP 800-86, *Guide to Integrating Forensic Techniques into Incident Response*, https://csrc.nist.gov/pubs/sp/800/86/final | Aug 2006 | Integrity verification by computing and comparing message digests of original and copy; a clearly defined chain of custody logging every person who had custody, what they did and when. **UNVERIFIED wording** (PDF excerpt). |
| NIST SP 800-61 Rev. 3, https://csrc.nist.gov/pubs/sp/800/61/r3/final | April 2025 (supersedes Rev. 2) | Incident response organised around CSF 2.0 functions. Under RS.AN-07: collect and retain evidence per the organisation's preservation procedures and retention policies; chain-of-custody procedures may not be needed for every incident. No numeric retention periods. **UNVERIFIED wording**. |
| OMB M-21-31 (2021) as summarised by AWS, https://aws.amazon.com/blogs/publicsector/aws-federal-customers-memorandum-m-21-31/ | Oct 2022, updated Oct 2023 | 12 months hot + 18 months cold retention; VPC flow logs are an EL1 (basic) source. Memo excerpt (**UNVERIFIED**): full packet capture required to be stored for only 72 hours. |
| OMB M-26-14 rescinds M-21-31, per Wiley Rein, https://www.wiley.law/alert-OMB-Overhauls-Federal-Cyber-Logging-Requirements-Providing-Clarity-for-Private-Sector | 2026-08-27 (memo dated 2026-05-22) | New baseline: six months actively searchable, twelve months retrievable; decentralised storage permitted. Secondary source; memo text not read. |
| ASD/CISA et al., *Best Practices for Event Logging and Threat Detection*, https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/best-practices-for-event-logging-and-threat-detection | 2024-08-22 | Default retention periods are often insufficient (incidents can take up to 18 months to discover; dwell 70–200 days); tier hot/cold; UTC ISO-8601 with milliseconds; cryptographic verification of logs in transit and at rest; central, segmented, backed-up log store; restrict and audit deletion; minimum fields include timestamp, event type, device id, source/destination IPs, user id, unique event id; netflow anomalies (a device talking to internal peers it normally does not) listed as a detection signal. |
| SWGDE 18-F-002, *Best Practices for Digital Evidence Collection*, https://www.swgde.org/documents/published-complete-listing/18-f-002-swgde-best-practices-for-digital-evidence-collection/ | v1.0, 2018-07-11 | Chain of custody must be contemporaneous, include a unique identifier, date/time of receipt and every transfer, and identify each person taking possession; deviations documented. |
| ISO/IEC 27037:2012, https://www.iso.org/standard/44381.html | 2012, confirmed 2018 | Scope includes TCP/IP networks; body text not accessible. |
| EDRM 2.0, https://edrm.net/edrm-model/current/ | 2026-09-01 | Preservation = safeguarding ESI against alteration or destruction; Disposition = defensible retain/delete/transfer process. |
| NIST SP 800-41 Rev. 1, https://csrc.nist.gov/pubs/sp/800/41/r1/final | Sept 2009 | Ruleset verification should include manual review *and* testing whether rules work as expected; changes managed by a formal process with periodic review. **UNVERIFIED wording** (PDF excerpt). No NIST text explicitly separates "command succeeded" from "rule took effect". |

## 2. Application security

| Source | Facts used |
|---|---|
| OWASP Top 10:2025, https://top10.owasp.org/2025/ (current release per https://owasp.org/projects/top-ten) | A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging & Alerting Failures, A10 Mishandling of Exceptional Conditions. |
| OWASP SQL Injection Prevention Cheat Sheet | Parameterised queries are the primary defence; identifiers cannot be bound, so map user choices to application-owned tokens; never give application accounts DBA rights; separate DB users per function. |
| OWASP Logging Cheat Sheet | Log when/where/who/what; always log authn/authz failures, admin actions, config changes, data export, uploads; never log session ids, tokens, passwords, connection strings, keys; sanitise CR/LF; write-only log account; logging failure must not break the app. |
| OWASP File Upload Cheat Sheet | Extension allow-list, signature check, rename to a generated id, length/charset limits, size limit, store outside the web root with least-privilege permissions, authenticated uploaders. |
| OWASP Authorization Cheat Sheet | Deny by default; validate permissions on every request; object-level (horizontal) checks; log access-control failures. |
| OWASP Deserialization Cheat Sheet | Prefer JSON over native serialisation; pickle-style data is untrusted. |

## 3. Network telemetry tooling

| Source | Date | Facts used |
|---|---|---|
| Zeek `conn.log` (Conn::Info), https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html | master docs | Fields: ts, uid, id (orig_h/p, resp_h/p), proto, service, duration, orig_bytes/resp_bytes, conn_state (S0, SF, REJ, RSTO…), history, orig_pkts/resp_pkts, missed_bytes; optional community_id. |
| Zeek logging framework and zeekctl, https://docs.zeek.org/en/master/frameworks/logging.html, https://github.com/zeek/zeekctl | | JSON via `LogAscii::use_json`; zeekctl rotates hourly, compresses with gzip, never expires by default (LogExpireInterval 0). |
| Suricata EVE JSON, https://docs.suricata.io/en/latest/output/eve/eve-json-format.html | | `flow_id` correlates records; flow records carry pkts/bytes to server/client, start, end, state, reason; `community_id` optional (seed must match across sensors). |
| Community ID spec, https://github.com/corelight/community-id-spec | | `1:` + base64(SHA-1 over seed, ordered endpoints, proto, ports) so Zeek, Suricata, Arkime, Wireshark, Elastic pivot on one string. |
| Arkime settings and FAQ, https://arkime.com/settings, https://arkime.com/faq | | PCAP files deleted oldest-first to keep `freeSpaceG` free (checked every minute); "locked" files never deleted; session metadata lives separately and is not auto-deleted; 1 Gbps ≈ 11 TB/day uncompressed; session index ≈ 5 % of PCAP volume; PCAP and index must not share a filesystem. |
| Google Stenographer, https://github.com/google/stenographer (archived 2022-11-04) | | Deletes oldest packet files when the disk threshold (default 10 % free) is hit; files rotate at 4 GB or 1 minute; per-file index keyed by IP/port/proto; designed for reading < 1 % of packets. |
| pcap and pcapng Internet-Drafts, https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/, https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/ | draft-09 and draft-06, 2026-09-19 | Neither is an RFC (RFC 9765 is a RADIUS document, not pcap). pcap: 24-byte header, magic 0xA1B2C3D4 (µs) / 0xA1B23C4D (ns), SnapLen must not be zero; 16-byte packet records. pcapng: block-structured, per-interface `if_tsresol`, 64-bit timestamps. |
| IPFIX RFC 7011 (STD 77, 2013) and RFC 5470 | | Flow = packets sharing properties through an observation point in a time interval; expiry on inactivity, resource limits or active timeout; no mandated timeout values. Cisco Flexible NetFlow defaults: active 1800 s, inactive 15 s. |
| nfdump, https://github.com/phaag/nfdump | | Binary 5-minute files; LZ4 for real-time, bzip2 for archive; no ratios published. |
| AWS VPC Flow Logs in Parquet, https://aws.amazon.com/blogs/big-data/optimize-performance-and-reduce-costs-for-network-analytics-with-vpc-flow-logs-in-apache-parquet-format | 2021-10-13 | Hourly Hive-style partitions, gzip Parquet; one query example 1.16 s vs 2.51 s text; no storage ratio published. |
| Elastic data tiers and ILM, https://www.elastic.co/docs/manage-data/lifecycle/data-tiers | | hot (SSD) → warm (weeks) → cold (searchable snapshots) → frozen (partially mounted; up to 20× warm capacity) → delete; `min_age` must increase per phase. |
| Splunk index storage (9.3), https://help.splunk.com/en/data-management/manage-splunk-enterprise-indexers/9.3/manage-index-storage/how-the-indexer-stores-indexes | | hot → warm → cold → frozen (deletion is the default; archiving optional) → thawed. |
| MITRE ATT&CK versions, https://attack.mitre.org/resources/versions/, https://github.com/mitre-attack/attack-stix-data | | Current v20.0 released 2026-10-13; releases each April and October; STIX 2.1 JSON bundles per version plus an always-latest bundle; technique ids `T####` and sub-techniques `T####.###`. |

## 4. Database technologies

| Source | Date | Facts used |
|---|---|---|
| PostgreSQL 18 release notes, https://www.postgresql.org/docs/18/release-18.html | 2025-09-25 | `uuidv7()` (temporally sortable); asynchronous I/O subsystem; virtual generated columns are now the default; OLD/NEW in RETURNING; B-tree skip scan. |
| PostgreSQL 17 release notes | 2024-09-26 | `COPY ... ON_ERROR ignore`; incremental `pg_basebackup` with `pg_combinebackup`. |
| Table partitioning, https://www.postgresql.org/docs/current/ddl-partitioning.html | 18.x docs | Dropping or detaching a partition is "far faster than a bulk operation" and avoids VACUUM overhead; DROP takes ACCESS EXCLUSIVE on the parent; unique/PK constraints must include the partition key; planner handles up to a few thousand partitions well when queries prune. |
| BRIN, https://www.postgresql.org/docs/current/brin.html | | For very large tables whose column correlates with physical position; "very small" index; not auto-summarised unless `autosummarize` or VACUUM. |
| JSONB indexing, https://www.postgresql.org/docs/current/datatype-json.html | | `jsonb_path_ops` GIN is usually much smaller than `jsonb_ops`. |
| Populating a database, https://www.postgresql.org/docs/current/populate.html | | COPY "is almost always faster than using INSERT, even if PREPARE is used and multiple insertions are batched". |
| Row security, https://www.postgresql.org/docs/current/ddl-rowsecurity.html | | Default-deny when enabled; superusers, BYPASSRLS and table owners bypass it. |
| psycopg / SQLAlchemy parameter docs | | Values are sent separately from SQL; identifiers cannot be bound. |
| Continuous archiving / PITR, https://www.postgresql.org/docs/current/continuous-archiving.html | | `wal_level=replica`, `archive_mode=on`, archive command must return zero only on success and refuse to overwrite; `archive_timeout` of about a minute reasonable; `pg_dump` cannot be part of continuous archiving. |
| pgBackRest, https://pgbackrest.org/ | updated 2026-10-17, v2.60.0 | Full/differential/incremental and block-level backups; parallel restore; repository encryption; per-file checksums rechecked on restore/verify; retention policies; S3/Azure/GCS/SFTP repos. |
| pg_partman, https://github.com/pgpartman/pg_partman | | Declarative partitioning only since 5.0.1; background worker; `retention_keep_table` default TRUE. Not available in the local PostgreSQL 18 build used here. |
| TimescaleDB editions and Hypercore, https://www.tigerdata.com/docs/about/latest/timescaledb-editions | | Compression, retention policies and continuous aggregates are Community (TSL) features, not Apache-2; claims "up to 98 %" compression (vendor claim). Not available in the local build. |
| ClickHouse compression and AWS flow-log post, https://clickhouse.com/blog/analyzing-aws-fow-logs-using-clickhouse | 2023-02-06 | 517 M VPC flow rows stored in 2.30 GiB (≈ 4.8 bytes/row); updates/deletes are heavy asynchronous mutations; sorting-key columns cannot be updated. |
| Redis EXPIRE, eviction, Streams, persistence, licences, https://redis.io/docs/latest/ | | TTL cleared only by delete/overwrite; `allkeys-lru` recommended default, `volatile-*` behave like `noeviction` without TTLs; `XADD MAXLEN` trims streams; RDB loses "the latest minutes", AOF `everysec` loses ≤ 1 s; Redis 8 is tri-licensed (RSALv2/SSPLv1/AGPLv3); Valkey is the BSD fork (9.1.3 released 2026-10-26). |
| S3 Object Lock and MinIO object retention | | WORM needs versioning; compliance mode cannot be shortened even by root; legal hold is an independent, indefinite flag. |
| RFC 9562 (UUIDs), https://www.rfc-editor.org/rfc/rfc9562.html | May 2024 | UUIDv7 = 48-bit ms timestamp + random; "time-ordered monotonic UUIDs benefit from greater database-index locality". |

## 5. Machine-learning data requirements

| Source | Date | Facts used |
|---|---|---|
| CIC-IDS2017 / CSE-CIC-IDS2018 and CICFlowMeter, https://www.unb.ca/cic/datasets/ids-2017.html, https://www.unb.ca/cic/research/applications.html | 2017 / 2018 | Bidirectional flows (first packet defines forward); > 80 statistical features per flow; TCP flows end at teardown, UDP on timeout; labels joined by 5-tuple and time. |
| NetFlow NIDS feature sets (Sarhan et al.), https://staff.itee.uq.edu.au/marius/NIDS_datasets/, arXiv 2101.11315 | 2021–2022 | NF-V1 = 12 features, NF-V2 = 43 NetFlow v9 features (listed in the paper); binary and attack-type labels. |
| E-GraphSAGE, arXiv 2103.16329 | 2021–2022 | Nodes = IP:port endpoints, edges = flows carrying the features; node features initialised to ones; whole-dataset graphs, no windows. |
| Anomal-E, arXiv 2207.06819 | 2022–2023 | Nodes = IPs, edges = flows with 43 features; self-supervised edge embeddings; no windowing; authors plan temporal training. |
| PPT-GNN, arXiv 2406.13365 | 2024-06-19 | Practical spatio-temporal GNN: 5 s windows chosen from a 0.5–20 s search, memory of 5 windows; long flows appear in several windows; full-dataset graphs "can clearly not be assumed in a practical scenario". |
| TGN, arXiv 2006.10637 | 2020 | Discrete-time dynamic graphs = snapshot sequences; continuous-time = timed event lists; keeps a per-node memory vector and last-event time. |
| DySAT, EvolveGCN, TGAT | 2018–2020 | Snapshot-sequence models (DySAT, EvolveGCN) vs. timestamped-edge models (TGAT). |
| Graph-NIDS evaluations, arXiv 2503.20281 (2025-03-26) and arXiv 2609.12263 (2026-09-10, CCS 2026) | | Snapshot window alone causes a mean 38.3 % relative swing in average precision; best windows ranged from 75 s to 2 h depending on dataset and model; "no single snapshot window is uniformly safe"; the window must be documented and tuned, never derived from the test set. |
| Sequence models on CIC-IDS2017, arXiv 2606.11098 | 2026-07-24 | Sequences grouped by 5-tuple; window length T ∈ {5,10,20}, T = 20 best or indistinguishable; 76 numeric features per step. |
| MITRE CTID Technique Inference Engine, arXiv 2503.04819 | 2025-03-04 | Predicts the next likely ATT&CK techniques from the *set* of observed techniques using a collaborative-filtering recommender trained on 43,899 technique observations from 6,236 CTI reports. |
| KillChainGraph (arXiv 2508.18230) and multi-stage GNN detection (arXiv 2404.18328) | 2024–2025 | Kill-chain phase graphs and stage-wise GNNs feed earlier-stage detections into later-stage prediction. |
| SHAP docs, https://shap.readthedocs.io/ | | DeepExplainer/GradientExplainer for PyTorch need a background sample of ~100–1000 rows; values sum to (output − base value); "making correlations transparent does not make them causal". |
| MLflow Model Registry and Tracking, https://mlflow.org/docs/latest/ml/model-registry/ | | Versioned models linked to the run that produced them; runs record parameters, metrics, artifacts, git commit. |

## 6. Volume arithmetic (our calculation, from cited inputs)

- Arkime: 1 Gbps ≈ 11 TB/day of raw PCAP. The 2.5 Gbps benchmark target therefore implies ≈ 27 TB/day of
  full packets, which is why full-payload capture is a short ring (72 h baseline) and only slices become evidence.
- Our benchmark (bench/benchmark.py, PostgreSQL 18.3, Windows 11, 200 k synthetic flows): 343 bytes per
  flow row including indexes, of which 49 % is index. At 1 000 flows/s that is 29.6 GB/day and 5.4 TB per
  183-day window; at 10 000 flows/s it is 54 TB. The flow rate at 2.5 Gbps is unknown for this
  deployment (depends on traffic mix) and must be measured before the retention window is treated as
  achievable in PostgreSQL alone.

## 7. What is verified, what we recommend, what we assume

**Verified facts we rely on**: PostgreSQL 18 provides native `uuidv7()` and virtual generated columns;
dropping partitions is the cheap retention path; COPY beats INSERT for bulk loads; Redis TTL and eviction
semantics; Arkime and Stenographer both implement oldest-first PCAP deletion with a protection mechanism
for locked files; chain-of-custody records need identifier, receipt time, every transfer and the handler;
the ATT&CK id format; the snapshot window is a sensitive, dataset-dependent hyper-parameter.

**Recommendations we adopt**: six-month searchable metadata with hot/cold thinking (M-26-14 baseline as
reported, ASD/CISA tiering); 72-hour full-packet ring (M-21-31 excerpt, UNVERIFIED wording, used as a
conservative default); UTC millisecond timestamps; deny-by-default object-level authorisation; parameterised
SQL and per-function database roles; never log secrets; integrity digests on every stored artifact.

**Assumptions (not evidence)**: the 10-second default state window (PPT-GNN used 5 s; graph-NIDS studies
found best windows from 75 s upward for other models); the 14-day edge retention; the window feature set
(10 aggregates) as a v1 placeholder until the model team fixes a schema; that Zeek/Suricata flow records
or CICFlowMeter-style exports are the ingestion unit; that firewall connectors can perform a read-back or
probe for verification; that the deployment's flow rate is in the low thousands per second.
