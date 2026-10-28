-- NEXTRACE AI initial schema. PostgreSQL 18 (uuidv7(), virtual generated columns, sha256()).
-- Conventions: text + CHECK for state enums (evolvable), uuidv7 keys (time-ordered index locality),
-- declarative range partitioning for high-volume telemetry, append-only tables guarded by triggers.

------------------------------------------------------------------------------------------
-- Shared trigger functions
------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION nt_forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- Rows are immutable. The only permitted DELETE is by the retention job, which marks its
  -- session with SET LOCAL nextrace.retention_job = 'on'. UPDATE is never permitted.
  IF TG_OP = 'DELETE' AND current_setting('nextrace.retention_job', true) = 'on' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION '% is append-only: % not allowed', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'integrity_constraint_violation';
END $$;

CREATE OR REPLACE FUNCTION nt_actor() RETURNS uuid LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('nextrace.actor_id', true), '')::uuid
$$;

------------------------------------------------------------------------------------------
-- Registry: sensors, users, feature schemas, datasets, models, objects
------------------------------------------------------------------------------------------
CREATE TABLE sensors (
  sensor_id   uuid PRIMARY KEY DEFAULT uuidv7(),
  name        text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 128),
  kind        text NOT NULL CHECK (kind IN ('zeek','suricata','ndr','live_capture','pcap_upload')),
  site        text,
  config      jsonb NOT NULL DEFAULT '{}'::jsonb,
  active      boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  user_id      uuid PRIMARY KEY DEFAULT uuidv7(),
  username     text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9_.-]{3,64}$'),
  role         text NOT NULL CHECK (role IN ('viewer','analyst','dfir','admin','service')),
  api_key_hash bytea UNIQUE CHECK (api_key_hash IS NULL OR octet_length(api_key_hash) = 32), -- sha256(key); raw key never stored
  active       boolean NOT NULL DEFAULT true,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE feature_schemas (
  feature_schema_id uuid PRIMARY KEY DEFAULT uuidv7(),
  name              text NOT NULL,
  version           int NOT NULL CHECK (version > 0),
  definition        jsonb NOT NULL,            -- ordered list of {name, dtype, description}
  definition_sha256 bytea NOT NULL CHECK (octet_length(definition_sha256) = 32),
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (name, version)
);

-- Content-addressed object registry. Bytes live in the object store (filesystem now, S3 later);
-- rows carry the hash, size and location so integrity can be re-verified at any time.
CREATE TABLE objects (
  sha256           bytea PRIMARY KEY CHECK (octet_length(sha256) = 32),
  size_bytes       bigint NOT NULL CHECK (size_bytes >= 0),
  media_type       text NOT NULL,
  kind             text NOT NULL CHECK (kind IN ('pcap','upload','model','shap','artifact','export','report')),
  storage_path     text NOT NULL,              -- relative to the store root; never user-controlled
  created_at       timestamptz NOT NULL DEFAULT now(),
  last_verified_at timestamptz,
  verify_ok        boolean,
  deleted_at       timestamptz                 -- tombstone: bytes reclaimed, provenance kept
);

CREATE TABLE datasets (
  dataset_id        uuid PRIMARY KEY DEFAULT uuidv7(),
  name              text NOT NULL,
  version           text NOT NULL,
  object_sha256     bytea NOT NULL REFERENCES objects (sha256),
  feature_schema_id uuid REFERENCES feature_schemas,
  row_count         bigint CHECK (row_count >= 0),
  description       text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (name, version)
);

CREATE TABLE model_versions (
  model_version_id    uuid PRIMARY KEY DEFAULT uuidv7(),
  name                text NOT NULL,
  kind                text NOT NULL CHECK (kind IN ('lstm_attention','gnn','llm','other')),
  version             text NOT NULL,
  artifact_sha256     bytea REFERENCES objects (sha256),
  feature_schema_id   uuid REFERENCES feature_schemas,
  training_dataset_id uuid REFERENCES datasets,
  hyperparameters     jsonb NOT NULL DEFAULT '{}'::jsonb,
  metrics             jsonb NOT NULL DEFAULT '{}'::jsonb,
  status              text NOT NULL DEFAULT 'candidate' CHECK (status IN ('candidate','active','retired')),
  created_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (name, version)
);

------------------------------------------------------------------------------------------
-- Telemetry: hosts, pcap segments, ingest batches, flows (partitioned), temporal states
------------------------------------------------------------------------------------------
CREATE TABLE hosts (
  host_id    uuid PRIMARY KEY DEFAULT uuidv7(),
  ip         inet NOT NULL UNIQUE,
  pseudonym  bytea NOT NULL UNIQUE CHECK (octet_length(pseudonym) = 32), -- HMAC-SHA256(ip, pepper)
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen  timestamptz NOT NULL DEFAULT now(),
  asset_tag  text,
  zone       text
);

CREATE TABLE pcap_segments (
  segment_id    uuid PRIMARY KEY DEFAULT uuidv7(),
  sensor_id     uuid NOT NULL REFERENCES sensors,
  capture_kind  text NOT NULL CHECK (capture_kind IN ('headers','full','upload')),
  snaplen       int CHECK (snaplen > 0),
  link_type     int,
  ts_first      timestamptz NOT NULL,
  ts_last       timestamptz NOT NULL CHECK (ts_last >= ts_first),
  packet_count  bigint CHECK (packet_count >= 0),
  object_sha256 bytea NOT NULL REFERENCES objects (sha256),
  status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active','held','reclaimed')),
  hold_count    int NOT NULL DEFAULT 0 CHECK (hold_count >= 0),
  created_at    timestamptz NOT NULL DEFAULT now(),
  reclaimed_at  timestamptz
);
CREATE INDEX pcap_segments_time_idx ON pcap_segments (sensor_id, ts_first);
CREATE INDEX pcap_segments_fifo_idx ON pcap_segments (created_at) WHERE status = 'active';

CREATE TABLE ingest_batches (
  batch_id      uuid PRIMARY KEY DEFAULT uuidv7(),
  sensor_id     uuid NOT NULL REFERENCES sensors,
  source        text NOT NULL CHECK (source IN ('zeek_conn','suricata_eve','pcap','csv','api')),
  object_sha256 bytea REFERENCES objects (sha256),   -- raw input file when one exists
  received_at   timestamptz NOT NULL DEFAULT now(),
  accepted      int NOT NULL DEFAULT 0,
  rejected      int NOT NULL DEFAULT 0,
  status        text NOT NULL DEFAULT 'received' CHECK (status IN ('received','loaded','failed')),
  error         text
);

-- Bidirectional flow records (Zeek conn.log / Suricata flow / CICFlowMeter-style). Daily partitions;
-- six-month FIFO by dropping partitions, which the legal-hold check can veto.
CREATE TABLE flows (
  flow_id           uuid NOT NULL DEFAULT uuidv7(),
  ts_start          timestamptz NOT NULL,
  ts_end            timestamptz,
  sensor_id         uuid NOT NULL REFERENCES sensors,
  batch_id          uuid REFERENCES ingest_batches,
  community_id      text,
  src_ip            inet NOT NULL,
  src_port          int CHECK (src_port BETWEEN 0 AND 65535),
  dst_ip            inet NOT NULL,
  dst_port          int CHECK (dst_port BETWEEN 0 AND 65535),
  proto             smallint NOT NULL CHECK (proto BETWEEN 0 AND 255),
  service           text,
  duration_ms       bigint CHECK (duration_ms >= 0),
  orig_bytes        bigint NOT NULL DEFAULT 0 CHECK (orig_bytes >= 0),
  resp_bytes        bigint NOT NULL DEFAULT 0 CHECK (resp_bytes >= 0),
  orig_pkts         bigint NOT NULL DEFAULT 0 CHECK (orig_pkts >= 0),
  resp_pkts         bigint NOT NULL DEFAULT 0 CHECK (resp_pkts >= 0),
  conn_state        text,
  history           text,
  pcap_segment_id   uuid REFERENCES pcap_segments,
  features          real[],
  feature_schema_id uuid REFERENCES feature_schemas,
  label             text,               -- ground truth when known (datasets / confirmed cases); NULL for live
  CHECK (ts_end IS NULL OR ts_end >= ts_start),
  CHECK ((features IS NULL) = (feature_schema_id IS NULL)),
  PRIMARY KEY (flow_id, ts_start)
) PARTITION BY RANGE (ts_start);
CREATE INDEX flows_ts_brin ON flows USING brin (ts_start) WITH (pages_per_range = 32);
CREATE INDEX flows_sensor_ts_idx ON flows (sensor_id, ts_start);
CREATE INDEX flows_src_idx ON flows (src_ip, ts_start);
CREATE INDEX flows_dst_idx ON flows (dst_ip, ts_start);
CREATE INDEX flows_community_idx ON flows (community_id) WHERE community_id IS NOT NULL;

-- Temporal network state: the primary analysis unit. One row per (sensor, window). Holds compact
-- aggregates plus the window-level feature vector consumed by the sequence model.
CREATE TABLE temporal_states (
  state_id          uuid NOT NULL DEFAULT uuidv7(),
  sensor_id         uuid NOT NULL REFERENCES sensors,
  window_start      timestamptz NOT NULL,
  window_seconds    int NOT NULL CHECK (window_seconds > 0),
  schema_version    int NOT NULL CHECK (schema_version > 0),
  n_flows           int NOT NULL CHECK (n_flows >= 0),
  n_nodes           int NOT NULL CHECK (n_nodes >= 0),
  n_edges           int NOT NULL CHECK (n_edges >= 0),
  total_bytes       bigint NOT NULL CHECK (total_bytes >= 0),
  total_pkts        bigint NOT NULL CHECK (total_pkts >= 0),
  summary           jsonb NOT NULL DEFAULT '{}'::jsonb,
  features          real[] NOT NULL,
  feature_schema_id uuid NOT NULL REFERENCES feature_schemas,
  built_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (state_id, window_start),
  UNIQUE (sensor_id, window_start, window_seconds)
) PARTITION BY RANGE (window_start);
CREATE INDEX temporal_states_ts_brin ON temporal_states USING brin (window_start);

-- Graph edges of a state (host -> host aggregate). Derived from flows, rebuildable, short retention.
CREATE TABLE state_edges (
  state_id          uuid NOT NULL,
  window_start      timestamptz NOT NULL,
  src_host_id       uuid NOT NULL REFERENCES hosts,
  dst_host_id       uuid NOT NULL REFERENCES hosts,
  n_flows           int NOT NULL CHECK (n_flows > 0),
  bytes             bigint NOT NULL CHECK (bytes >= 0),
  pkts              bigint NOT NULL CHECK (pkts >= 0),
  dst_ports         int NOT NULL CHECK (dst_ports >= 0),
  features          real[] NOT NULL,
  PRIMARY KEY (state_id, window_start, src_host_id, dst_host_id),
  FOREIGN KEY (state_id, window_start) REFERENCES temporal_states (state_id, window_start) ON DELETE CASCADE
) PARTITION BY RANGE (window_start);
CREATE INDEX state_edges_src_idx ON state_edges (src_host_id, window_start);
CREATE INDEX state_edges_dst_idx ON state_edges (dst_host_id, window_start);

------------------------------------------------------------------------------------------
-- Forecasting: immutable runs, predictions, progression, explanations; current pointer
------------------------------------------------------------------------------------------
CREATE TABLE forecast_runs (
  run_id                       uuid PRIMARY KEY DEFAULT uuidv7(),
  sensor_id                    uuid NOT NULL REFERENCES sensors,
  model_version_id             uuid NOT NULL REFERENCES model_versions,
  progression_model_version_id uuid REFERENCES model_versions,
  input_state_ids              uuid[] NOT NULL CHECK (cardinality(input_state_ids) > 0),
  input_window_start           timestamptz NOT NULL,
  input_window_end             timestamptz NOT NULL CHECK (input_window_end >= input_window_start),
  input_sha256                 bytea NOT NULL CHECK (octet_length(input_sha256) = 32),
  horizon_seconds              int NOT NULL CHECK (horizon_seconds > 0),
  started_at                   timestamptz NOT NULL,
  completed_at                 timestamptz NOT NULL CHECK (completed_at >= started_at),
  status                       text NOT NULL CHECK (status IN ('completed','failed')),
  error                        text,
  created_at                   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX forecast_runs_sensor_idx ON forecast_runs (sensor_id, created_at DESC);
CREATE INDEX forecast_runs_created_idx ON forecast_runs (created_at);

CREATE OR REPLACE FUNCTION nt_valid_technique_ids(ids text[]) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT COALESCE(bool_and(t ~ '^T[0-9]{4}(\.[0-9]{3})?$'), true) FROM unnest(ids) t
$$;

CREATE TABLE predictions (
  prediction_id uuid PRIMARY KEY DEFAULT uuidv7(),
  run_id        uuid NOT NULL REFERENCES forecast_runs,
  state_id      uuid NOT NULL,
  window_start  timestamptz NOT NULL,
  is_malicious  boolean NOT NULL,
  probability   real NOT NULL CHECK (probability BETWEEN 0 AND 1),
  category      text,
  attack_stage  text,
  technique_ids text[] NOT NULL DEFAULT '{}' CHECK (nt_valid_technique_ids(technique_ids))
);
CREATE INDEX predictions_run_idx ON predictions (run_id);
CREATE INDEX predictions_state_idx ON predictions (state_id);

CREATE TABLE simulations (
  simulation_id uuid PRIMARY KEY DEFAULT uuidv7(),
  base_run_id   uuid NOT NULL REFERENCES forecast_runs,
  requested_by  uuid REFERENCES users,
  scenario      jsonb NOT NULL,              -- hypothetical interventions / assumptions
  status        text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','failed')),
  result_sha256 bytea REFERENCES objects (sha256),
  created_at    timestamptz NOT NULL DEFAULT now(),
  completed_at  timestamptz
);

CREATE TABLE progression_forecasts (
  progression_id         uuid PRIMARY KEY DEFAULT uuidv7(),
  run_id                 uuid NOT NULL REFERENCES forecast_runs,
  simulation_id          uuid REFERENCES simulations,   -- NULL = baseline forecast
  step                   int NOT NULL CHECK (step >= 1),
  predicted_technique_id text NOT NULL CHECK (predicted_technique_id ~ '^T[0-9]{4}(\.[0-9]{3})?$'),
  predicted_tactic       text,
  target_host_id         uuid REFERENCES hosts,
  probability            real NOT NULL CHECK (probability BETWEEN 0 AND 1),
  expected_within_s      int CHECK (expected_within_s > 0)
);
CREATE INDEX progression_run_idx ON progression_forecasts (run_id, step);

CREATE TABLE explanations (
  explanation_id   uuid PRIMARY KEY DEFAULT uuidv7(),
  run_id           uuid NOT NULL REFERENCES forecast_runs,
  prediction_id    uuid REFERENCES predictions,
  kind             text NOT NULL CHECK (kind IN ('shap','llm')),
  model_version_id uuid REFERENCES model_versions,
  content          jsonb NOT NULL,            -- top-k attributions or LLM text; pseudonymised hosts only
  artifact_sha256  bytea REFERENCES objects (sha256), -- full SHAP arrays when large
  prompt_sha256    bytea CHECK (prompt_sha256 IS NULL OR octet_length(prompt_sha256) = 32),
  disclaimer       text NOT NULL DEFAULT 'Explanation of model output. Not evidence that an attack occurred.',
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX explanations_run_idx ON explanations (run_id);

-- What the dashboard shows: one current run per sensor. Mutable pointer; history stays in forecast_runs.
CREATE TABLE forecast_current (
  sensor_id  uuid PRIMARY KEY REFERENCES sensors,
  run_id     uuid NOT NULL REFERENCES forecast_runs,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER forecast_runs_immutable BEFORE UPDATE OR DELETE ON forecast_runs FOR EACH ROW EXECUTE FUNCTION nt_forbid_mutation();
CREATE TRIGGER predictions_immutable BEFORE UPDATE OR DELETE ON predictions FOR EACH ROW EXECUTE FUNCTION nt_forbid_mutation();
CREATE TRIGGER progression_immutable BEFORE UPDATE OR DELETE ON progression_forecasts FOR EACH ROW EXECUTE FUNCTION nt_forbid_mutation();
CREATE TRIGGER explanations_immutable BEFORE UPDATE OR DELETE ON explanations FOR EACH ROW EXECUTE FUNCTION nt_forbid_mutation();

-- Analyst feedback is recorded for triage quality; it is NOT fed back to training unless an admin
-- explicitly flags it (eligible_for_training) and a separate, reviewed process consumes it.
CREATE TABLE analyst_feedback (
  feedback_id           uuid PRIMARY KEY DEFAULT uuidv7(),
  prediction_id         uuid NOT NULL REFERENCES predictions,
  user_id               uuid NOT NULL REFERENCES users,
  verdict               text NOT NULL CHECK (verdict IN ('true_positive','false_positive','benign_anomaly','unknown')),
  note                  text,
  eligible_for_training boolean NOT NULL DEFAULT false,
  created_at            timestamptz NOT NULL DEFAULT now()
);

------------------------------------------------------------------------------------------
-- Post-detection workflow: alerts -> investigations -> evidence / holds -> response actions
------------------------------------------------------------------------------------------
CREATE TABLE investigations (
  investigation_id uuid PRIMARY KEY DEFAULT uuidv7(),
  case_number      text NOT NULL UNIQUE CHECK (case_number ~ '^[A-Z0-9-]{4,32}$'),
  title            text NOT NULL CHECK (length(title) BETWEEN 1 AND 256),
  severity         text NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  status           text NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','closed')),
  opened_by        uuid NOT NULL REFERENCES users,
  opened_at        timestamptz NOT NULL DEFAULT now(),
  closed_at        timestamptz,
  summary          text
);

CREATE TABLE alerts (
  alert_id         uuid PRIMARY KEY DEFAULT uuidv7(),
  run_id           uuid NOT NULL REFERENCES forecast_runs,
  prediction_id    uuid REFERENCES predictions,
  sensor_id        uuid NOT NULL REFERENCES sensors,
  severity         text NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  title            text NOT NULL,
  status           text NOT NULL DEFAULT 'new' CHECK (status IN ('new','acknowledged','escalated','closed')),
  assigned_to      uuid REFERENCES users,
  investigation_id uuid REFERENCES investigations,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  closed_reason    text
);
CREATE INDEX alerts_open_idx ON alerts (created_at DESC) WHERE status <> 'closed';

CREATE TABLE investigation_links (
  investigation_id uuid NOT NULL REFERENCES investigations,
  object_type      text NOT NULL CHECK (object_type IN ('alert','forecast_run','temporal_state','host','flow','forensic_finding','response_action','upload')),
  object_id        uuid NOT NULL,
  added_by         uuid NOT NULL REFERENCES users,
  added_at         timestamptz NOT NULL DEFAULT now(),
  note             text,
  PRIMARY KEY (investigation_id, object_type, object_id)
);

-- Case-level access control. 'full_pcap' is required to read packet payloads; 'metadata' for the rest.
CREATE TABLE case_grants (
  grant_id         uuid PRIMARY KEY DEFAULT uuidv7(),
  investigation_id uuid NOT NULL REFERENCES investigations,
  user_id          uuid NOT NULL REFERENCES users,
  access_level     text NOT NULL CHECK (access_level IN ('metadata','full_pcap')),
  granted_by       uuid NOT NULL REFERENCES users,
  granted_at       timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL CHECK (expires_at > granted_at),
  revoked_at       timestamptz,
  reason           text NOT NULL CHECK (length(reason) >= 8),
  CHECK (granted_by <> user_id)
);
CREATE INDEX case_grants_lookup_idx ON case_grants (investigation_id, user_id) WHERE revoked_at IS NULL;

CREATE TABLE evidence_items (
  evidence_id        uuid PRIMARY KEY DEFAULT uuidv7(),
  investigation_id   uuid NOT NULL REFERENCES investigations,
  kind               text NOT NULL CHECK (kind IN ('pcap_slice','flow_export','state_export','artifact','report','upload')),
  object_sha256      bytea NOT NULL REFERENCES objects (sha256),
  description        text NOT NULL,
  source_sensor_id   uuid REFERENCES sensors,
  ts_first           timestamptz,
  ts_last            timestamptz,
  acquired_by        uuid NOT NULL REFERENCES users,
  acquired_at        timestamptz NOT NULL DEFAULT now(),
  acquisition_method text NOT NULL,
  CHECK (ts_last IS NULL OR ts_first IS NULL OR ts_last >= ts_first)
);
CREATE INDEX evidence_case_idx ON evidence_items (investigation_id);

-- Chain of custody: append-only, one row per acquisition/verification/access/export/release.
CREATE TABLE custody_events (
  event_id      uuid PRIMARY KEY DEFAULT uuidv7(),
  evidence_id   uuid NOT NULL REFERENCES evidence_items,
  action        text NOT NULL CHECK (action IN ('acquired','verified','accessed','exported','transferred','released')),
  actor_id      uuid NOT NULL REFERENCES users,
  at            timestamptz NOT NULL DEFAULT now(),
  hash_verified boolean,
  details       jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX custody_evidence_idx ON custody_events (evidence_id, at);
CREATE TRIGGER custody_immutable BEFORE UPDATE OR DELETE ON custody_events FOR EACH ROW EXECUTE FUNCTION nt_forbid_mutation();

-- Legal holds suspend FIFO expiry for a scoped time range. 'pending' holds veto partition drops;
-- 'preserved' holds have had their data copied into immutable evidence objects.
CREATE TABLE legal_holds (
  hold_id          uuid PRIMARY KEY DEFAULT uuidv7(),
  investigation_id uuid NOT NULL REFERENCES investigations,
  sensor_id        uuid REFERENCES sensors,            -- NULL = all sensors
  scope_start      timestamptz NOT NULL,
  scope_end        timestamptz NOT NULL CHECK (scope_end > scope_start),
  host_ips         inet[],                             -- NULL = all hosts
  reason           text NOT NULL CHECK (length(reason) >= 8),
  requested_by     uuid NOT NULL REFERENCES users,
  approved_by      uuid NOT NULL REFERENCES users,
  status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','preserved','released')),
  created_at       timestamptz NOT NULL DEFAULT now(),
  preserved_at     timestamptz,
  released_at      timestamptz,
  released_by      uuid REFERENCES users,
  CHECK (requested_by <> approved_by)
);
CREATE INDEX legal_holds_active_idx ON legal_holds (scope_start, scope_end) WHERE status <> 'released';

CREATE TABLE uploads (
  upload_id         uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id           uuid NOT NULL REFERENCES users,
  investigation_id  uuid REFERENCES investigations,
  original_filename text NOT NULL CHECK (original_filename ~ '^[A-Za-z0-9._ -]{1,200}$'),
  media_type        text NOT NULL CHECK (media_type IN ('application/vnd.tcpdump.pcap','application/x-pcapng','text/csv')),
  size_bytes        bigint NOT NULL CHECK (size_bytes > 0),
  object_sha256     bytea NOT NULL REFERENCES objects (sha256),
  status            text NOT NULL DEFAULT 'received' CHECK (status IN ('received','validated','rejected','processed')),
  rejection_reason  text,
  created_at        timestamptz NOT NULL DEFAULT now()
);

-- Historical forensics: a separate pipeline over uploaded or preserved captures. Findings may be
-- linked to an investigation (investigation_links) by an authorised analyst.
CREATE TABLE forensic_analyses (
  analysis_id      uuid PRIMARY KEY DEFAULT uuidv7(),
  investigation_id uuid REFERENCES investigations,
  upload_id        uuid REFERENCES uploads,
  evidence_id      uuid REFERENCES evidence_items,
  requested_by     uuid NOT NULL REFERENCES users,
  status           text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','failed')),
  params           jsonb NOT NULL DEFAULT '{}'::jsonb,
  result_sha256    bytea REFERENCES objects (sha256),
  summary          jsonb NOT NULL DEFAULT '{}'::jsonb,
  started_at       timestamptz,
  completed_at     timestamptz,
  error            text,
  CHECK (upload_id IS NOT NULL OR evidence_id IS NOT NULL)
);

CREATE TABLE forensic_findings (
  finding_id      uuid PRIMARY KEY DEFAULT uuidv7(),
  analysis_id     uuid NOT NULL REFERENCES forensic_analyses,
  seq             int NOT NULL CHECK (seq >= 1),
  ts              timestamptz NOT NULL,
  src_ip          inet,
  dst_ip          inet,
  technique_id    text CHECK (technique_id IS NULL OR technique_id ~ '^T[0-9]{4}(\.[0-9]{3})?$'),
  description     text NOT NULL,
  confidence      real CHECK (confidence BETWEEN 0 AND 1),
  evidence_sha256 bytea REFERENCES objects (sha256),
  UNIQUE (analysis_id, seq)
);

-- Response (firewall) actions. Command success is 'executed'; only an independent verification
-- makes an action 'verified', and only 'verified' counts as enforced. Every block has an expiry.
CREATE TABLE response_actions (
  action_id            uuid PRIMARY KEY DEFAULT uuidv7(),
  investigation_id     uuid REFERENCES investigations,
  alert_id             uuid REFERENCES alerts,
  run_id               uuid REFERENCES forecast_runs,
  action_type          text NOT NULL CHECK (action_type IN ('block_ip','block_pair','rate_limit','isolate_host')),
  target               inet NOT NULL,                    -- host or CIDR
  peer                 inet,
  port                 int CHECK (port BETWEEN 0 AND 65535),
  direction            text NOT NULL DEFAULT 'both' CHECK (direction IN ('inbound','outbound','both')),
  enforcement_point    text NOT NULL CHECK (length(enforcement_point) BETWEEN 1 AND 128),
  proposed_by          uuid REFERENCES users,            -- NULL = proposed by the system
  proposed_at          timestamptz NOT NULL DEFAULT now(),
  justification        text NOT NULL CHECK (length(justification) >= 8),
  status               text NOT NULL DEFAULT 'proposed' CHECK (status IN (
                         'proposed','authorized','rejected','executing','executed','verified',
                         'verification_failed','expired','removed','removal_verified','failed')),
  authorized_by        uuid REFERENCES users,
  authorized_at        timestamptz,
  authorization_note   text,
  executed_at          timestamptz,
  execution_ref        text,                             -- firewall change id / ticket
  execution_response   jsonb,
  verified_at          timestamptz,
  verification_method  text CHECK (verification_method IN ('rule_readback','probe','traffic_observation','manual')),
  verification_result  jsonb,
  expires_at           timestamptz NOT NULL,
  removed_at           timestamptz,
  removal_verified_at  timestamptz,
  updated_at           timestamptz NOT NULL DEFAULT now(),
  enforced             boolean GENERATED ALWAYS AS (status = 'verified') VIRTUAL,
  CHECK (expires_at > proposed_at),
  CHECK (proposed_by IS NULL OR authorized_by IS NULL OR authorized_by <> proposed_by)   -- two-person rule
);
CREATE INDEX response_actions_live_idx ON response_actions (expires_at) WHERE status IN ('verified','executed');
CREATE INDEX response_actions_target_idx ON response_actions (target);

CREATE TABLE response_action_events (
  event_id    uuid PRIMARY KEY DEFAULT uuidv7(),
  action_id   uuid NOT NULL REFERENCES response_actions,
  from_status text,
  to_status   text NOT NULL,
  actor_id    uuid REFERENCES users,
  at          timestamptz NOT NULL DEFAULT now(),
  details     jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX response_action_events_idx ON response_action_events (action_id, at);
CREATE TRIGGER response_events_immutable BEFORE UPDATE OR DELETE ON response_action_events FOR EACH ROW EXECUTE FUNCTION nt_forbid_mutation();

CREATE OR REPLACE FUNCTION nt_response_action_transition() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE legal boolean;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'proposed' THEN
      RAISE EXCEPTION 'response actions must start as proposed' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    legal := CASE OLD.status
      WHEN 'proposed'            THEN NEW.status IN ('authorized','rejected')
      WHEN 'authorized'          THEN NEW.status IN ('executing','rejected')
      WHEN 'executing'           THEN NEW.status IN ('executed','failed')
      WHEN 'executed'            THEN NEW.status IN ('verified','verification_failed')
      WHEN 'verification_failed' THEN NEW.status IN ('executing','failed')
      WHEN 'verified'            THEN NEW.status IN ('expired','removed')
      WHEN 'expired'             THEN NEW.status IN ('removed','failed')
      WHEN 'removed'             THEN NEW.status IN ('removal_verified')
      ELSE false END;
    IF NOT legal THEN
      RAISE EXCEPTION 'illegal response action transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status = 'authorized' AND (NEW.authorized_by IS NULL OR NEW.authorized_at IS NULL) THEN
      RAISE EXCEPTION 'authorization requires authorized_by and authorized_at' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status = 'executed' AND NEW.executed_at IS NULL THEN
      RAISE EXCEPTION 'executed requires executed_at' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status IN ('verified','verification_failed') AND (NEW.verified_at IS NULL OR NEW.verification_method IS NULL OR NEW.verification_result IS NULL) THEN
      RAISE EXCEPTION 'verification requires verified_at, verification_method and verification_result' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status = 'removed' AND NEW.removed_at IS NULL THEN
      RAISE EXCEPTION 'removed requires removed_at' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status = 'removal_verified' AND NEW.removal_verified_at IS NULL THEN
      RAISE EXCEPTION 'removal_verified requires removal_verified_at' USING ERRCODE = 'check_violation';
    END IF;
    INSERT INTO response_action_events (action_id, from_status, to_status, actor_id, details)
      VALUES (NEW.action_id, OLD.status, NEW.status, nt_actor(),
              jsonb_strip_nulls(jsonb_build_object('verification_method', NEW.verification_method,
                                                   'execution_ref', NEW.execution_ref)));
  ELSIF OLD.status IN ('rejected','failed','removal_verified') THEN
    RAISE EXCEPTION 'response action in terminal state % cannot change', OLD.status USING ERRCODE = 'check_violation';
  END IF;
  -- Historical decision fields are write-once.
  IF OLD.authorized_by IS NOT NULL AND NEW.authorized_by IS DISTINCT FROM OLD.authorized_by THEN
    RAISE EXCEPTION 'authorized_by is write-once' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.proposed_by IS DISTINCT FROM OLD.proposed_by OR NEW.proposed_at <> OLD.proposed_at OR NEW.justification <> OLD.justification THEN
    RAISE EXCEPTION 'proposal fields are write-once' USING ERRCODE = 'check_violation';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$;
CREATE TRIGGER response_actions_transition BEFORE INSERT OR UPDATE ON response_actions FOR EACH ROW EXECUTE FUNCTION nt_response_action_transition();

CREATE OR REPLACE FUNCTION nt_response_action_created() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO response_action_events (action_id, from_status, to_status, actor_id)
    VALUES (NEW.action_id, NULL, 'proposed', COALESCE(NEW.proposed_by, nt_actor()));
  RETURN NULL;
END $$;
CREATE TRIGGER response_actions_created AFTER INSERT ON response_actions FOR EACH ROW EXECUTE FUNCTION nt_response_action_created();

------------------------------------------------------------------------------------------
-- Audit log: append-only, SHA-256 hash chained
------------------------------------------------------------------------------------------
CREATE TABLE audit_log (
  audit_id    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT now(),
  actor_id    uuid,
  actor_label text,
  action      text NOT NULL CHECK (action ~ '^[a-z_.]{3,64}$'),
  object_type text,
  object_id   text,
  details     jsonb NOT NULL DEFAULT '{}'::jsonb,
  client_ip   inet,
  prev_hash   bytea,
  entry_hash  bytea NOT NULL
);
CREATE INDEX audit_log_at_idx ON audit_log (at);
CREATE INDEX audit_log_object_idx ON audit_log (object_type, object_id);

CREATE OR REPLACE FUNCTION nt_audit_entry_hash(prev bytea, at_ timestamptz, actor uuid, label text, action text,
                                               otype text, oid text, details jsonb, ip inet)
RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
  SELECT sha256(COALESCE(prev, '\x'::bytea) || convert_to(
    concat_ws('|', at_::text, actor::text, label, action, otype, oid, details::text, ip::text), 'UTF8'))
$$;

CREATE OR REPLACE FUNCTION nt_audit_chain() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('nextrace.audit_log'));
  SELECT entry_hash INTO NEW.prev_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1;
  NEW.actor_id := COALESCE(NEW.actor_id, nt_actor());
  NEW.entry_hash := nt_audit_entry_hash(NEW.prev_hash, NEW.at, NEW.actor_id, NEW.actor_label, NEW.action,
                                        NEW.object_type, NEW.object_id, NEW.details, NEW.client_ip);
  RETURN NEW;
END $$;
CREATE TRIGGER audit_log_chain BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION nt_audit_chain();
CREATE TRIGGER audit_log_immutable BEFORE UPDATE OR DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION nt_forbid_mutation();

-- Returns the first audit_id whose stored hash does not match a recomputation (NULL = chain intact).
CREATE OR REPLACE FUNCTION nt_audit_verify() RETURNS bigint LANGUAGE sql STABLE AS $$
  WITH ordered AS (
    SELECT a.*, lag(entry_hash) OVER (ORDER BY audit_id) AS computed_prev FROM audit_log a
  )
  SELECT min(audit_id) FROM ordered
  WHERE (computed_prev IS NOT NULL AND prev_hash IS DISTINCT FROM computed_prev)
     OR entry_hash <> nt_audit_entry_hash(prev_hash, at, actor_id, actor_label, action, object_type, object_id, details, client_ip)
$$;
