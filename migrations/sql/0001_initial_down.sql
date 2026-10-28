DROP TABLE IF EXISTS audit_log, response_action_events, response_actions, forensic_findings, forensic_analyses,
  uploads, legal_holds, custody_events, evidence_items, case_grants, investigation_links, alerts, investigations,
  analyst_feedback, forecast_current, explanations, progression_forecasts, simulations, predictions, forecast_runs,
  state_edges, temporal_states, flows, ingest_batches, pcap_segments, hosts, model_versions, datasets, objects,
  feature_schemas, users, sensors CASCADE;
DROP FUNCTION IF EXISTS nt_audit_verify(), nt_audit_chain(),
  nt_audit_entry_hash(bytea, timestamptz, uuid, text, text, text, text, jsonb, inet),
  nt_response_action_transition(), nt_response_action_created(), nt_valid_technique_ids(text[]), nt_actor(), nt_forbid_mutation();
