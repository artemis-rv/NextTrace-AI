-- Least-privilege database roles. Run once as a superuser, after `alembic upgrade head`,
-- connected to the NEXTRACE database. Replace the passwords with values from your secret manager.
--
--   nextrace_owner     owns the schema; used only by migrations and the retention job (DROP partition)
--   nextrace_app       the API/backend and pipeline workers: DML only, no DDL, no DELETE on telemetry
--   nextrace_readonly  dashboards / reporting: SELECT only, and no access to object storage paths
--
-- Immutability of forecast history, custody events and the audit log is enforced by triggers for
-- every role; these grants add a second layer so an application credential cannot even attempt it.

CREATE ROLE nextrace_owner    LOGIN PASSWORD 'change-me-owner';
CREATE ROLE nextrace_app      LOGIN PASSWORD 'change-me-app';
CREATE ROLE nextrace_readonly LOGIN PASSWORD 'change-me-ro';

-- Ownership of every existing object (tables, partitions, functions) to the owner role.
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO nextrace_owner', r.tablename);
  END LOOP;
  FOR r IN SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args
           FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.proname LIKE 'nt\_%' LOOP
    EXECUTE format('ALTER FUNCTION public.%I(%s) OWNER TO nextrace_owner', r.proname, r.args);
  END LOOP;
END $$;
ALTER SCHEMA public OWNER TO nextrace_owner;

-- Application role: insert/update everywhere it legitimately writes; no DELETE on telemetry or history.
GRANT USAGE ON SCHEMA public TO nextrace_app, nextrace_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO nextrace_app, nextrace_readonly;
GRANT INSERT ON ALL TABLES IN SCHEMA public TO nextrace_app;
GRANT UPDATE ON sensors, users, hosts, objects, pcap_segments, ingest_batches, temporal_states, state_edges, model_versions,
                 forecast_current, simulations, alerts, investigations, case_grants, legal_holds, uploads,
                 forensic_analyses, response_actions TO nextrace_app;
GRANT DELETE ON case_grants, investigation_links TO nextrace_app;   -- the only rows the app may remove
REVOKE SELECT (storage_path) ON objects FROM nextrace_readonly;      -- reporting never needs filesystem paths
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nextrace_app;

-- Partitions created later by the owner role inherit nothing automatically: default privileges cover them.
ALTER DEFAULT PRIVILEGES FOR ROLE nextrace_owner IN SCHEMA public GRANT SELECT ON TABLES TO nextrace_app, nextrace_readonly;
ALTER DEFAULT PRIVILEGES FOR ROLE nextrace_owner IN SCHEMA public GRANT INSERT ON TABLES TO nextrace_app;

-- The retention job runs as nextrace_owner and marks its session: SET LOCAL nextrace.retention_job = 'on'.
-- The application never sets that variable; the triggers refuse DELETE without it.
