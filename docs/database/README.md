# NEXTRACE AI database and storage layer

> The backend built on this layer (contracts, pipeline, models, response, API, ownership) is documented in
> [../backend/README.md](../backend/README.md).

Local, non-containerised storage layer for the AI network-attack forecaster: PostgreSQL 18 as the
system of record, a bounded Redis cache for live temporal states, and a content-addressed object store
for packet captures, exports and model artifacts.

| Document | What it answers |
|---|---|
| [research.md](research.md) | What the standards, tool docs and papers actually say (with dates), and which of our choices rest on verified facts vs. assumptions |
| [storage-policy.md](storage-policy.md) | Data inventory, where each data type lives, how it flows through the pipeline, retention, legal holds, backups, recovery, security controls |
| [schema.md](schema.md) | Entity-relationship diagram, data dictionary, versioned contracts, open decisions |
| [algorithm-and-architecture-decisions.md](algorithm-and-architecture-decisions.md) | Alternatives considered, what was selected and why, test and benchmark results, remaining risks |

The master brief asked for seven separate design files plus a final decisions file. They are
consolidated here so each document stays readable: pipeline-storage map and storage policy are one file;
ERD, data dictionary and data contracts are one file; architecture decisions and the final
algorithm-and-architecture document are one file.

## Repository state when this work started

The repository contained a single README. There was no capture, ingestion, model, API or UI code.
Everything under `nextrace/`, `migrations/`, `tests/`, `bench/` and `scripts/` was created in this
work. Integration with the (future) sensor adapters, forecasting engine and firewall connector is
therefore expressed as versioned contracts and service functions, not as wiring to existing modules.
See "Integration assumptions" in storage-policy.md.

## Layout

```
nextrace/config.py            validated settings from NEXTRACE_* environment variables
nextrace/db/engine.py         engine, reflected tables (schema is defined once, in SQL)
nextrace/db/partitions.py     daily partition creation and retention drops
nextrace/contracts/v1.py      pydantic contracts for everything crossing a process boundary
nextrace/storage/object_store.py  content-addressed local object store (S3-replaceable interface)
nextrace/storage/pcap.py      PCAP segment registry, scanning, evidence carving
nextrace/storage/cache.py     bounded Redis window + live channel
nextrace/services/ingest.py   flow validation, host pseudonyms, COPY bulk load
nextrace/services/states.py   temporal state and edge construction (set-based SQL)
nextrace/services/forecast.py immutable forecast history, current pointer
nextrace/services/investigations.py  cases, grants, evidence, custody, legal holds
nextrace/services/response.py firewall action state machine
nextrace/services/retention.py partition/PCAP/forecast retention, integrity sweep
nextrace/services/audit.py    hash-chained audit log
nextrace/cli.py               ensure-partitions | retention | expire-actions | verify | config
migrations/sql/0001_initial.sql   the schema (authoritative)
migrations/versions/0001_initial.py Alembic revision that applies it
scripts/create_roles.sql      least-privilege database roles
tests/                        49 tests (schema, contracts, authz, injection, retention, holds, cache, immutability, custody, firewall states)
bench/benchmark.py            ingestion / state build / query latency / bytes per row
```

## Running locally

Requirements: PostgreSQL 18 (uses `uuidv7()` and virtual generated columns), Python 3.12, Redis 7+
(or Valkey) for the live cache. Nothing is containerised; the layout can be containerised later
without redesign because all configuration is environment-driven.

```bash
pip install -r requirements.txt
cp .env.example .env          # then edit: database URL, pepper (32+ random chars), object store root
python -m alembic upgrade head
psql -d nextrace -f scripts/create_roles.sql   # as a superuser, once
python -m nextrace.cli ensure-partitions
```

Scheduled jobs (cron / Task Scheduler), all idempotent:

```bash
python -m nextrace.cli ensure-partitions   # daily
python -m nextrace.cli retention           # daily, run as the owner role
python -m nextrace.cli expire-actions      # every minute
python -m nextrace.cli verify              # daily integrity sweep + audit chain check (exit 2 on failure)
```

Tests (schema is rebuilt through the real migration; Redis is faked):

```bash
NEXTRACE_TEST_DATABASE_URL=postgresql+psycopg2://postgres:postgres@127.0.0.1:5432/nextrace_test python -m pytest
```
