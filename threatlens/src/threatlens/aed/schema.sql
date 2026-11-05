-- AED Phase 1 — persistent storage schema (PostgreSQL).
--
-- STATUS: integration-pending. This DDL is the design for the Postgres-backed
-- EventStore (daily-partitioned aed_events + aed_alerts). It is kept OUT of the
-- Alembic chain on purpose (these tables are not in the ORM models, so adding
-- them to a migration would make `alembic check` report drift). Apply it as a
-- one-off on the lab Docker stack when wiring the Pg store; the in-memory store
-- in events.py is the unit-tested path. Lab use only.

-- Agents enrolled with the gateway (mirror of the in-memory registry).
CREATE TABLE IF NOT EXISTS aed_agents (
    agent_id    text PRIMARY KEY,
    fingerprint text NOT NULL,
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz,
    revoked     boolean NOT NULL DEFAULT false
);

-- Normalized events, daily-partitioned by collected_at so retention is a cheap
-- partition drop. The raw record is preserved alongside the normalized columns.
CREATE TABLE IF NOT EXISTS aed_events (
    id           bigint GENERATED ALWAYS AS IDENTITY,
    agent_id     text NOT NULL,
    class_uid    integer NOT NULL,          -- OCSF class (3002 auth, 5001 inventory)
    event_time   timestamptz NOT NULL,      -- OCSF event time
    collected_at timestamptz NOT NULL,      -- when the gateway stored it (partition key)
    src_ip       inet,
    status       text,                      -- e.g. "failure"
    ocsf_version text NOT NULL,
    fields       jsonb NOT NULL,            -- normalized subset (username already hashed)
    raw          jsonb,                     -- original record, secrets scrubbed
    PRIMARY KEY (id, collected_at)
) PARTITION BY RANGE (collected_at);

-- A default partition catches everything; a scheduled job creates per-day
-- partitions ahead of time and drops those older than the retention window.
CREATE TABLE IF NOT EXISTS aed_events_default PARTITION OF aed_events DEFAULT;

CREATE INDEX IF NOT EXISTS ix_aed_events_detect ON aed_events (agent_id, src_ip, collected_at)
    WHERE class_uid = 3002 AND status = 'failure';
CREATE INDEX IF NOT EXISTS ix_aed_events_class_time ON aed_events (class_uid, event_time);

-- Alerts raised by the detection rules.
CREATE TABLE IF NOT EXISTS aed_alerts (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule       text NOT NULL,
    agent_id   text NOT NULL,
    src_ip     inet,
    severity   text NOT NULL,
    confidence double precision NOT NULL,
    count      integer NOT NULL,
    window_s   integer NOT NULL,
    created_at timestamptz NOT NULL,
    evidence   jsonb NOT NULL,
    fp_guidance text NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_aed_alerts_created ON aed_alerts (created_at DESC);
