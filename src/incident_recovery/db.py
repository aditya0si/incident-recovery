"""PostgreSQL connection pool and versioned schema bootstrap.

The database is the single source of truth.  Schema evolution is tracked in
``schema_version`` and applied inside an advisory-locked transaction so that
concurrent service starts cannot race.  Migration 1 is the Task 1 deployment
schema (owned by :mod:`incident_recovery.gateway`); migration 2 adds the durable
incident workflow: incidents, immutable evidence, append-only events, and the
proposal/approval/operation tables later milestones build on.

Only asyncpg is used.  JSON and JSONB are encoded/decoded transparently.
"""

from __future__ import annotations

import json
from typing import Optional

import asyncpg

from .gateway import SCHEMA_SQL as DEPLOYMENT_SCHEMA_SQL

_SCHEMA_VERSION_DDL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

# Every incident workflow table, constraint, index, and immutability rule that
# Task 2 owns.  Later milestones extend this list with new versioned migrations.
INCIDENT_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS incidents (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dedupe_key        TEXT NOT NULL UNIQUE,
    service_id        TEXT NOT NULL,
    state             TEXT NOT NULL DEFAULT 'detected',
    summary           TEXT,
    alert_payload     JSONB NOT NULL DEFAULT '{}'::jsonb,
    detected_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    version           INTEGER NOT NULL DEFAULT 0,
    lease_owner       TEXT,
    lease_expires_at  TIMESTAMPTZ,
    CONSTRAINT incidents_state_valid CHECK (state IN (
        'detected','investigating','awaiting_approval','recovering','verifying',
        'resolved','escalated','rejected','recovery_failed')),
    CONSTRAINT incidents_alert_payload_size CHECK (octet_length(alert_payload::text) <= 16384),
    CONSTRAINT incidents_summary_length CHECK (summary IS NULL OR char_length(summary) <= 500)
);
CREATE INDEX IF NOT EXISTS incidents_state_idx ON incidents (state);
CREATE INDEX IF NOT EXISTS incidents_detected_idx ON incidents (detected_at DESC);

CREATE TABLE IF NOT EXISTS incident_evidence (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- RESTRICT (not CASCADE): an incident that has recorded evidence cannot be
    -- deleted, and the no-delete rule below never rewrites a cascade query.
    incident_id    UUID NOT NULL REFERENCES incidents(id) ON DELETE RESTRICT,
    source         TEXT NOT NULL,
    evidence_type  TEXT NOT NULL,
    observed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    payload        JSONB NOT NULL,
    CONSTRAINT incident_evidence_type_valid CHECK (evidence_type IN (
        'alert','log_excerpt','metric','health_check','deployment_history','note')),
    CONSTRAINT incident_evidence_payload_size CHECK (octet_length(payload::text) <= 16384)
);
CREATE INDEX IF NOT EXISTS incident_evidence_incident_idx
    ON incident_evidence (incident_id, observed_at, id);

-- Evidence is immutable: updates and deletes are silently refused at the
-- database level, independently of application code.
DROP RULE IF EXISTS incident_evidence_no_update ON incident_evidence;
CREATE RULE incident_evidence_no_update AS ON UPDATE TO incident_evidence DO INSTEAD NOTHING;
DROP RULE IF EXISTS incident_evidence_no_delete ON incident_evidence;
CREATE RULE incident_evidence_no_delete AS ON DELETE TO incident_evidence DO INSTEAD NOTHING;

CREATE TABLE IF NOT EXISTS incident_events (
    id           BIGSERIAL PRIMARY KEY,
    incident_id  UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    payload      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT incident_events_kind_valid CHECK (kind IN (
        'detected','state_changed','evidence_recorded','proposal_created',
        'approval_requested','approved','rejected','recovery_started',
        'recovery_verified','recovery_failed','escalated','fault_injected')),
    CONSTRAINT incident_events_payload_size CHECK (octet_length(payload::text) <= 16384)
);
CREATE INDEX IF NOT EXISTS incident_events_incident_idx ON incident_events (incident_id, id);

CREATE TABLE IF NOT EXISTS proposals (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id         UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    service_id          TEXT NOT NULL,
    expected_generation INTEGER NOT NULL,
    current_revision    TEXT NOT NULL,
    target_revision     TEXT NOT NULL,
    evidence_ids        UUID[] NOT NULL DEFAULT '{}',
    digest              TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT proposals_digest_unique UNIQUE (incident_id, digest)
);
CREATE INDEX IF NOT EXISTS proposals_incident_idx ON proposals (incident_id);

CREATE TABLE IF NOT EXISTS approvals (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id           UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    proposal_id           UUID NOT NULL REFERENCES proposals(id) ON DELETE CASCADE,
    proposal_digest       TEXT NOT NULL,
    service_id            TEXT NOT NULL,
    expected_revision     TEXT NOT NULL,
    target_revision       TEXT NOT NULL,
    actor                 TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'pending',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at            TIMESTAMPTZ NOT NULL,
    consumed_by_operation UUID
);
CREATE INDEX IF NOT EXISTS approvals_incident_idx ON approvals (incident_id, status);

CREATE TABLE IF NOT EXISTS recovery_operations (
    id               UUID PRIMARY KEY,
    incident_id      UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    approval_id      UUID REFERENCES approvals(id),
    status           TEXT NOT NULL DEFAULT 'pending',
    target_revision  TEXT NOT NULL,
    result           JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS recovery_operations_incident_idx
    ON recovery_operations (incident_id, status);
"""

RECOVERY_SCHEMA_SQL = """
-- Migration 3: approval-gated recovery.
--
-- ``deployment_reservations`` is the authoritative deployment-mutation token.
-- The partial unique index guarantees at most one *active* reservation per
-- service, so a fault injection and a recovery can never both own the
-- deployment and an unauthorized competing change can never win a race by
-- slipping between a check and the switch.  The gateway switch transaction
-- (which locks ``deployment_state``) validates this token before mutating.

CREATE TABLE IF NOT EXISTS deployment_reservations (
    operation_id        UUID PRIMARY KEY,
    service_id          TEXT NOT NULL,
    scope               TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'active',
    expected_generation INTEGER NOT NULL,
    target_revision     TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_at         TIMESTAMPTZ,
    CONSTRAINT deployment_reservations_scope_valid CHECK (scope IN ('fault','recovery')),
    CONSTRAINT deployment_reservations_status_valid CHECK (status IN ('active','released'))
);
CREATE UNIQUE INDEX IF NOT EXISTS deployment_reservations_active_idx
    ON deployment_reservations (service_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS deployment_reservations_operation_idx
    ON deployment_reservations (operation_id);

-- Concurrent duplicate approvals for one proposal collapse to a single record,
-- so duplicated operator submissions cannot create two logical recoveries.
CREATE UNIQUE INDEX IF NOT EXISTS approvals_incident_proposal_idx
    ON approvals (incident_id, proposal_id);

-- Operation lifecycle and reconciliation detail.
ALTER TABLE recovery_operations
    ADD COLUMN IF NOT EXISTS service_id TEXT;
ALTER TABLE recovery_operations
    ADD COLUMN IF NOT EXISTS expected_generation INTEGER;
ALTER TABLE recovery_operations
    ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE recovery_operations
    ADD COLUMN IF NOT EXISTS last_error TEXT;
ALTER TABLE recovery_operations
    ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
ALTER TABLE recovery_operations DROP CONSTRAINT IF EXISTS recovery_operations_status_valid;
ALTER TABLE recovery_operations ADD CONSTRAINT recovery_operations_status_valid
    CHECK (status IN ('pending','executing','executed','verifying','verified','failed'));

-- Add the distinct recovery_executed event kind.
ALTER TABLE incident_events DROP CONSTRAINT IF EXISTS incident_events_kind_valid;
ALTER TABLE incident_events ADD CONSTRAINT incident_events_kind_valid CHECK (kind IN (
    'detected','state_changed','evidence_recorded','proposal_created',
    'approval_requested','approved','rejected','recovery_started',
    'recovery_executed','recovery_verified','recovery_failed','escalated','fault_injected'));
"""

INVESTIGATION_SCHEMA_SQL = """
-- Migration 4: bounded, evidence-backed investigation.
--
-- One investigation *run* per incident epoch persists the adapter identity, the
-- server-enforced tool-call and wall-clock budget, and a terminal run state, so a
-- worker restart resumes the same epoch instead of resetting limits.  Logical
-- step traces are unique per (incident, epoch, step_index) and immutable, so a
-- restarted worker can never duplicate a trace.  Investigation evidence carries
-- the epoch it was observed in; the proposal gate requires evidence that belongs
-- to the incident's current epoch.

ALTER TABLE incident_evidence ADD COLUMN IF NOT EXISTS epoch INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS incident_evidence_epoch_idx
    ON incident_evidence (incident_id, epoch, observed_at, id);

CREATE TABLE IF NOT EXISTS investigation_runs (
    incident_id  UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    epoch        INTEGER NOT NULL,
    adapter      TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'running',
    tool_calls   INTEGER NOT NULL DEFAULT 0,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deadline_at  TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error   TEXT,
    PRIMARY KEY (incident_id, epoch),
    CONSTRAINT investigation_runs_state_valid CHECK (state IN ('running','decided','escalated','failed')),
    CONSTRAINT investigation_runs_tool_calls_bounds CHECK (tool_calls >= 0 AND tool_calls <= 12)
);

CREATE TABLE IF NOT EXISTS investigation_steps (
    id          BIGSERIAL PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    epoch       INTEGER NOT NULL,
    step_index  INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    payload     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT investigation_steps_kind_valid CHECK (kind IN (
        'run_started','tool_request','tool_result','diagnosis','decision','escalation')),
    CONSTRAINT investigation_steps_payload_size CHECK (octet_length(payload::text) <= 16384),
    CONSTRAINT investigation_steps_unique UNIQUE (incident_id, epoch, step_index)
);
CREATE INDEX IF NOT EXISTS investigation_steps_epoch_idx
    ON investigation_steps (incident_id, epoch, step_index);

DROP RULE IF EXISTS investigation_steps_no_update ON investigation_steps;
CREATE RULE investigation_steps_no_update AS ON UPDATE TO investigation_steps DO INSTEAD NOTHING;

-- Add the distinct investigation event kinds.
ALTER TABLE incident_events DROP CONSTRAINT IF EXISTS incident_events_kind_valid;
ALTER TABLE incident_events ADD CONSTRAINT incident_events_kind_valid CHECK (kind IN (
    'detected','state_changed','evidence_recorded','proposal_created',
    'approval_requested','approved','rejected','recovery_started',
    'recovery_executed','recovery_verified','recovery_failed','escalated',
    'fault_injected','investigation_started','diagnosis'));
"""

# Migration 5 removes the investigation-steps delete rule added by an earlier
# draft of migration 4: a DO INSTEAD NOTHING delete rule breaks the parent
# incident cascade.  Step traces are still append-only (no UPDATE rule and no
# repository delete path); evidence immutability remains database-enforced.
INVESTIGATION_STEPS_CASCADE_FIX_SQL = """
DROP RULE IF EXISTS investigation_steps_no_delete ON investigation_steps;
"""

MIGRATIONS: tuple[tuple[int, str], ...] = (
    (1, DEPLOYMENT_SCHEMA_SQL),
    (2, INCIDENT_SCHEMA_SQL),
    (3, RECOVERY_SCHEMA_SQL),
    (4, INVESTIGATION_SCHEMA_SQL),
    (5, INVESTIGATION_STEPS_CASCADE_FIX_SQL),
)

_ADVISORY_LOCK_KEY = 7762002

async def _init_connection(conn: asyncpg.Connection) -> None:
    for type_name in ("json", "jsonb"):
        await conn.set_type_codec(
            type_name,
            encoder=json.dumps,
            decoder=json.loads,
            schema="pg_catalog",
        )


async def create_pool(
    dsn: str,
    *,
    schema: Optional[str] = None,
    min_size: int = 1,
    max_size: int = 10,
) -> asyncpg.Pool:
    """Create a pool, optionally bound to an isolated ``schema`` search path."""

    server_settings = {"search_path": schema} if schema else None
    return await asyncpg.create_pool(
        dsn=dsn,
        min_size=min_size,
        max_size=max_size,
        init=_init_connection,
        server_settings=server_settings,
    )


async def bootstrap_schema(pool: asyncpg.Pool) -> int:
    """Apply outstanding versioned migrations; returns the applied version.

    The advisory lock makes concurrent bootstraps safe, and each migration is
    applied exactly once per database/schema.
    """

    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock($1)", _ADVISORY_LOCK_KEY)
            await conn.execute(_SCHEMA_VERSION_DDL)
            current = await conn.fetchval("SELECT COALESCE(MAX(version), 0) FROM schema_version")
            for version, sql in MIGRATIONS:
                if version > current:
                    await conn.execute(sql)
                    await conn.execute(
                        "INSERT INTO schema_version (version) VALUES ($1)", version
                    )
                    current = version
    return current
