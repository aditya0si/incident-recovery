"""Transactional repository over PostgreSQL.

All state changes use conditional ``UPDATE ... WHERE`` predicates and row locks
so concurrent callers cannot corrupt the workflow:

* duplicate alerts collapse to one incident via a unique dedupe key,
* state transitions are pure compare-and-set on the persisted state,
* leases are durable columns; expiry permits takeover and a stale owner can
  never commit under a renewed owner's lease,
* evidence is append-only (enforced by database rules),
* events are append-only with strictly increasing ``BIGSERIAL`` ids.

Timestamps are stored as UTC ``TIMESTAMPTZ``.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import Any, AsyncIterator, Iterable, Mapping, Optional
from uuid import UUID

import asyncpg

from .models import (
    CLAIMABLE_STATES,
    DEFAULT_LEASE_SECONDS,
    PENDING_RECOVERY_STATES,
    Approval,
    Event,
    EventKind,
    Evidence,
    EvidenceType,
    IllegalStateTransition,
    Incident,
    IncidentState,
    LeaseLost,
    NotFound,
    Operation,
    PayloadTooLarge,
    Proposal,
    ensure_utc,
    legal_predecessors,
    utcnow,
    validate_payload,
)

_COLS = (
    "id, dedupe_key, service_id, state, summary, alert_payload, "
    "detected_at, updated_at, version, lease_owner, lease_expires_at"
)
_COLS_Q = ", ".join(f"incidents.{column.strip()}" for column in _COLS.split(","))


def _row_to_incident(row: asyncpg.Record) -> Incident:
    return Incident(
        id=row["id"],
        dedupe_key=row["dedupe_key"],
        service_id=row["service_id"],
        state=IncidentState(row["state"]),
        summary=row["summary"],
        alert_payload=row["alert_payload"],
        detected_at=row["detected_at"],
        updated_at=row["updated_at"],
        version=row["version"],
        lease_owner=row["lease_owner"],
        lease_expires_at=row["lease_expires_at"],
    )


def _row_to_evidence(row: asyncpg.Record) -> Evidence:
    return Evidence(
        id=row["id"],
        incident_id=row["incident_id"],
        source=row["source"],
        evidence_type=EvidenceType(row["evidence_type"]),
        observed_at=row["observed_at"],
        payload=row["payload"],
    )


def _row_to_event(row: asyncpg.Record) -> Event:
    return Event(
        id=row["id"],
        incident_id=row["incident_id"],
        kind=EventKind(row["kind"]),
        payload=row["payload"],
        created_at=row["created_at"],
    )


class IncidentRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    # --- incidents ---------------------------------------------------------

    async def ingest_alert(
        self,
        dedupe_key: str,
        service_id: str,
        summary: Optional[str],
        payload: Mapping[str, Any],
    ) -> tuple[Incident, bool]:
        """Return ``(incident, created)``; duplicate keys map to one incident."""

        validate_payload(payload)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    f"INSERT INTO incidents (dedupe_key, service_id, state, summary, alert_payload) "
                    f"VALUES ($1, $2, 'detected', $3, $4::jsonb) "
                    f"ON CONFLICT (dedupe_key) DO NOTHING RETURNING {_COLS}",
                    dedupe_key,
                    service_id,
                    summary,
                    dict(payload),
                )
                if row is not None:
                    await conn.execute(
                        "INSERT INTO incident_events (incident_id, kind, payload) "
                        "VALUES ($1, $2, $3::jsonb)",
                        row["id"],
                        EventKind.DETECTED.value,
                        {"dedupe_key": dedupe_key},
                    )
                    return _row_to_incident(row), True

                existing = await conn.fetchrow(
                    f"SELECT {_COLS} FROM incidents WHERE dedupe_key = $1", dedupe_key
                )
                if existing is None:  # pragma: no cover - defensive
                    raise RuntimeError("conflicting alert vanished")
                return _row_to_incident(existing), False

    async def get_incident(self, incident_id: UUID) -> Optional[Incident]:
        row = await self.pool.fetchrow(
            f"SELECT {_COLS} FROM incidents WHERE id = $1", incident_id
        )
        return _row_to_incident(row) if row else None

    async def list_incidents(self, *, limit: int = 50, offset: int = 0) -> list[Incident]:
        rows = await self.pool.fetch(
            f"SELECT {_COLS} FROM incidents ORDER BY detected_at DESC, id LIMIT $1 OFFSET $2",
            limit,
            offset,
        )
        return [_row_to_incident(row) for row in rows]

    async def has_pending_recovery(self) -> bool:
        return bool(
            await self.pool.fetchval(
                "SELECT EXISTS(SELECT 1 FROM incidents WHERE state = ANY($1::text[]))",
                [state.value for state in PENDING_RECOVERY_STATES],
            )
        )

    async def append_evidence(
        self,
        incident_id: UUID,
        source: str,
        evidence_type: EvidenceType,
        payload: Mapping[str, Any],
    ) -> Evidence:
        validate_payload(payload)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    "INSERT INTO incident_evidence (incident_id, source, evidence_type, payload) "
                    "VALUES ($1, $2, $3, $4::jsonb) "
                    "RETURNING id, incident_id, source, evidence_type, observed_at, payload",
                    incident_id,
                    source,
                    EvidenceType(evidence_type).value,
                    dict(payload),
                )
                await conn.execute(
                    "INSERT INTO incident_events (incident_id, kind, payload) "
                    "VALUES ($1, $2, $3::jsonb)",
                    incident_id,
                    EventKind.EVIDENCE_RECORDED.value,
                    {"evidence_id": str(row["id"]), "evidence_type": row["evidence_type"]},
                )
        return _row_to_evidence(row)

    async def list_evidence(self, incident_id: UUID) -> list[Evidence]:
        rows = await self.pool.fetch(
            "SELECT id, incident_id, source, evidence_type, observed_at, payload "
            "FROM incident_evidence WHERE incident_id = $1 ORDER BY observed_at, id",
            incident_id,
        )
        return [_row_to_evidence(row) for row in rows]

    # --- events ------------------------------------------------------------

    async def append_event(
        self,
        incident_id: UUID,
        kind: EventKind,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Event:
        body = dict(payload or {})
        validate_payload(body)
        row = await self.pool.fetchrow(
            "INSERT INTO incident_events (incident_id, kind, payload) "
            "VALUES ($1, $2, $3::jsonb) "
            "RETURNING id, incident_id, kind, payload, created_at",
            incident_id,
            EventKind(kind).value,
            body,
        )
        return _row_to_event(row)

    async def list_events(
        self, incident_id: UUID, *, after_id: int = 0, limit: int = 500
    ) -> list[Event]:
        rows = await self.pool.fetch(
            "SELECT id, incident_id, kind, payload, created_at FROM incident_events "
            "WHERE incident_id = $1 AND id > $2 ORDER BY id ASC LIMIT $3",
            incident_id,
            after_id,
            limit,
        )
        return [_row_to_event(row) for row in rows]

    async def iter_events(
        self,
        incident_id: UUID,
        *,
        after_id: int = 0,
        poll_interval: float = 0.5,
        batch: int = 200,
    ) -> AsyncIterator[Event]:
        """Yield persisted events in id order, polling the table for new ones.

        Because the stream reads from the durable event table rather than an
        in-memory queue, a reconnect cannot lose events emitted between the
        backfill read and the subscription: the next poll picks them up.
        """

        last = after_id
        while True:
            batch_rows = await self.list_events(incident_id, after_id=last, limit=batch)
            if not batch_rows:
                await asyncio.sleep(poll_interval)
                continue
            for event in batch_rows:
                last = event.id
                yield event

    # --- state machine -----------------------------------------------------

    async def transition(
        self,
        incident_id: UUID,
        new_state: IncidentState,
        *,
        event_payload: Optional[Mapping[str, Any]] = None,
        now: Optional[datetime] = None,
    ) -> Incident:
        target = IncidentState(new_state)
        predecessors = [state.value for state in legal_predecessors(target)]
        if not predecessors:
            raise IllegalStateTransition(f"{target.value} has no legal predecessors")
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    f"UPDATE incidents SET state = $2, updated_at = now(), version = version + 1 "
                    f"WHERE id = $1 AND state = ANY($3::text[]) RETURNING {_COLS_Q}",
                    incident_id,
                    target.value,
                    predecessors,
                )
                if row is None:
                    current = await conn.fetchrow(
                        "SELECT state FROM incidents WHERE id = $1", incident_id
                    )
                    if current is None:
                        raise NotFound(f"incident {incident_id} not found")
                    raise IllegalStateTransition(
                        f"cannot move {current['state']} -> {target.value}"
                    )
                payload = {"to": target.value, **dict(event_payload or {})}
                validate_payload(payload)
                await conn.execute(
                    "INSERT INTO incident_events (incident_id, kind, payload) "
                    "VALUES ($1, $2, $3::jsonb)",
                    incident_id,
                    EventKind.STATE_CHANGED.value,
                    payload,
                )
        return _row_to_incident(row)

    # --- durable leases ----------------------------------------------------

    async def claim_next(
        self,
        worker_id: str,
        *,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
        now: Optional[datetime] = None,
    ) -> Optional[Incident]:
        instant = ensure_utc(now or utcnow())
        expiry = instant + timedelta(seconds=lease_seconds)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    f"WITH candidate AS ("
                    f"  SELECT id FROM incidents "
                    f"  WHERE state = ANY($3::text[]) "
                    f"    AND (lease_expires_at IS NULL OR lease_expires_at <= $4) "
                    f"  ORDER BY detected_at "
                    f"  FOR UPDATE SKIP LOCKED LIMIT 1"
                    f") "
                    f"UPDATE incidents SET lease_owner = $1, lease_expires_at = $2, "
                    f"updated_at = now() FROM candidate "
                    f"WHERE incidents.id = candidate.id RETURNING {_COLS_Q}",
                    worker_id,
                    expiry,
                    [state.value for state in CLAIMABLE_STATES],
                    instant,
                )
        return _row_to_incident(row) if row else None

    async def commit_under_lease(
        self,
        incident_id: UUID,
        worker_id: str,
        new_state: IncidentState,
        *,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
        event_payload: Optional[Mapping[str, Any]] = None,
        now: Optional[datetime] = None,
    ) -> Incident:
        instant = ensure_utc(now or utcnow())
        expiry = instant + timedelta(seconds=lease_seconds)
        target = IncidentState(new_state)
        predecessors = [state.value for state in legal_predecessors(target)]
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    f"UPDATE incidents SET state = $3, lease_expires_at = $4, "
                    f"updated_at = now(), version = version + 1 "
                    f"WHERE id = $1 AND lease_owner = $2 AND lease_expires_at > $5 "
                    f"AND state = ANY($6::text[]) RETURNING {_COLS_Q}",
                    incident_id,
                    worker_id,
                    target.value,
                    expiry,
                    instant,
                    predecessors,
                )
                if row is None:
                    current = await conn.fetchrow(
                        f"SELECT {_COLS} FROM incidents WHERE id = $1", incident_id
                    )
                    if current is None:
                        raise NotFound(f"incident {incident_id} not found")
                    lease_ok = (
                        current["lease_owner"] == worker_id
                        and current["lease_expires_at"] is not None
                        and ensure_utc(current["lease_expires_at"]) > instant
                    )
                    if not lease_ok:
                        raise LeaseLost(
                            f"lease for {incident_id} not held by {worker_id}"
                        )
                    raise IllegalStateTransition(
                        f"cannot move {current['state']} -> {target.value}"
                    )
                payload = {"to": target.value, **dict(event_payload or {})}
                validate_payload(payload)
                await conn.execute(
                    "INSERT INTO incident_events (incident_id, kind, payload) "
                    "VALUES ($1, $2, $3::jsonb)",
                    incident_id,
                    EventKind.STATE_CHANGED.value,
                    payload,
                )
        return _row_to_incident(row)

    async def renew_lease(
        self,
        incident_id: UUID,
        worker_id: str,
        *,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
        now: Optional[datetime] = None,
    ) -> Incident:
        instant = ensure_utc(now or utcnow())
        expiry = instant + timedelta(seconds=lease_seconds)
        row = await self.pool.fetchrow(
            f"UPDATE incidents SET lease_expires_at = $3, updated_at = now() "
            f"WHERE id = $1 AND lease_owner = $2 AND lease_expires_at > $4 "
            f"RETURNING {_COLS_Q}",
            incident_id,
            worker_id,
            expiry,
            instant,
        )
        if row is None:
            raise LeaseLost(f"cannot renew lease for {incident_id} held by {worker_id}")
        return _row_to_incident(row)

    async def release_lease(self, incident_id: UUID, worker_id: str) -> None:
        await self.pool.execute(
            "UPDATE incidents SET lease_owner = NULL, lease_expires_at = NULL "
            "WHERE id = $1 AND lease_owner = $2",
            incident_id,
            worker_id,
        )

    # --- proposals / approvals / operations (next-milestone interface) -----

    async def create_proposal(
        self,
        *,
        incident_id: UUID,
        service_id: str,
        expected_generation: int,
        current_revision: str,
        target_revision: str,
        evidence_ids: Iterable[UUID],
        digest: str,
    ) -> Proposal:
        row = await self.pool.fetchrow(
            "INSERT INTO proposals (incident_id, service_id, expected_generation, "
            "current_revision, target_revision, evidence_ids, digest) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7) "
            "RETURNING id, incident_id, service_id, expected_generation, current_revision, "
            "target_revision, evidence_ids, digest, created_at",
            incident_id,
            service_id,
            expected_generation,
            current_revision,
            target_revision,
            list(evidence_ids),
            digest,
        )
        await self.append_event(
            incident_id,
            EventKind.PROPOSAL_CREATED,
            {"proposal_id": str(row["id"]), "digest": digest},
        )
        return _row_to_proposal(row)

    async def get_proposal(self, proposal_id: UUID) -> Optional[Proposal]:
        row = await self.pool.fetchrow(
            "SELECT id, incident_id, service_id, expected_generation, current_revision, "
            "target_revision, evidence_ids, digest, created_at FROM proposals WHERE id = $1",
            proposal_id,
        )
        return _row_to_proposal(row) if row else None

    async def create_approval(
        self,
        *,
        incident_id: UUID,
        proposal_id: UUID,
        proposal_digest: str,
        service_id: str,
        expected_revision: str,
        target_revision: str,
        actor: str,
        expires_at: datetime,
    ) -> Approval:
        row = await self.pool.fetchrow(
            "INSERT INTO approvals (incident_id, proposal_id, proposal_digest, service_id, "
            "expected_revision, target_revision, actor, expires_at) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) "
            "RETURNING id, incident_id, proposal_id, proposal_digest, service_id, "
            "expected_revision, target_revision, actor, status, created_at, expires_at, "
            "consumed_by_operation",
            incident_id,
            proposal_id,
            proposal_digest,
            service_id,
            expected_revision,
            target_revision,
            actor,
            ensure_utc(expires_at),
        )
        await self.append_event(
            incident_id,
            EventKind.APPROVAL_REQUESTED,
            {"approval_id": str(row["id"]), "digest": proposal_digest},
        )
        return _row_to_approval(row)

    async def get_approval(self, approval_id: UUID) -> Optional[Approval]:
        row = await self.pool.fetchrow(
            "SELECT id, incident_id, proposal_id, proposal_digest, service_id, "
            "expected_revision, target_revision, actor, status, created_at, expires_at, "
            "consumed_by_operation FROM approvals WHERE id = $1",
            approval_id,
        )
        return _row_to_approval(row) if row else None

    async def create_operation(
        self,
        *,
        operation_id: UUID,
        incident_id: UUID,
        approval_id: Optional[UUID],
        target_revision: str,
    ) -> Operation:
        row = await self.pool.fetchrow(
            "INSERT INTO recovery_operations (id, incident_id, approval_id, target_revision) "
            "VALUES ($1, $2, $3, $4) "
            "RETURNING id, incident_id, approval_id, status, target_revision, result, "
            "created_at, updated_at",
            operation_id,
            incident_id,
            approval_id,
            target_revision,
        )
        return _row_to_operation(row)

    async def get_operation(self, operation_id: UUID) -> Optional[Operation]:
        row = await self.pool.fetchrow(
            "SELECT id, incident_id, approval_id, status, target_revision, result, "
            "created_at, updated_at FROM recovery_operations WHERE id = $1",
            operation_id,
        )
        return _row_to_operation(row) if row else None


def _row_to_proposal(row: asyncpg.Record) -> Proposal:
    return Proposal(
        id=row["id"],
        incident_id=row["incident_id"],
        service_id=row["service_id"],
        expected_generation=row["expected_generation"],
        current_revision=row["current_revision"],
        target_revision=row["target_revision"],
        evidence_ids=tuple(row["evidence_ids"] or ()),
        digest=row["digest"],
        created_at=row["created_at"],
    )


def _row_to_approval(row: asyncpg.Record) -> Approval:
    return Approval(
        id=row["id"],
        incident_id=row["incident_id"],
        proposal_id=row["proposal_id"],
        proposal_digest=row["proposal_digest"],
        service_id=row["service_id"],
        expected_revision=row["expected_revision"],
        target_revision=row["target_revision"],
        actor=row["actor"],
        status=row["status"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        consumed_by_operation=row["consumed_by_operation"],
    )


def _row_to_operation(row: asyncpg.Record) -> Operation:
    return Operation(
        id=row["id"],
        incident_id=row["incident_id"],
        approval_id=row["approval_id"],
        status=row["status"],
        target_revision=row["target_revision"],
        result=row["result"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )
