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
from uuid import UUID, uuid4

import asyncpg

from .models import (
    CLAIMABLE_STATES,
    DEFAULT_LEASE_SECONDS,
    OPERATION_FAILED,
    OPERATION_VERIFIED,
    PENDING_RECOVERY_STATES,
    RECOVERY_CLAIMABLE_STATES,
    RUN_DECIDED,
    RUN_ESCALATED,
    RUN_FAILED,
    RUN_RUNNING,
    SERVICE_ID,
    Approval,
    ApprovalStale,
    Event,
    EventKind,
    Evidence,
    EvidenceType,
    IllegalStateTransition,
    Incident,
    IncidentState,
    InvestigationRun,
    InvestigationStep,
    LeaseLost,
    NotFound,
    Operation,
    PayloadTooLarge,
    Proposal,
    ProposalNotFound,
    Reservation,
    ReservationConflict,
    ensure_utc,
    legal_predecessors,
    utcnow,
    validate_payload,
)
from .tools import redact_secrets, redact_structure

_OPERATION_COLS = (
    "id, incident_id, approval_id, status, target_revision, result, created_at, "
    "updated_at, service_id, expected_generation, attempts, last_error, verified_at"
)

_COLS = (
    "id, dedupe_key, service_id, state, summary, alert_payload, "
    "detected_at, updated_at, version, lease_owner, lease_expires_at"
)
_COLS_Q = ", ".join(f"incidents.{column.strip()}" for column in _COLS.split(","))


def _redact_text(value: Optional[str]) -> Optional[str]:
    """Redact secret-shaped text before it is written to a text column.

    Error/trace strings are persisted verbatim in ``last_error`` columns, so they
    flow through the same shared redaction as structured payloads; a synthetic
    ``password=...`` in an error message must not survive.
    """

    return redact_secrets(value) if value is not None else None



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
        epoch=row["epoch"],
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

        body = redact_structure(dict(payload))
        validate_payload(body)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    f"INSERT INTO incidents (dedupe_key, service_id, state, summary, alert_payload) "
                    f"VALUES ($1, $2, 'detected', $3, $4::jsonb) "
                    f"ON CONFLICT (dedupe_key) DO NOTHING RETURNING {_COLS}",
                    dedupe_key,
                    service_id,
                    summary,
                    body,
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
        *,
        epoch: int = 0,
    ) -> Evidence:
        body = redact_structure(dict(payload))
        validate_payload(body)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    "INSERT INTO incident_evidence (incident_id, source, evidence_type, payload, epoch) "
                    "VALUES ($1, $2, $3, $4::jsonb, $5) "
                    "RETURNING id, incident_id, source, evidence_type, observed_at, payload, epoch",
                    incident_id,
                    source,
                    EvidenceType(evidence_type).value,
                    body,
                    epoch,
                )
                await conn.execute(
                    "INSERT INTO incident_events (incident_id, kind, payload) "
                    "VALUES ($1, $2, $3::jsonb)",
                    incident_id,
                    EventKind.EVIDENCE_RECORDED.value,
                    {"evidence_id": str(row["id"]), "evidence_type": row["evidence_type"]},
                )
        return _row_to_evidence(row)

    async def list_evidence(
        self, incident_id: UUID, *, epoch: Optional[int] = None
    ) -> list[Evidence]:
        if epoch is None:
            rows = await self.pool.fetch(
                "SELECT id, incident_id, source, evidence_type, observed_at, payload, epoch "
                "FROM incident_evidence WHERE incident_id = $1 ORDER BY observed_at, id",
                incident_id,
            )
        else:
            rows = await self.pool.fetch(
                "SELECT id, incident_id, source, evidence_type, observed_at, payload, epoch "
                "FROM incident_evidence WHERE incident_id = $1 AND epoch = $2 "
                "ORDER BY observed_at, id",
                incident_id,
                epoch,
            )
        return [_row_to_evidence(row) for row in rows]

    # --- events ------------------------------------------------------------

    async def append_event(
        self,
        incident_id: UUID,
        kind: EventKind,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Event:
        body = redact_structure(dict(payload or {}))
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
                payload = redact_structure({"to": target.value, **dict(event_payload or {})})
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
                payload = redact_structure({"to": target.value, **dict(event_payload or {})})
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
        service_id: Optional[str] = SERVICE_ID,
        expected_generation: Optional[int] = None,
    ) -> Operation:
        row = await self.pool.fetchrow(
            f"INSERT INTO recovery_operations (id, incident_id, approval_id, target_revision, "
            f"service_id, expected_generation) "
            f"VALUES ($1, $2, $3, $4, $5, $6) RETURNING {_OPERATION_COLS}",
            operation_id,
            incident_id,
            approval_id,
            target_revision,
            service_id,
            expected_generation,
        )
        return _row_to_operation(row)

    async def get_operation(self, operation_id: UUID) -> Optional[Operation]:
        row = await self.pool.fetchrow(
            f"SELECT {_OPERATION_COLS} FROM recovery_operations WHERE id = $1",
            operation_id,
        )
        return _row_to_operation(row) if row else None

    async def get_operation_for_incident(self, incident_id: UUID) -> Optional[Operation]:
        row = await self.pool.fetchrow(
            f"SELECT {_OPERATION_COLS} FROM recovery_operations "
            f"WHERE incident_id = $1 ORDER BY created_at DESC LIMIT 1",
            incident_id,
        )
        return _row_to_operation(row) if row else None

    async def set_operation_status(
        self,
        operation_id: UUID,
        status: str,
        *,
        result: Optional[Mapping[str, Any]] = None,
        last_error: Optional[str] = None,
        mark_verified: bool = False,
        bump_attempts: bool = False,
    ) -> Operation:
        """Conditionally update operation state; returns the current row.

        Terminal operations are never rewritten by a late status change.
        """
        body = redact_structure(dict(result)) if result is not None else None
        validate_payload(body or {})
        row = await self.pool.fetchrow(
            f"UPDATE recovery_operations SET status = $2, "
            f"result = COALESCE($3::jsonb, result), "
            f"last_error = COALESCE($4, last_error), "
            f"attempts = attempts + CASE WHEN $5 THEN 1 ELSE 0 END, "
            f"verified_at = CASE WHEN $6 THEN now() ELSE verified_at END, "
            f"updated_at = now() "
            f"WHERE id = $1 AND status NOT IN ('verified','failed') "
            f"RETURNING {_OPERATION_COLS}",
            operation_id,
            status,
            body,
            _redact_text(last_error),
            bump_attempts,
            mark_verified,
        )
        if row is None:
            existing = await self.get_operation(operation_id)
            if existing is None:
                raise NotFound(f"operation {operation_id} not found")
            return existing
        return _row_to_operation(row)

    # --- proposals / approvals -------------------------------------------------

    async def get_proposal_by_digest(
        self, incident_id: UUID, digest: str
    ) -> Optional[Proposal]:
        row = await self.pool.fetchrow(
            "SELECT id, incident_id, service_id, expected_generation, current_revision, "
            "target_revision, evidence_ids, digest, created_at FROM proposals "
            "WHERE incident_id = $1 AND digest = $2",
            incident_id,
            digest,
        )
        return _row_to_proposal(row) if row else None

    async def get_proposal_for_incident(self, incident_id: UUID) -> Optional[Proposal]:
        row = await self.pool.fetchrow(
            "SELECT id, incident_id, service_id, expected_generation, current_revision, "
            "target_revision, evidence_ids, digest, created_at FROM proposals "
            "WHERE incident_id = $1 ORDER BY created_at DESC LIMIT 1",
            incident_id,
        )
        return _row_to_proposal(row) if row else None

    async def get_approval_for_incident(self, incident_id: UUID) -> Optional[Approval]:
        row = await self.pool.fetchrow(
            "SELECT id, incident_id, proposal_id, proposal_digest, service_id, "
            "expected_revision, target_revision, actor, status, created_at, expires_at, "
            "consumed_by_operation FROM approvals WHERE incident_id = $1 "
            "ORDER BY created_at DESC LIMIT 1",
            incident_id,
        )
        return _row_to_approval(row) if row else None

    async def approve_incident(
        self,
        incident_id: UUID,
        proposal_digest: str,
        actor: str,
        *,
        ttl_seconds: int = 300,
        now: Optional[datetime] = None,
        service_id: str = SERVICE_ID,
    ) -> tuple[Approval, Operation, bool]:
        """Authorize the exact proposal digest.

        The proposal digest, fixed service, current revision/generation, known-good
        predecessor, actor, and a five-minute UTC expiry are all bound atomically.
        Duplicate submissions return the one persisted approval/operation; a
        competing reservation (fault or recovery) fails closed.
        """
        instant = ensure_utc(now or utcnow())
        expires_at = instant + timedelta(seconds=ttl_seconds)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                incident_row = await conn.fetchrow(
                    f"SELECT {_COLS} FROM incidents WHERE id = $1 FOR UPDATE", incident_id
                )
                if incident_row is None:
                    raise NotFound(f"incident {incident_id} not found")
                incident = _row_to_incident(incident_row)

                proposal = await conn.fetchrow(
                    "SELECT id, incident_id, service_id, expected_generation, "
                    "current_revision, target_revision, evidence_ids, digest, created_at "
                    "FROM proposals WHERE incident_id = $1 AND digest = $2",
                    incident_id,
                    proposal_digest,
                )
                if proposal is None:
                    raise ProposalNotFound("proposal digest not found for incident")

                # Idempotent duplicate: return the existing approval and operation.
                existing = await conn.fetchrow(
                    "SELECT id, incident_id, proposal_id, proposal_digest, service_id, "
                    "expected_revision, target_revision, actor, status, created_at, "
                    "expires_at, consumed_by_operation FROM approvals "
                    "WHERE incident_id = $1 AND proposal_id = $2",
                    incident_id,
                    proposal["id"],
                )
                if existing is not None:
                    operation = await self._operation_for_approval(conn, existing["id"])
                    return _row_to_approval(existing), operation, False

                if incident.state is not IncidentState.AWAITING_APPROVAL:
                    raise IllegalStateTransition(
                        f"cannot approve incident in state {incident.state.value}"
                    )

                state_row = await conn.fetchrow(
                    "SELECT service_id, revision, generation, activated_at, predecessor "
                    "FROM deployment_state WHERE service_id = $1 FOR UPDATE",
                    service_id,
                )
                if state_row is None:
                    raise NotFound("deployment_state is not initialised")

                target = proposal["target_revision"]
                if proposal["service_id"] != service_id:
                    raise ApprovalStale("proposal service does not match the bound service")
                if (
                    proposal["expected_generation"] != state_row["generation"]
                    or proposal["current_revision"] != state_row["revision"]
                ):
                    raise ApprovalStale("proposal revision/generation is stale")
                if state_row["predecessor"] is None or target != state_row["predecessor"]:
                    raise ApprovalStale("target revision is not the recorded predecessor")

                approval_row = await conn.fetchrow(
                    "INSERT INTO approvals (incident_id, proposal_id, proposal_digest, "
                    "service_id, expected_revision, target_revision, actor, expires_at) "
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) "
                    "RETURNING id, incident_id, proposal_id, proposal_digest, service_id, "
                    "expected_revision, target_revision, actor, status, created_at, "
                    "expires_at, consumed_by_operation",
                    incident_id,
                    proposal["id"],
                    proposal_digest,
                    service_id,
                    state_row["revision"],
                    target,
                    actor,
                    expires_at,
                )

                operation_id = uuid4()
                operation_row = await conn.fetchrow(
                    f"INSERT INTO recovery_operations (id, incident_id, approval_id, "
                    f"target_revision, service_id, expected_generation) "
                    f"VALUES ($1, $2, $3, $4, $5, $6) RETURNING {_OPERATION_COLS}",
                    operation_id,
                    incident_id,
                    approval_row["id"],
                    target,
                    service_id,
                    state_row["generation"],
                )

                try:
                    await conn.execute(
                        "INSERT INTO deployment_reservations (operation_id, service_id, scope, "
                        "expected_generation, target_revision) VALUES ($1, $2, 'recovery', $3, $4)",
                        operation_id,
                        service_id,
                        state_row["generation"],
                        target,
                    )
                except asyncpg.UniqueViolationError as exc:
                    raise ReservationConflict(
                        "deployment is reserved by a competing operation"
                    ) from exc

                transitioned = await conn.fetchrow(
                    "UPDATE incidents SET state = $2, updated_at = now(), "
                    "version = version + 1 WHERE id = $1 AND state = $3 RETURNING id",
                    incident_id,
                    IncidentState.RECOVERING.value,
                    IncidentState.AWAITING_APPROVAL.value,
                )
                if transitioned is None:  # pragma: no cover - guarded by row lock
                    raise IllegalStateTransition("incident left awaiting_approval")

                await conn.execute(
                    "INSERT INTO incident_events (incident_id, kind, payload) "
                    "VALUES ($1, $2, $3::jsonb)",
                    incident_id,
                    EventKind.APPROVED.value,
                    redact_structure(
                        {
                            "approval_id": str(approval_row["id"]),
                            "operation_id": str(operation_id),
                            "digest": proposal_digest,
                            "actor": actor,
                            "expires_at": ensure_utc(expires_at).isoformat(),
                        }
                    ),
                )
                await conn.execute(
                    "INSERT INTO incident_events (incident_id, kind, payload) "
                    "VALUES ($1, $2, $3::jsonb)",
                    incident_id,
                    EventKind.RECOVERY_STARTED.value,
                    redact_structure(
                        {
                            "operation_id": str(operation_id),
                            "target_revision": target,
                        }
                    ),
                )
        return _row_to_approval(approval_row), _row_to_operation(operation_row), True

    async def consume_approval(self, approval_id: UUID, operation_id: UUID) -> bool:
        """Mark an approval consumed by exactly one operation (idempotent)."""
        row = await self.pool.fetchrow(
            "UPDATE approvals SET status = 'consumed', consumed_by_operation = $2 "
            "WHERE id = $1 AND (consumed_by_operation IS NULL OR consumed_by_operation = $2) "
            "RETURNING id",
            approval_id,
            operation_id,
        )
        return row is not None

    async def record_execution(
        self, operation_id: UUID, result: Mapping[str, Any]
    ) -> Operation:
        """Persist a successful execution and its distinct event atomically."""
        body = redact_structure(dict(result))
        validate_payload(body)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    f"UPDATE recovery_operations SET status = $2, result = $3::jsonb, "
                    f"updated_at = now() WHERE id = $1 "
                    f"AND status NOT IN ('verified','failed') RETURNING {_OPERATION_COLS}",
                    operation_id,
                    "executed",
                    body,
                )
                if row is None:
                    existing = await self.get_operation(operation_id)
                    if existing is None:
                        raise NotFound(f"operation {operation_id} not found")
                    return existing
                await conn.execute(
                    "INSERT INTO incident_events (incident_id, kind, payload) "
                    "VALUES ($1, $2, $3::jsonb)",
                    row["incident_id"],
                    EventKind.RECOVERY_EXECUTED.value,
                    {"operation_id": str(operation_id), **body},
                )
        return _row_to_operation(row)

    async def _operation_for_approval(
        self, conn: asyncpg.Connection, approval_id: UUID
    ) -> Operation:
        row = await conn.fetchrow(
            f"SELECT {_OPERATION_COLS} FROM recovery_operations "
            f"WHERE approval_id = $1 ORDER BY created_at DESC LIMIT 1",
            approval_id,
        )
        if row is None:  # pragma: no cover - approval always creates an operation
            raise NotFound("operation for approval not found")
        return _row_to_operation(row)

    async def reject_incident(
        self,
        incident_id: UUID,
        actor: str,
        *,
        reason: Optional[str] = None,
        proposal_digest: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> Incident:
        instant = ensure_utc(now or utcnow())
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    f"UPDATE incidents SET state = $2, updated_at = now(), "
                    f"version = version + 1 "
                    f"WHERE id = $1 AND state = $3 RETURNING {_COLS_Q}",
                    incident_id,
                    IncidentState.REJECTED.value,
                    IncidentState.AWAITING_APPROVAL.value,
                )
                if row is None:
                    current = await conn.fetchrow(
                        "SELECT state FROM incidents WHERE id = $1", incident_id
                    )
                    if current is None:
                        raise NotFound(f"incident {incident_id} not found")
                    raise IllegalStateTransition(
                        f"cannot reject incident in state {current['state']}"
                    )
                await conn.execute(
                    "INSERT INTO incident_events (incident_id, kind, payload) "
                    "VALUES ($1, $2, $3::jsonb)",
                    incident_id,
                    EventKind.REJECTED.value,
                    redact_structure(
                        {
                            "actor": actor,
                            "reason": reason,
                            "digest": proposal_digest,
                            "at": instant.isoformat(),
                        }
                    ),
                )
        return _row_to_incident(row)

    # --- authoritative deployment reservations --------------------------------

    async def reserve(
        self,
        operation_id: UUID,
        *,
        scope: str,
        expected_generation: int,
        target_revision: str,
        service_id: str = SERVICE_ID,
    ) -> Reservation:
        """Claim the deployment mutation token; fail closed if already held."""
        try:
            row = await self.pool.fetchrow(
                "INSERT INTO deployment_reservations (operation_id, service_id, scope, "
                "expected_generation, target_revision) VALUES ($1, $2, $3, $4, $5) "
                "RETURNING operation_id, service_id, scope, status, expected_generation, "
                "target_revision, created_at, released_at",
                operation_id,
                service_id,
                scope,
                expected_generation,
                target_revision,
            )
        except asyncpg.UniqueViolationError as exc:
            raise ReservationConflict("deployment is already reserved") from exc
        return _row_to_reservation(row)

    async def release_reservation(self, operation_id: UUID) -> None:
        await self.pool.execute(
            "UPDATE deployment_reservations SET status = 'released', released_at = now() "
            "WHERE operation_id = $1 AND status = 'active'",
            operation_id,
        )

    async def get_reservation(self, operation_id: UUID) -> Optional[Reservation]:
        row = await self.pool.fetchrow(
            "SELECT operation_id, service_id, scope, status, expected_generation, "
            "target_revision, created_at, released_at FROM deployment_reservations "
            "WHERE operation_id = $1",
            operation_id,
        )
        return _row_to_reservation(row) if row else None

    async def active_reservation(self, service_id: str = SERVICE_ID) -> Optional[Reservation]:
        row = await self.pool.fetchrow(
            "SELECT operation_id, service_id, scope, status, expected_generation, "
            "target_revision, created_at, released_at FROM deployment_reservations "
            "WHERE service_id = $1 AND status = 'active' LIMIT 1",
            service_id,
        )
        return _row_to_reservation(row) if row else None

    # --- durable recovery worker ----------------------------------------------

    async def claim_next_recovery(
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
                    [state.value for state in RECOVERY_CLAIMABLE_STATES],
                    instant,
                )
        return _row_to_incident(row) if row else None

    async def verify_revision(self, expected_revision: str, *, service_id: str = SERVICE_ID) -> bool:
        """Read the authoritative active revision from PostgreSQL."""
        revision = await self.pool.fetchval(
            "SELECT revision FROM deployment_state WHERE service_id = $1", service_id
        )
        return revision == expected_revision

    async def finalize_verification(
        self,
        incident_id: UUID,
        worker_id: str,
        operation_id: UUID,
        *,
        success: bool,
        verification: Mapping[str, Any],
        now: Optional[datetime] = None,
    ) -> Incident:
        """Atomically persist the verification outcome and release the reservation.

        The incumbent worker's lease must still be valid; a stale worker can never
        resolve the incident.  A consumed approval/operation is terminal.
        """
        instant = ensure_utc(now or utcnow())
        body = redact_structure(dict(verification))
        validate_payload(body)
        target_state = IncidentState.RESOLVED if success else IncidentState.RECOVERY_FAILED
        predecessors = [state.value for state in legal_predecessors(target_state)]
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    f"UPDATE incidents SET state = $3, lease_expires_at = NULL, "
                    f"updated_at = now(), version = version + 1 "
                    f"WHERE id = $1 AND lease_owner = $2 AND lease_expires_at > $4 "
                    f"AND state = ANY($5::text[]) RETURNING {_COLS_Q}",
                    incident_id,
                    worker_id,
                    target_state.value,
                    instant,
                    predecessors,
                )
                if row is None:
                    current = await conn.fetchrow(
                        f"SELECT {_COLS} FROM incidents WHERE id = $1", incident_id
                    )
                    if current is None:
                        raise NotFound(f"incident {incident_id} not found")
                    ok = (
                        current["lease_owner"] == worker_id
                        and current["lease_expires_at"] is not None
                        and ensure_utc(current["lease_expires_at"]) > instant
                    )
                    if not ok:
                        raise LeaseLost(f"lease for {incident_id} not held by {worker_id}")
                    raise IllegalStateTransition(
                        f"cannot move {current['state']} -> {target_state.value}"
                    )

                await conn.execute(
                    "UPDATE recovery_operations SET status = $2, result = $3::jsonb, "
                    "verified_at = CASE WHEN $4 THEN now() ELSE verified_at END, "
                    "updated_at = now() WHERE id = $1",
                    operation_id,
                    OPERATION_VERIFIED if success else OPERATION_FAILED,
                    body,
                    success,
                )
                await conn.execute(
                    "UPDATE deployment_reservations SET status = 'released', "
                    "released_at = now() WHERE operation_id = $1 AND status = 'active'",
                    operation_id,
                )
                await conn.execute(
                    "INSERT INTO incident_events (incident_id, kind, payload) "
                    "VALUES ($1, $2, $3::jsonb)",
                    incident_id,
                    (
                        EventKind.RECOVERY_VERIFIED.value
                        if success
                        else EventKind.RECOVERY_FAILED.value
                    ),
                    body,
                )
        return _row_to_incident(row)

    async def fail_recovery(
        self,
        incident_id: UUID,
        worker_id: str,
        operation_id: UUID,
        *,
        error: str,
        result: Optional[Mapping[str, Any]] = None,
        now: Optional[datetime] = None,
    ) -> Incident:
        """Persist a failed recovery operation and move the incident to recovery_failed."""
        instant = ensure_utc(now or utcnow())
        result_body = redact_structure(dict(result)) if result is not None else None
        payload = redact_structure({"error": error, **dict(result or {})})
        validate_payload(payload)
        predecessors = [state.value for state in legal_predecessors(IncidentState.RECOVERY_FAILED)]
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    f"UPDATE incidents SET state = $3, lease_expires_at = NULL, "
                    f"updated_at = now(), version = version + 1 "
                    f"WHERE id = $1 AND lease_owner = $2 AND lease_expires_at > $4 "
                    f"AND state = ANY($5::text[]) RETURNING {_COLS_Q}",
                    incident_id,
                    worker_id,
                    IncidentState.RECOVERY_FAILED.value,
                    instant,
                    predecessors,
                )
                if row is None:
                    current = await conn.fetchrow(
                        f"SELECT {_COLS} FROM incidents WHERE id = $1", incident_id
                    )
                    if current is None:
                        raise NotFound(f"incident {incident_id} not found")
                    ok = (
                        current["lease_owner"] == worker_id
                        and current["lease_expires_at"] is not None
                        and ensure_utc(current["lease_expires_at"]) > instant
                    )
                    if not ok:
                        raise LeaseLost(f"lease for {incident_id} not held by {worker_id}")
                    raise IllegalStateTransition(
                        f"cannot move {current['state']} -> recovery_failed"
                    )
                await conn.execute(
                    "UPDATE recovery_operations SET status = $2, last_error = $3, "
                    "result = COALESCE($4::jsonb, result), updated_at = now() WHERE id = $1",
                    operation_id,
                    OPERATION_FAILED,
                    _redact_text(error),
                    result_body,
                )
                await conn.execute(
                    "UPDATE deployment_reservations SET status = 'released', "
                    "released_at = now() WHERE operation_id = $1 AND status = 'active'",
                    operation_id,
                )
                await conn.execute(
                    "INSERT INTO incident_events (incident_id, kind, payload) "
                    "VALUES ($1, $2, $3::jsonb)",
                    incident_id,
                    EventKind.RECOVERY_FAILED.value,
                    payload,
                )
        return _row_to_incident(row)


    async def _assert_lease(
        self, conn: asyncpg.Connection, incident_id: UUID, worker_id: str, now: datetime
    ) -> None:
        row = await conn.fetchrow(
            "SELECT lease_owner, lease_expires_at FROM incidents WHERE id = $1 FOR UPDATE",
            incident_id,
        )
        if row is None:
            raise NotFound(f"incident {incident_id} not found")
        if (
            row["lease_owner"] != worker_id
            or row["lease_expires_at"] is None
            or ensure_utc(row["lease_expires_at"]) <= ensure_utc(now)
        ):
            raise LeaseLost(f"lease for {incident_id} not held by {worker_id}")

    async def claim_next_investigation(
        self,
        worker_id: str,
        *,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
        now: Optional[datetime] = None,
    ) -> Optional[Incident]:
        """Claim a ``detected``/``investigating`` incident under a durable lease.

        A ``detected`` incident is atomically moved to ``investigating``; an
        ``investigating`` incident is simply re-leased so a restart resumes the
        in-progress investigation rather than starting a new epoch.
        """

        instant = ensure_utc(now or utcnow())
        expiry = instant + timedelta(seconds=lease_seconds)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    f"SELECT {_COLS_Q} FROM incidents "
                    f"WHERE state = ANY($1::text[]) "
                    f"  AND (lease_expires_at IS NULL OR lease_expires_at <= $2) "
                    f"ORDER BY detected_at FOR UPDATE SKIP LOCKED LIMIT 1",
                    [IncidentState.DETECTED.value, IncidentState.INVESTIGATING.value],
                    instant,
                )
                if row is None:
                    return None
                previous = row["state"]
                updated = await conn.fetchrow(
                    f"UPDATE incidents SET lease_owner = $2, lease_expires_at = $3, "
                    f"state = $4, updated_at = now(), version = version + 1 "
                    f"WHERE id = $1 RETURNING {_COLS_Q}",
                    row["id"],
                    worker_id,
                    expiry,
                    IncidentState.INVESTIGATING.value,
                )
                if previous != IncidentState.INVESTIGATING.value:
                    await conn.execute(
                        "INSERT INTO incident_events (incident_id, kind, payload) "
                        "VALUES ($1, $2, $3::jsonb)",
                        row["id"],
                        EventKind.STATE_CHANGED.value,
                        {"to": IncidentState.INVESTIGATING.value},
                    )
        return _row_to_incident(updated)

    async def ensure_investigation_run(
        self,
        incident_id: UUID,
        adapter: str,
        max_seconds: float,
        *,
        now: Optional[datetime] = None,
    ) -> InvestigationRun:
        """Return the running investigation run, or create a new epoch.

        Restarting a worker reuses the persisted running run (same epoch, same
        tool-call count, same deadline), so limits are never silently reset.
        """

        instant = ensure_utc(now or utcnow())
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                existing = await conn.fetchrow(
                    "SELECT incident_id, epoch, adapter, state, tool_calls, started_at, "
                    "deadline_at, updated_at, last_error FROM investigation_runs "
                    "WHERE incident_id = $1 AND state = 'running' "
                    "ORDER BY epoch DESC LIMIT 1 FOR UPDATE",
                    incident_id,
                )
                if existing is not None:
                    return _row_to_investigation_run(existing)
                epoch = await conn.fetchval(
                    "SELECT COALESCE(MAX(epoch), 0) + 1 FROM investigation_runs "
                    "WHERE incident_id = $1",
                    incident_id,
                )
                row = await conn.fetchrow(
                    "INSERT INTO investigation_runs "
                    "(incident_id, epoch, adapter, state, deadline_at, started_at, updated_at) "
                    "VALUES ($1, $2, $3, 'running', $4, $5, $5) "
                    "RETURNING incident_id, epoch, adapter, state, tool_calls, started_at, "
                    "deadline_at, updated_at, last_error",
                    incident_id,
                    epoch,
                    adapter,
                    instant + timedelta(seconds=max_seconds),
                    instant,
                )
                await conn.execute(
                    "INSERT INTO incident_events (incident_id, kind, payload) "
                    "VALUES ($1, $2, $3::jsonb)",
                    incident_id,
                    EventKind.INVESTIGATION_STARTED.value,
                    {"epoch": epoch, "adapter": adapter},
                )
        return _row_to_investigation_run(row)

    async def get_investigation_run(
        self, incident_id: UUID, epoch: int
    ) -> Optional[InvestigationRun]:
        row = await self.pool.fetchrow(
            "SELECT incident_id, epoch, adapter, state, tool_calls, started_at, "
            "deadline_at, updated_at, last_error FROM investigation_runs "
            "WHERE incident_id = $1 AND epoch = $2",
            incident_id,
            epoch,
        )
        return _row_to_investigation_run(row) if row else None

    async def get_latest_investigation_run(
        self, incident_id: UUID
    ) -> Optional[InvestigationRun]:
        """Most recent investigation run for an incident (read-only console view)."""
        row = await self.pool.fetchrow(
            "SELECT incident_id, epoch, adapter, state, tool_calls, started_at, "
            "deadline_at, updated_at, last_error FROM investigation_runs "
            "WHERE incident_id = $1 ORDER BY epoch DESC LIMIT 1",
            incident_id,
        )
        return _row_to_investigation_run(row) if row else None

    async def set_investigation_run_state(
        self,
        incident_id: UUID,
        epoch: int,
        state: str,
        *,
        last_error: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> Optional[InvestigationRun]:
        row = await self.pool.fetchrow(
            "UPDATE investigation_runs SET state = $3, "
            "last_error = COALESCE($4, last_error), updated_at = now() "
            "WHERE incident_id = $1 AND epoch = $2 "
            "RETURNING incident_id, epoch, adapter, state, tool_calls, started_at, "
            "deadline_at, updated_at, last_error",
            incident_id,
            epoch,
            state,
            _redact_text(last_error),
        )
        return _row_to_investigation_run(row) if row else None

    async def record_investigation_step(
        self,
        incident_id: UUID,
        epoch: int,
        kind: str,
        payload: Mapping[str, Any],
        *,
        worker_id: str,
        now: Optional[datetime] = None,
        advance_tool_calls: bool = False,
    ) -> InvestigationStep:
        body = redact_structure(dict(payload))
        validate_payload(body)
        instant = ensure_utc(now or utcnow())
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await self._assert_lease(conn, incident_id, worker_id, instant)
                index = await conn.fetchval(
                    "SELECT COALESCE(MAX(step_index), 0) + 1 FROM investigation_steps "
                    "WHERE incident_id = $1 AND epoch = $2",
                    incident_id,
                    epoch,
                )
                row = await conn.fetchrow(
                    "INSERT INTO investigation_steps "
                    "(incident_id, epoch, step_index, kind, payload) "
                    "VALUES ($1, $2, $3, $4, $5::jsonb) "
                    "RETURNING id, incident_id, epoch, step_index, kind, payload, created_at",
                    incident_id,
                    epoch,
                    index,
                    kind,
                    body,
                )
                if advance_tool_calls:
                    await conn.execute(
                        "UPDATE investigation_runs "
                        "SET tool_calls = LEAST(tool_calls + 1, 12), updated_at = now() "
                        "WHERE incident_id = $1 AND epoch = $2",
                        incident_id,
                        epoch,
                    )
        return _row_to_investigation_step(row)

    async def list_investigation_steps(
        self, incident_id: UUID, epoch: int
    ) -> list[InvestigationStep]:
        rows = await self.pool.fetch(
            "SELECT id, incident_id, epoch, step_index, kind, payload, created_at "
            "FROM investigation_steps WHERE incident_id = $1 AND epoch = $2 "
            "ORDER BY step_index",
            incident_id,
            epoch,
        )
        return [_row_to_investigation_step(row) for row in rows]

    async def append_investigation_evidence(
        self,
        incident_id: UUID,
        epoch: int,
        source: str,
        evidence_type: EvidenceType,
        payload: Mapping[str, Any],
        *,
        worker_id: str,
        now: Optional[datetime] = None,
    ) -> Evidence:
        body = redact_structure(dict(payload))
        validate_payload(body)
        instant = ensure_utc(now or utcnow())
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await self._assert_lease(conn, incident_id, worker_id, instant)
                row = await conn.fetchrow(
                    "INSERT INTO incident_evidence "
                    "(incident_id, source, evidence_type, payload, epoch) "
                    "VALUES ($1, $2, $3, $4::jsonb, $5) "
                    "RETURNING id, incident_id, source, evidence_type, observed_at, payload, epoch",
                    incident_id,
                    source,
                    EvidenceType(evidence_type).value,
                    body,
                    epoch,
                )
                await conn.execute(
                    "INSERT INTO incident_events (incident_id, kind, payload) "
                    "VALUES ($1, $2, $3::jsonb)",
                    incident_id,
                    EventKind.EVIDENCE_RECORDED.value,
                    {"evidence_id": str(row["id"]), "evidence_type": row["evidence_type"]},
                )
        return _row_to_evidence(row)

    async def create_investigation_proposal(
        self,
        incident_id: UUID,
        epoch: int,
        *,
        service_id: str,
        expected_generation: int,
        current_revision: str,
        target_revision: str,
        evidence_ids: Iterable[UUID],
        digest: str,
        worker_id: str,
        now: Optional[datetime] = None,
    ) -> Proposal:
        """Persist a gated proposal, but only while the caller still owns the
        lease and the incident is still ``investigating``.

        A stale owner that lost its lease for the current epoch can therefore
        never write a proposal or advance the incident.
        """

        instant = ensure_utc(now or utcnow())
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                current = await conn.fetchrow(
                    "SELECT lease_owner, lease_expires_at, state FROM incidents "
                    "WHERE id = $1 FOR UPDATE",
                    incident_id,
                )
                if current is None:
                    raise NotFound(f"incident {incident_id} not found")
                lease_ok = (
                    current["lease_owner"] == worker_id
                    and current["lease_expires_at"] is not None
                    and ensure_utc(current["lease_expires_at"]) > instant
                )
                if not lease_ok:
                    raise LeaseLost(f"lease for {incident_id} not held by {worker_id}")
                if current["state"] != IncidentState.INVESTIGATING.value:
                    raise IllegalStateTransition(
                        f"cannot propose while incident is {current['state']}"
                    )
                row = await conn.fetchrow(
                    "INSERT INTO proposals (incident_id, service_id, expected_generation, "
                    "current_revision, target_revision, evidence_ids, digest) "
                    "VALUES ($1, $2, $3, $4, $5, $6, $7) "
                    "RETURNING id, incident_id, service_id, expected_generation, "
                    "current_revision, target_revision, evidence_ids, digest, created_at",
                    incident_id,
                    service_id,
                    expected_generation,
                    current_revision,
                    target_revision,
                    list(evidence_ids),
                    digest,
                )
                await conn.execute(
                    "INSERT INTO incident_events (incident_id, kind, payload) "
                    "VALUES ($1, $2, $3::jsonb)",
                    incident_id,
                    EventKind.PROPOSAL_CREATED.value,
                    redact_structure(
                        {
                            "proposal_id": str(row["id"]),
                            "digest": digest,
                            "epoch": epoch,
                            "target_revision": target_revision,
                        }
                    ),
                )
        return _row_to_proposal(row)

    async def escalate_investigation(
        self,
        incident_id: UUID,
        worker_id: str,
        *,
        reason: str,
        now: Optional[datetime] = None,
        epoch: Optional[int] = None,
    ) -> Incident:
        """Escalate an incident only while the caller owns its
        ``investigating`` lease; a stale owner is refused and changes nothing."""

        instant = ensure_utc(now or utcnow())
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    f"UPDATE incidents SET state = $3, lease_expires_at = NULL, "
                    f"updated_at = now(), version = version + 1 "
                    f"WHERE id = $1 AND lease_owner = $2 AND lease_expires_at > $4 "
                    f"AND state = $5 RETURNING {_COLS_Q}",
                    incident_id,
                    worker_id,
                    IncidentState.ESCALATED.value,
                    instant,
                    IncidentState.INVESTIGATING.value,
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
                        raise LeaseLost(f"lease for {incident_id} not held by {worker_id}")
                    raise IllegalStateTransition(
                        f"cannot escalate incident in state {current['state']}"
                    )
                await conn.execute(
                    "INSERT INTO incident_events (incident_id, kind, payload) "
                    "VALUES ($1, $2, $3::jsonb)",
                    incident_id,
                    EventKind.ESCALATED.value,
                    redact_structure({"reason": reason, "epoch": epoch}),
                )
        return _row_to_incident(row)

    async def get_deployment_snapshot(self, *, service_id: str = SERVICE_ID):
        """Authoritative active deployment snapshot, read from PostgreSQL."""

        from .contracts import DeploymentSnapshot

        row = await self.pool.fetchrow(
            "SELECT service_id, revision, generation, activated_at, predecessor "
            "FROM deployment_state WHERE service_id = $1",
            service_id,
        )
        if row is None:
            raise NotFound("deployment_state is not initialised")
        return DeploymentSnapshot(
            service_id=row["service_id"],
            revision=row["revision"],
            generation=row["generation"],
            activated_at=row["activated_at"],
            predecessor=row["predecessor"],
        )

    async def list_deployment_history(
        self, *, service_id: str = SERVICE_ID, limit: int = 20
    ) -> list[dict[str, Any]]:
        rows = await self.pool.fetch(
            "SELECT from_revision, to_revision, generation, activated_at "
            "FROM deployment_history WHERE service_id = $1 ORDER BY id DESC LIMIT $2",
            service_id,
            limit,
        )
        return [dict(row) for row in rows]


def _row_to_investigation_run(row: asyncpg.Record) -> InvestigationRun:
    return InvestigationRun(
        incident_id=row["incident_id"],
        epoch=row["epoch"],
        adapter=row["adapter"],
        state=row["state"],
        tool_calls=row["tool_calls"],
        started_at=row["started_at"],
        deadline_at=row["deadline_at"],
        updated_at=row["updated_at"],
        last_error=row["last_error"],
    )


def _row_to_investigation_step(row: asyncpg.Record) -> InvestigationStep:
    return InvestigationStep(
        id=row["id"],
        incident_id=row["incident_id"],
        epoch=row["epoch"],
        step_index=row["step_index"],
        kind=row["kind"],
        payload=row["payload"],
        created_at=row["created_at"],
    )


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
        service_id=row["service_id"],
        expected_generation=row["expected_generation"],
        attempts=row["attempts"],
        last_error=row["last_error"],
        verified_at=row["verified_at"],
    )


def _row_to_reservation(row: asyncpg.Record) -> Reservation:
    return Reservation(
        operation_id=row["operation_id"],
        service_id=row["service_id"],
        scope=row["scope"],
        status=row["status"],
        expected_generation=row["expected_generation"],
        target_revision=row["target_revision"],
        created_at=row["created_at"],
        released_at=row["released_at"],
    )
