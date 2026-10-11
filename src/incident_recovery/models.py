"""Domain models, state machine, and bounded-payload rules for the workflow.

Task 1 kept deployment state in :mod:`incident_recovery.gateway`.  Task 2 adds
the durable incident workflow on the *same* PostgreSQL source of truth using
asyncpg throughout; no second ORM is introduced.

Everything that crosses a boundary (alert payloads, evidence payloads, event
payloads) is bounded before it is persisted so untrusted data cannot grow the
store without limit.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Mapping, Optional
from uuid import UUID

SERVICE_ID = "demo-api"

MAX_PAYLOAD_BYTES = 16_384
MAX_SUMMARY_LENGTH = 500
MAX_DEDUPE_KEY_LENGTH = 256


class IncidentState(str, Enum):
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    AWAITING_APPROVAL = "awaiting_approval"
    RECOVERING = "recovering"
    VERIFYING = "verifying"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    REJECTED = "rejected"
    RECOVERY_FAILED = "recovery_failed"


TERMINAL_STATES: frozenset[IncidentState] = frozenset(
    {
        IncidentState.RESOLVED,
        IncidentState.ESCALATED,
        IncidentState.REJECTED,
        IncidentState.RECOVERY_FAILED,
    }
)

CLAIMABLE_STATES: frozenset[IncidentState] = frozenset(
    {IncidentState.DETECTED, IncidentState.INVESTIGATING}
)

PENDING_RECOVERY_STATES: frozenset[IncidentState] = frozenset(
    {IncidentState.RECOVERING, IncidentState.VERIFYING}
)

# States a durable recovery worker may claim.  ``verifying`` is claimable so an
# interrupted verification resumes from persisted state after a crash.
RECOVERY_CLAIMABLE_STATES: frozenset[IncidentState] = frozenset(
    {IncidentState.RECOVERING, IncidentState.VERIFYING}
)

# Explicit, reviewable state machine.  A transition is refused unless the
# persisted current state is a legal predecessor of the requested target.
LEGAL_TRANSITIONS: dict[IncidentState, frozenset[IncidentState]] = {
    IncidentState.DETECTED: frozenset(
        {IncidentState.INVESTIGATING, IncidentState.ESCALATED, IncidentState.REJECTED}
    ),
    IncidentState.INVESTIGATING: frozenset(
        {IncidentState.AWAITING_APPROVAL, IncidentState.ESCALATED, IncidentState.REJECTED}
    ),
    IncidentState.AWAITING_APPROVAL: frozenset(
        {IncidentState.RECOVERING, IncidentState.REJECTED, IncidentState.ESCALATED}
    ),
    IncidentState.RECOVERING: frozenset(
        {
            IncidentState.VERIFYING,
            IncidentState.RECOVERY_FAILED,
            IncidentState.ESCALATED,
        }
    ),
    IncidentState.VERIFYING: frozenset(
        {IncidentState.RESOLVED, IncidentState.RECOVERY_FAILED}
    ),
    IncidentState.RESOLVED: frozenset(),
    IncidentState.ESCALATED: frozenset(),
    IncidentState.REJECTED: frozenset(),
    IncidentState.RECOVERY_FAILED: frozenset(),
}


def legal_predecessors(target: IncidentState) -> frozenset[IncidentState]:
    return frozenset(state for state, allowed in LEGAL_TRANSITIONS.items() if target in allowed)


class EventKind(str, Enum):
    """Explicit, closed set of persisted event types."""

    DETECTED = "detected"
    STATE_CHANGED = "state_changed"
    EVIDENCE_RECORDED = "evidence_recorded"
    PROPOSAL_CREATED = "proposal_created"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    RECOVERY_STARTED = "recovery_started"
    RECOVERY_EXECUTED = "recovery_executed"
    RECOVERY_VERIFIED = "recovery_verified"
    RECOVERY_FAILED = "recovery_failed"
    ESCALATED = "escalated"
    FAULT_INJECTED = "fault_injected"
    INVESTIGATION_STARTED = "investigation_started"
    DIAGNOSIS = "diagnosis"


class EvidenceType(str, Enum):
    """Explicit, closed set of persisted evidence types."""

    ALERT = "alert"
    LOG = "log_excerpt"
    METRIC = "metric"
    HEALTH = "health_check"
    DEPLOYMENT = "deployment_history"
    NOTE = "note"


class WorkflowError(Exception):
    """Base class for repository-level workflow errors."""


class NotFound(WorkflowError):
    pass


class IllegalStateTransition(WorkflowError):
    pass


class LeaseLost(WorkflowError):
    pass


class PayloadTooLarge(WorkflowError):
    pass


class ProposalNotFound(WorkflowError):
    pass


class ApprovalError(WorkflowError):
    """A proposed recovery may not be authorized; the request fails closed."""


class ApprovalExpired(ApprovalError):
    pass


class ApprovalStale(ApprovalError):
    pass


class ApprovalConsumed(ApprovalError):
    pass


class ReservationConflict(WorkflowError):
    """Another reservation already owns the deployment for this service."""


class SwitchUnreachable(RuntimeError):
    """The internal switch could not be reached or returned an unusable body."""


WORKFLOW_STATE = IncidentState

# Closed set of persisted recovery-operation statuses.
OPERATION_PENDING = "pending"
OPERATION_EXECUTING = "executing"
OPERATION_EXECUTED = "executed"
OPERATION_VERIFYING = "verifying"
OPERATION_VERIFIED = "verified"
OPERATION_FAILED = "failed"

OPERATION_TERMINAL: frozenset[str] = frozenset({OPERATION_VERIFIED, OPERATION_FAILED})

RESERVATION_SCOPE_FAULT = "fault"
RESERVATION_SCOPE_RECOVERY = "recovery"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def payload_size(payload: Mapping[str, Any]) -> int:
    encoded = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    return len(encoded)


def validate_payload(payload: Mapping[str, Any]) -> None:
    if not isinstance(payload, Mapping):
        raise PayloadTooLarge("payload must be a JSON object")
    if payload_size(payload) > MAX_PAYLOAD_BYTES:
        raise PayloadTooLarge(
            f"payload exceeds {MAX_PAYLOAD_BYTES} bytes (was {payload_size(payload)})"
        )


@dataclass(frozen=True)
class Incident:
    id: UUID
    dedupe_key: str
    service_id: str
    state: IncidentState
    summary: Optional[str]
    alert_payload: dict[str, Any]
    detected_at: datetime
    updated_at: datetime
    version: int
    lease_owner: Optional[str]
    lease_expires_at: Optional[datetime]


@dataclass(frozen=True)
class Evidence:
    id: UUID
    incident_id: UUID
    source: str
    evidence_type: EvidenceType
    observed_at: datetime
    payload: dict[str, Any]
    epoch: int = 0


@dataclass(frozen=True)
class Event:
    id: int
    incident_id: UUID
    kind: EventKind
    payload: dict[str, Any]
    created_at: datetime


@dataclass(frozen=True)
class Proposal:
    id: UUID
    incident_id: UUID
    service_id: str
    expected_generation: int
    current_revision: str
    target_revision: str
    evidence_ids: tuple[UUID, ...]
    digest: str
    created_at: datetime


@dataclass(frozen=True)
class Approval:
    id: UUID
    incident_id: UUID
    proposal_id: UUID
    proposal_digest: str
    service_id: str
    expected_revision: str
    target_revision: str
    actor: str
    status: str
    created_at: datetime
    expires_at: datetime
    consumed_by_operation: Optional[UUID]


@dataclass(frozen=True)
class Operation:
    id: UUID
    incident_id: UUID
    approval_id: Optional[UUID]
    status: str
    target_revision: str
    result: Optional[dict[str, Any]]
    created_at: datetime
    updated_at: datetime
    service_id: Optional[str] = None
    expected_generation: Optional[int] = None
    attempts: int = 0
    last_error: Optional[str] = None
    verified_at: Optional[datetime] = None


@dataclass(frozen=True)
class Reservation:
    operation_id: UUID
    service_id: str
    scope: str
    status: str
    expected_generation: int
    target_revision: str
    created_at: datetime
    released_at: Optional[datetime]


# --- Task 4: bounded investigation -------------------------------------------

# Server-enforced maxima.  Configured values may be lower but never higher.
INVESTIGATION_MAX_TOOL_CALLS = 12
INVESTIGATION_MAX_SECONDS = 120.0
INVESTIGATION_KNOWN_GOOD_TARGET = "healthy-v1"
INVESTIGATION_BROKEN_REVISION = "broken-v2"


class InvestigationRunState(str, Enum):
    """Closed set of persisted investigation-run states."""

    RUNNING = "running"
    DECIDED = "decided"
    ESCALATED = "escalated"
    FAILED = "failed"


RUN_RUNNING = InvestigationRunState.RUNNING.value
RUN_DECIDED = InvestigationRunState.DECIDED.value
RUN_ESCALATED = InvestigationRunState.ESCALATED.value
RUN_FAILED = InvestigationRunState.FAILED.value

INVESTIGATION_RUN_TERMINAL: frozenset[str] = frozenset({RUN_DECIDED, RUN_ESCALATED, RUN_FAILED})


class InvestigationStepKind(str, Enum):
    """Closed set of append-only logical step traces for one investigation epoch."""

    RUN_STARTED = "run_started"
    TOOL_REQUEST = "tool_request"
    TOOL_RESULT = "tool_result"
    DIAGNOSIS = "diagnosis"
    DECISION = "decision"
    ESCALATION = "escalation"


class ModelUnavailable(WorkflowError):
    """The configured runtime model cannot be reached or is not configured."""


class ModelProtocolError(WorkflowError):
    """The provider returned malformed or unusable step data."""


class InvestigationBudgetExhausted(WorkflowError):
    """The tool-call or wall-clock investigation budget was exhausted."""


class InsufficientEvidence(WorkflowError):
    """The proposal gate refused a conclusion with insufficient/foreign evidence."""


@dataclass(frozen=True)
class InvestigationRun:
    incident_id: UUID
    epoch: int
    adapter: str
    state: str
    tool_calls: int
    started_at: datetime
    deadline_at: datetime
    updated_at: datetime
    last_error: Optional[str]


@dataclass(frozen=True)
class InvestigationStep:
    id: int
    incident_id: UUID
    epoch: int
    step_index: int
    kind: str
    payload: dict[str, Any]
    created_at: datetime


DEFAULT_LEASE_SECONDS = 30


def lease_expiry(now: datetime, lease_seconds: int = DEFAULT_LEASE_SECONDS) -> datetime:
    return ensure_utc(now) + timedelta(seconds=lease_seconds)
