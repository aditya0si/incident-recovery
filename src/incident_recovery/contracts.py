"""Validated public/internal payloads and state enums for Milestone 1.

The revision set is fixed: the gateway may only ever route to a predefined
healthy or broken demo deployment. No caller may supply a destination.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .models import validate_payload

SERVICE_ID = "demo-api"

Revision = Literal["healthy-v1", "broken-v2"]

REVISIONS: tuple[str, ...] = ("healthy-v1", "broken-v2")


class DeploymentSnapshot(BaseModel):
    """Authoritative active deployment state read from PostgreSQL.

    ``revision`` is an unconstrained string at the persistence boundary because
    the same snapshot type carries the demo revisions *and* the isolated staging
    revisions; the closed revision set is enforced by the bound
    :class:`~incident_recovery.service_profile.ServiceProfile` at the gateway
    switch and by the validated :class:`SwitchRequest` input (which stays a
    demo literal).
    """

    model_config = ConfigDict(frozen=True)

    service_id: str
    revision: str = Field(min_length=1)
    generation: int = Field(ge=1)
    activated_at: datetime
    predecessor: Optional[str] = None


class SwitchRequest(BaseModel):
    """Internal compare-and-set switch request.

    Extra fields are forbidden so a caller cannot smuggle a destination or any
    other override into the switch.  Every switch must carry the reservation
    scope it is acting under; the gateway switch transaction validates the
    matching persisted reservation (and, for ``recovery``, the authoritative
    approval/operation) before it mutates ``deployment_state``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: UUID
    expected_generation: int = Field(ge=1)
    target_revision: Revision
    scope: Literal["fault", "recovery"]


class OperationRecord(BaseModel):
    """Persisted idempotency record for a previously applied switch.

    ``scope`` records the reservation scope the switch was applied under so an
    exact replay can require an exact operation/scope/request match rather than
    matching on the revision alone.
    """

    model_config = ConfigDict(frozen=True)

    operation_id: UUID
    service_id: str
    expected_generation: int
    target_revision: str = Field(min_length=1)
    snapshot: DeploymentSnapshot
    scope: Optional[str] = None


class SwitchDecision(BaseModel):
    """Outcome of evaluating a switch request against current state.

    ``snapshot`` is the resulting state for applied/replayed and the unchanged
    current state for stale/conflict.
    """

    model_config = ConfigDict(frozen=True)

    status: Literal["applied", "replayed", "stale", "conflict", "unauthorized"]
    snapshot: DeploymentSnapshot


# --- Task 2: operator API payloads -------------------------------------------


class AlertCreate(BaseModel):
    """Authenticated alert ingestion request. Extra fields are forbidden."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dedupe_key: str = Field(min_length=1, max_length=256)
    service_id: Literal["demo-api"] = SERVICE_ID
    summary: Optional[str] = Field(default=None, max_length=500)
    payload: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _payload_within_bounds(self) -> "AlertCreate":
        validate_payload(self.payload)
        return self


class AlertAccepted(BaseModel):
    """Response for a newly created or deduplicated alert."""

    model_config = ConfigDict(frozen=True)

    id: UUID
    state: str
    service_id: str
    deduplicated: bool


class IncidentSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: UUID
    service_id: str
    state: str
    summary: Optional[str] = None
    detected_at: datetime
    updated_at: datetime
    version: int


class EvidenceView(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: UUID
    incident_id: UUID
    source: str
    evidence_type: str
    observed_at: datetime
    payload: Dict[str, Any]


class EventView(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    incident_id: UUID
    kind: str
    payload: Dict[str, Any]
    created_at: datetime


class FaultRequest(BaseModel):
    """Authenticated demo fault injection. Only the fixed broken revision is valid."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_revision: Literal["broken-v2"] = "broken-v2"


class FaultResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: str
    snapshot: DeploymentSnapshot
    reconciled: bool = False


# --- Task 3: approval-gated rollback and recovery verification ---------------


class ApprovalRequest(BaseModel):
    """Operator approval. Binds an exact proposal digest; no action fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    proposal_digest: str = Field(min_length=1, max_length=256)
    actor: str = Field(min_length=1, max_length=200)


class RejectionRequest(BaseModel):
    """Operator rejection. Never executes an action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    actor: str = Field(min_length=1, max_length=200)
    proposal_digest: Optional[str] = Field(default=None, max_length=256)
    reason: Optional[str] = Field(default=None, max_length=500)


class ProposalView(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: UUID
    incident_id: UUID
    service_id: str
    expected_generation: int
    current_revision: str
    target_revision: str
    evidence_ids: List[UUID] = Field(default_factory=list)
    digest: str
    created_at: datetime


class ApprovalView(BaseModel):
    model_config = ConfigDict(frozen=True)

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
    consumed_by_operation: Optional[UUID] = None


class OperationView(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: UUID
    incident_id: UUID
    approval_id: Optional[UUID] = None
    status: str
    target_revision: str
    result: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime
    service_id: Optional[str] = None
    expected_generation: Optional[int] = None
    attempts: int = 0
    last_error: Optional[str] = None
    verified_at: Optional[datetime] = None


class VerificationView(BaseModel):
    """Sustained functional-verification outcome for the future console."""

    model_config = ConfigDict(frozen=True)

    status: str
    target_revision: str
    checks: int
    consecutive_successes: int
    required_streak: int
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    detail: Optional[str] = None


class ApprovalResult(BaseModel):
    """Response for an operator approval (idempotent for duplicate submissions)."""

    model_config = ConfigDict(frozen=True)

    approval: ApprovalView
    operation: OperationView
    created: bool


class RejectionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    incident_id: UUID
    state: str
    actor: str


class ExecuteRequest(BaseModel):
    """Internal executor request. Only a persisted operation id is accepted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: UUID


class ExecuteResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    operation: OperationView


class InvestigationRunView(BaseModel):
    """Recorded investigation identity and budget for the console.

    The adapter identity is surfaced verbatim so a scripted run is always shown
    as ``scripted:demo`` and an unavailable runtime model as
    ``missing-credentials``; it is never relabeled as a live model.
    """

    model_config = ConfigDict(frozen=True)

    incident_id: UUID
    epoch: int
    adapter: str
    state: str
    tool_calls: int
    started_at: datetime
    deadline_at: datetime
    updated_at: datetime
    last_error: Optional[str] = None


class InvestigationStepView(BaseModel):
    """A bounded logical investigation step (actual tool trace)."""

    model_config = ConfigDict(frozen=True)

    id: int
    epoch: int
    step_index: int
    kind: str
    payload: Dict[str, Any]
    created_at: datetime


class InvestigationView(BaseModel):
    model_config = ConfigDict(frozen=True)

    run: Optional[InvestigationRunView] = None
    steps: List[InvestigationStepView] = Field(default_factory=list)


class IncidentDetail(IncidentSummary):
    model_config = ConfigDict(frozen=True)

    evidence: List[EvidenceView] = Field(default_factory=list)
    events: List[EventView] = Field(default_factory=list)
    proposal: Optional[ProposalView] = None
    approval: Optional[ApprovalView] = None
    operation: Optional[OperationView] = None
    verification: Optional[VerificationView] = None
    investigation: Optional[InvestigationView] = None


def operation_view(operation) -> OperationView:
    """Map a persisted operation dataclass to its public view."""
    return OperationView(
        id=operation.id,
        incident_id=operation.incident_id,
        approval_id=operation.approval_id,
        status=operation.status,
        target_revision=operation.target_revision,
        result=operation.result,
        created_at=operation.created_at,
        updated_at=operation.updated_at,
        service_id=operation.service_id,
        expected_generation=operation.expected_generation,
        attempts=operation.attempts,
        last_error=operation.last_error,
        verified_at=operation.verified_at,
    )


def proposal_view(proposal) -> ProposalView:
    return ProposalView(
        id=proposal.id,
        incident_id=proposal.incident_id,
        service_id=proposal.service_id,
        expected_generation=proposal.expected_generation,
        current_revision=proposal.current_revision,
        target_revision=proposal.target_revision,
        evidence_ids=list(proposal.evidence_ids),
        digest=proposal.digest,
        created_at=proposal.created_at,
    )


def approval_view(approval) -> ApprovalView:
    return ApprovalView(
        id=approval.id,
        incident_id=approval.incident_id,
        proposal_id=approval.proposal_id,
        proposal_digest=approval.proposal_digest,
        service_id=approval.service_id,
        expected_revision=approval.expected_revision,
        target_revision=approval.target_revision,
        actor=approval.actor,
        status=approval.status,
        created_at=approval.created_at,
        expires_at=approval.expires_at,
        consumed_by_operation=approval.consumed_by_operation,
    )


# --- Task 4: bounded investigation contracts ---------------------------------

ToolName = Literal["health", "logs", "metrics", "deployments"]


class ToolRequest(BaseModel):
    """A bounded read-only observation request.

    Only the four fixed tool names are accepted, and the schema forbids any
    additional field, so a model can never smuggle a URL, path, container id,
    shell command, or arbitrary destination into a tool call.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: ToolName
    reason: str = Field(default="", max_length=280)
    lines: Optional[int] = Field(default=None, ge=1, le=200)

    @model_validator(mode="after")
    def _per_tool_arguments(self) -> "ToolRequest":
        if self.lines is not None and self.tool != "logs":
            raise ValueError("lines is only valid for the logs tool")
        return self


class Diagnosis(BaseModel):
    """A bounded, evidence-linked conclusion; never trusted as an authorization."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    symptoms: List[str] = Field(min_length=1, max_length=20)
    candidate_cause: str = Field(min_length=1, max_length=500)
    uncertainty: str = Field(min_length=1, max_length=500)
    evidence_ids: List[UUID] = Field(default_factory=list, max_length=50)
    proposed_rollback: bool = False

    @model_validator(mode="after")
    def _symptom_bounds(self) -> "Diagnosis":
        for symptom in self.symptoms:
            if len(symptom) > 300:
                raise ValueError("symptom exceeds 300 characters")
        return self


class ToolObservation(BaseModel):
    model_config = ConfigDict(frozen=True)

    evidence_id: UUID
    tool: str
    observed_at: datetime
    summary: Dict[str, Any]


class InvestigationContext(BaseModel):
    """Bounded context passed to the model adapter on each step."""

    model_config = ConfigDict(frozen=True)

    incident_id: UUID
    service_id: str
    epoch: int
    step: int
    tool_calls_used: int
    max_tool_calls: int
    seconds_remaining: float
    observations: List[ToolObservation] = Field(default_factory=list)
    adapter_identity: str


@dataclass(frozen=True)
class GateDecision:
    """Deterministic proposal-gate outcome, independent of model confidence."""

    allowed: bool
    reason: str
    target_revision: Optional[str] = None
    digest: Optional[str] = None


@dataclass(frozen=True)
class InvestigationOutcome:
    status: str
    reason: str
    epoch: int
    proposal_id: Optional[UUID] = None
