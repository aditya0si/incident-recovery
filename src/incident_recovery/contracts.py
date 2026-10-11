"""Validated public/internal payloads and state enums for Milestone 1.

The revision set is fixed: the gateway may only ever route to a predefined
healthy or broken demo deployment. No caller may supply a destination.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .models import validate_payload

SERVICE_ID = "demo-api"

Revision = Literal["healthy-v1", "broken-v2"]

REVISIONS: tuple[str, ...] = ("healthy-v1", "broken-v2")


class DeploymentSnapshot(BaseModel):
    """Authoritative active deployment state read from PostgreSQL."""

    model_config = ConfigDict(frozen=True)

    service_id: str
    revision: Revision
    generation: int = Field(ge=1)
    activated_at: datetime
    predecessor: Optional[Revision] = None


class SwitchRequest(BaseModel):
    """Internal compare-and-set switch request.

    Extra fields are forbidden so a caller cannot smuggle a destination or any
    other override into the switch.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: UUID
    expected_generation: int = Field(ge=1)
    target_revision: Revision


class OperationRecord(BaseModel):
    """Persisted idempotency record for a previously applied switch."""

    model_config = ConfigDict(frozen=True)

    operation_id: UUID
    service_id: str
    expected_generation: int
    target_revision: Revision
    snapshot: DeploymentSnapshot


class SwitchDecision(BaseModel):
    """Outcome of evaluating a switch request against current state.

    ``snapshot`` is the resulting state for applied/replayed and the unchanged
    current state for stale/conflict.
    """

    model_config = ConfigDict(frozen=True)

    status: Literal["applied", "replayed", "stale", "conflict"]
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


class IncidentDetail(IncidentSummary):
    model_config = ConfigDict(frozen=True)

    evidence: List[EvidenceView] = Field(default_factory=list)
    events: List[EventView] = Field(default_factory=list)


class FaultRequest(BaseModel):
    """Authenticated demo fault injection. Only the fixed broken revision is valid."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_revision: Literal["broken-v2"] = "broken-v2"


class FaultResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: str
    snapshot: DeploymentSnapshot
    reconciled: bool = False
