"""Validated public/internal payloads and state enums for Milestone 1.

The revision set is fixed: the gateway may only ever route to a predefined
healthy or broken demo deployment. No caller may supply a destination.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

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
