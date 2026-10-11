"""Fixed contracts for the isolated tenant-api-platform staging workload.

These contracts mirror the reviewed demo contracts but bind to the *fixed*
staging service identity and its closed two-revision set.  The revision literal
is intentionally narrow: a staging switch can only ever name the healthy or the
faulty revision, never an arbitrary one, and the traffic gateway additionally
refuses any revision absent from its fixed destination map.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..models import validate_payload
from ..service_profile import (
    STAGING_FAULTY_REVISION,
    STAGING_HEALTHY_REVISION,
    STAGING_SERVICE_ID,
)

STAGING_SERVICE = STAGING_SERVICE_ID

# The closed revision set.  The literals are written out because a pydantic
# ``Literal`` cannot be built from a variable; a test asserts they match the
# profile constants exactly.
StagingRevision = Literal["tenant-api-healthy-a6f715a", "tenant-api-faulty-a6f715a"]

STAGING_REVISIONS: tuple[str, ...] = (STAGING_HEALTHY_REVISION, STAGING_FAULTY_REVISION)


class StagingSwitchRequest(BaseModel):
    """Internal staging compare-and-set switch request.

    Extra fields are forbidden so a caller cannot smuggle a destination in, and
    ``target_revision`` is a closed literal, so only the fixed healthy/faulty
    revisions are ever addressable.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: UUID
    expected_generation: int = Field(ge=1)
    target_revision: StagingRevision
    scope: Literal["fault", "recovery"]


class StagingFaultRequest(BaseModel):
    """Operator fault injection for staging. Only the fixed faulty revision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_revision: Literal["tenant-api-faulty-a6f715a"] = STAGING_FAULTY_REVISION


class StagingAlertCreate(BaseModel):
    """Authenticated staging alert. The service id is fixed, never caller-supplied."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dedupe_key: str = Field(min_length=1, max_length=256)
    service_id: Literal["tenant-api-staging"] = STAGING_SERVICE
    summary: Optional[str] = Field(default=None, max_length=500)
    payload: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _payload_within_bounds(self) -> "StagingAlertCreate":
        validate_payload(self.payload)
        return self


class StagingObservation(BaseModel):
    """One allowlisted staging observation.

    ``evidence_fields`` carries only allowlisted, source-side fields; credentials
    and raw environment values are never placed here and never reach the model.
    """

    model_config = ConfigDict(frozen=True)

    service_id: str = STAGING_SERVICE
    kind: str
    revision: Optional[str] = None
    generation: Optional[int] = None
    observed_at: datetime
    functional_ok: bool
    dependencies_ok: bool
    evidence_fields: Dict[str, Any] = Field(default_factory=dict)
