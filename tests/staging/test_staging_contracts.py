"""Fixed staging identity, closed revision set, and profile validation."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from incident_recovery.service_profile import (
    DEMO_PROFILE,
    STAGING_PROFILE,
    ProfileError,
    load_service_profile,
)
from incident_recovery.staging.contracts import (
    STAGING_FAULTY_REVISION,
    STAGING_HEALTHY_REVISION,
    STAGING_REVISIONS,
    STAGING_SERVICE_ID,
    StagingFaultRequest,
    StagingSwitchRequest,
)


def test_staging_profile_is_fixed_and_closed() -> None:
    assert STAGING_PROFILE.service_id == "tenant-api-staging"
    assert STAGING_PROFILE.revisions() == STAGING_REVISIONS
    assert set(STAGING_PROFILE.revision_targets) == set(STAGING_REVISIONS)
    assert STAGING_PROFILE.target_for("evil-v9") is None


def test_revision_literals_match_profile_constants() -> None:
    assert STAGING_HEALTHY_REVISION in STAGING_REVISIONS
    assert STAGING_FAULTY_REVISION in STAGING_REVISIONS
    assert STAGING_SERVICE_ID == STAGING_PROFILE.service_id


def test_switch_request_rejects_unknown_revision_and_extra_fields() -> None:
    with pytest.raises(ValidationError):
        StagingSwitchRequest(
            operation_id=uuid.uuid4(),
            expected_generation=1,
            target_revision="evil-v9",
            scope="fault",
        )
    with pytest.raises(ValidationError):
        StagingSwitchRequest(
            operation_id=uuid.uuid4(),
            expected_generation=1,
            target_revision=STAGING_FAULTY_REVISION,
            scope="fault",
            destination="http://attacker.invalid",
        )


def test_switch_request_accepts_only_the_two_fixed_revisions() -> None:
    for revision in STAGING_REVISIONS:
        request = StagingSwitchRequest(
            operation_id=uuid.uuid4(),
            expected_generation=1,
            target_revision=revision,
            scope="fault",
        )
        assert request.target_revision == revision


def test_fault_request_is_only_the_faulty_revision() -> None:
    req = StagingFaultRequest()
    assert req.target_revision == STAGING_FAULTY_REVISION
    with pytest.raises(ValidationError):
        StagingFaultRequest(target_revision=STAGING_HEALTHY_REVISION)


def test_load_service_profile_selects_and_fails_closed() -> None:
    assert load_service_profile({"SERVICE_PROFILE": "staging"}).service_id == "tenant-api-staging"
    assert load_service_profile({}).service_id == DEMO_PROFILE.service_id
    with pytest.raises(ProfileError):
        load_service_profile({"SERVICE_PROFILE": "arbitrary"})
