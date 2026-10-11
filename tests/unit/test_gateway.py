"""Unit tests for the demo workload and gateway switch decision logic.

These exercise real application behaviour (the demo ASGI app and the pure
compare-and-set decision function) without Docker or PostgreSQL. The
PostgreSQL-backed store is covered by the real Docker E2E suite.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from incident_recovery.contracts import (
    SERVICE_ID,
    DeploymentSnapshot,
    OperationRecord,
    SwitchRequest,
)
from incident_recovery.demo import create_demo_app
from incident_recovery.gateway import evaluate_switch, target_for_revision

NOW = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)


def _snapshot(revision: str, generation: int, predecessor: str | None = None) -> DeploymentSnapshot:
    return DeploymentSnapshot(
        service_id=SERVICE_ID,
        revision=revision,
        generation=generation,
        activated_at=NOW,
        predecessor=predecessor,
    )


# --- demo workload: functional success vs genuine functional failure ---


def test_healthy_demo_serves_functional_success() -> None:
    client = TestClient(create_demo_app("healthy-v1"))
    work = client.get("/work")
    assert work.status_code == 200
    assert work.json()["ok"] is True
    assert client.get("/health").status_code == 200


def test_broken_demo_returns_genuine_functional_failure() -> None:
    client = TestClient(create_demo_app("broken-v2"))
    work = client.get("/work")
    assert work.status_code == 500
    assert work.json()["ok"] is False
    assert client.get("/health").status_code == 503
    # Process liveness must not be confused with functional health.
    assert client.get("/livez").status_code == 200


# --- gateway switch: compare-and-set semantics ---


def test_switch_increments_generation_and_records_predecessor() -> None:
    request = SwitchRequest(
        operation_id=uuid.uuid4(),
        expected_generation=1,
        target_revision="broken-v2",
        scope="fault",
    )
    decision = evaluate_switch(_snapshot("healthy-v1", 1), request, None, NOW)
    assert decision.status == "applied"
    assert decision.snapshot.generation == 2
    assert decision.snapshot.revision == "broken-v2"
    assert decision.snapshot.predecessor == "healthy-v1"


def test_switch_rejects_stale_generation() -> None:
    request = SwitchRequest(
        operation_id=uuid.uuid4(),
        expected_generation=1,
        target_revision="broken-v2",
        scope="fault",
    )
    decision = evaluate_switch(_snapshot("healthy-v1", 5), request, None, NOW)
    assert decision.status == "stale"
    assert decision.snapshot.generation == 5
    assert decision.snapshot.revision == "healthy-v1"


def test_exact_replay_returns_recorded_result_without_second_mutation() -> None:
    operation_id = uuid.uuid4()
    applied = evaluate_switch(
        _snapshot("healthy-v1", 1),
        SwitchRequest(
            operation_id=operation_id,
            expected_generation=1,
            target_revision="broken-v2",
            scope="fault",
        ),
        None,
        NOW,
    )
    recorded = OperationRecord(
        operation_id=operation_id,
        service_id=SERVICE_ID,
        expected_generation=1,
        target_revision="broken-v2",
        snapshot=applied.snapshot,
    )
    # State has since moved on to generation 3 (healthy). Replaying the exact
    # original request must return the recorded result, not mutate again.
    replay = evaluate_switch(
        _snapshot("healthy-v1", 3, "broken-v2"),
        SwitchRequest(
            operation_id=operation_id,
            expected_generation=1,
            target_revision="broken-v2",
            scope="fault",
        ),
        recorded,
        NOW,
    )
    assert replay.status == "replayed"
    assert replay.snapshot.generation == 2
    assert replay.snapshot.revision == "broken-v2"


def test_conflicting_replay_is_rejected() -> None:
    operation_id = uuid.uuid4()
    recorded = OperationRecord(
        operation_id=operation_id,
        service_id=SERVICE_ID,
        expected_generation=1,
        target_revision="broken-v2",
        snapshot=_snapshot("broken-v2", 2, "healthy-v1"),
    )
    decision = evaluate_switch(
        _snapshot("broken-v2", 2, "healthy-v1"),
        SwitchRequest(
            operation_id=operation_id,
            expected_generation=2,
            target_revision="healthy-v1",
            scope="fault",
        ),
        recorded,
        NOW,
    )
    assert decision.status == "conflict"


# --- no arbitrary destinations ---


def test_destination_map_is_fixed_to_predefined_services() -> None:
    assert target_for_revision("healthy-v1") == "http://demo-healthy-v1:8000"
    assert target_for_revision("broken-v2") == "http://demo-broken-v2:8000"
    assert target_for_revision("evil-v9") is None


def test_switch_request_rejects_unknown_revision_and_extra_fields() -> None:
    with pytest.raises(ValidationError):
        SwitchRequest(
            operation_id=uuid.uuid4(),
            expected_generation=1,
            target_revision="healthy-v1",
            destination="http://attacker.invalid",
        )
    with pytest.raises(ValidationError):
        SwitchRequest(
            operation_id=uuid.uuid4(), expected_generation=1, target_revision="evil-v9"
        )
