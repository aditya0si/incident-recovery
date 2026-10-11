"""Real-PostgreSQL integration tests for durable incidents and operator control.

Covers Task 2 acceptance: concurrent duplicate alert deduplication, legal state
transitions with conditional updates, immutable evidence, durable lease takeover
and stale-worker refusal, operator auth/origin enforcement, secret exclusion,
and pending-recovery fault refusal.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from incident_recovery import db as db_module
from incident_recovery.models import (
    EvidenceType,
    EventKind,
    IllegalStateTransition,
    IncidentState,
    PayloadTooLarge,
)
from incident_recovery.repository import IncidentRepository, LeaseLost, NotFound

from .conftest import ApiHarness, IntegrationDB

BASE = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def _key(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4()}"


# --- concurrent duplicate alert keys yield one incident -----------------------


async def test_concurrent_duplicate_alert_keys_yield_one_incident(test_db: IntegrationDB) -> None:
    repo = IncidentRepository(test_db.pool)
    key = _key("dup")
    results = await asyncio.gather(
        *[repo.ingest_alert(key, "demo-api", "boom", {"attempt": i}) for i in range(8)]
    )
    incident_ids = {incident.id for incident, _ in results}
    assert len(incident_ids) == 1
    assert sum(1 for _, created in results if created) == 1
    count = await test_db.pool.fetchval(
        "SELECT count(*) FROM incidents WHERE dedupe_key = $1", key
    )
    assert count == 1
    event_count = await test_db.pool.fetchval(
        "SELECT count(*) FROM incident_events WHERE incident_id = $1 AND kind = 'detected'",
        next(iter(incident_ids)),
    )
    assert event_count == 1


async def test_duplicate_alert_returns_existing_incident_via_api(harness: ApiHarness) -> None:
    body = {"dedupe_key": _key("api-dup"), "service_id": "demo-api", "summary": "disk pressure"}
    first = await harness.client.post("/alerts", json=body, headers=harness.auth())
    assert first.status_code == 201, first.text
    second = await harness.client.post("/alerts", json=body, headers=harness.auth())
    assert second.status_code == 200, second.text
    assert first.json()["id"] == second.json()["id"]
    assert second.json()["deduplicated"] is True


# --- persistence / read-back across a new connection --------------------------


async def test_incident_survives_new_connection(test_db: IntegrationDB) -> None:
    repo = IncidentRepository(test_db.pool)
    incident, _ = await repo.ingest_alert(_key("persist"), "demo-api", "s", {"a": 1})
    await repo.append_evidence(incident.id, "logs", EvidenceType.LOG, {"lines": ["x"]})

    # A brand new pool (simulating a restarted process) reads the same state back.
    fresh_pool = await db_module.create_pool(test_db.dsn, schema=test_db.schema)
    try:
        fresh_repo = IncidentRepository(fresh_pool)
        reread = await fresh_repo.get_incident(incident.id)
        assert reread is not None and reread.id == incident.id
        evidence = await fresh_repo.list_evidence(incident.id)
        assert [e.payload for e in evidence] == [{"lines": ["x"]}]
    finally:
        await fresh_pool.close()


# --- legal transitions and conditional update refusal -------------------------


async def test_illegal_state_transition_is_refused(test_db: IntegrationDB) -> None:
    repo = IncidentRepository(test_db.pool)
    incident, _ = await repo.ingest_alert(_key("state"), "demo-api", None, {})

    with pytest.raises(IllegalStateTransition):
        await repo.transition(incident.id, IncidentState.RESOLVED)

    # State is unchanged after the refused transition.
    assert (await repo.get_incident(incident.id)).state == IncidentState.DETECTED

    moved = await repo.transition(incident.id, IncidentState.INVESTIGATING)
    assert moved.state == IncidentState.INVESTIGATING
    assert moved.version == incident.version + 1

    # A transition event was appended atomically with the update.
    events = await repo.list_events(incident.id)
    assert [e.kind for e in events] == [EventKind.DETECTED, EventKind.STATE_CHANGED]
    assert events[-1].payload["to"] == "investigating"


async def test_transition_for_unknown_incident_raises_not_found(test_db: IntegrationDB) -> None:
    repo = IncidentRepository(test_db.pool)
    with pytest.raises(NotFound):
        await repo.transition(uuid.uuid4(), IncidentState.INVESTIGATING)


# --- immutable evidence -------------------------------------------------------


async def test_evidence_cannot_be_updated_or_deleted(test_db: IntegrationDB) -> None:
    repo = IncidentRepository(test_db.pool)
    incident, _ = await repo.ingest_alert(_key("evidence"), "demo-api", None, {})
    evidence = await repo.append_evidence(
        incident.id, "logs", EvidenceType.LOG, {"lines": ["original"]}
    )

    await test_db.pool.execute(
        "UPDATE incident_evidence SET payload = $1::jsonb WHERE id = $2",
        json.dumps({"tampered": True}),
        evidence.id,
    )
    await test_db.pool.execute("DELETE FROM incident_evidence WHERE id = $1", evidence.id)

    remaining = await repo.list_evidence(incident.id)
    assert len(remaining) == 1
    assert remaining[0].payload == {"lines": ["original"]}


async def test_oversized_evidence_payload_is_refused(repo: IncidentRepository) -> None:
    incident, _ = await repo.ingest_alert(_key("oversize"), "demo-api", None, {})
    with pytest.raises(PayloadTooLarge):
        await repo.append_evidence(
            incident.id, "logs", EvidenceType.LOG, {"blob": "x" * 20_000}
        )


# --- durable leases -----------------------------------------------------------


async def test_expired_lease_allows_takeover_and_stale_worker_is_refused(
    test_db: IntegrationDB,
) -> None:
    repo = IncidentRepository(test_db.pool)
    incident, _ = await repo.ingest_alert(_key("lease"), "demo-api", None, {})

    claimed = await repo.claim_next("worker-a", lease_seconds=30, now=BASE)
    assert claimed is not None and claimed.id == incident.id
    assert claimed.lease_owner == "worker-a"

    # A non-owner can never commit.
    with pytest.raises(LeaseLost):
        await repo.commit_under_lease(
            incident.id, "worker-b", IncidentState.INVESTIGATING, now=BASE
        )

    # The owner cannot commit after its own lease has expired.
    with pytest.raises(LeaseLost):
        await repo.commit_under_lease(
            incident.id,
            "worker-a",
            IncidentState.INVESTIGATING,
            now=BASE + timedelta(seconds=31),
        )

    # After expiry a different worker may take over the same incident.
    taken_over = await repo.claim_next(
        "worker-b", lease_seconds=30, now=BASE + timedelta(seconds=31)
    )
    assert taken_over is not None and taken_over.id == incident.id
    assert taken_over.lease_owner == "worker-b"

    # The stale original owner can no longer commit under the new owner's lease.
    with pytest.raises(LeaseLost):
        await repo.commit_under_lease(
            incident.id,
            "worker-a",
            IncidentState.INVESTIGATING,
            now=BASE + timedelta(seconds=32),
        )

    committed = await repo.commit_under_lease(
        incident.id,
        "worker-b",
        IncidentState.INVESTIGATING,
        lease_seconds=30,
        now=BASE + timedelta(seconds=32),
    )
    assert committed.state == IncidentState.INVESTIGATING
    assert committed.lease_owner == "worker-b"


# --- auth and origin enforcement ---------------------------------------------


async def test_read_endpoints_are_open_but_writes_require_token(harness: ApiHarness) -> None:
    anonymous = await harness.client.post(
        "/alerts", json={"dedupe_key": _key("noauth"), "service_id": "demo-api"}
    )
    assert anonymous.status_code == 401

    bad_token = await harness.client.post(
        "/alerts",
        json={"dedupe_key": _key("badauth"), "service_id": "demo-api"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert bad_token.status_code == 401

    # Read endpoints need no credentials.
    listed = await harness.client.get("/incidents")
    assert listed.status_code == 200


async def test_untrusted_origin_is_rejected_even_with_valid_token(
    harness: ApiHarness,
) -> None:
    response = await harness.client.post(
        "/alerts",
        json={"dedupe_key": _key("origin"), "service_id": "demo-api"},
        headers=harness.auth(origin="http://evil.example"),
    )
    assert response.status_code == 403
    # Nothing was written for the rejected request.
    count = await harness.repo.pool.fetchval("SELECT count(*) FROM incidents")
    assert count == 0


async def test_allowed_origin_with_token_is_accepted(harness: ApiHarness) -> None:
    response = await harness.client.post(
        "/alerts",
        json={"dedupe_key": _key("allowed"), "service_id": "demo-api"},
        headers=harness.auth(origin=harness.origin),
    )
    assert response.status_code == 201, response.text


async def test_token_is_never_echoed_in_responses_or_events(harness: ApiHarness) -> None:
    key = _key("secret")
    created = await harness.client.post(
        "/alerts",
        json={"dedupe_key": key, "service_id": "demo-api", "summary": "check"},
        headers=harness.auth(),
    )
    assert harness.token not in created.text
    incident_id = created.json()["id"]

    detail = await harness.client.get(f"/incidents/{incident_id}")
    assert harness.token not in detail.text

    events = await harness.repo.list_events(uuid.UUID(incident_id))
    assert events
    for event in events:
        assert harness.token not in json.dumps(event.payload)


# --- read models --------------------------------------------------------------


async def test_list_and_get_incident_include_evidence_and_events(harness: ApiHarness) -> None:
    created = await harness.client.post(
        "/alerts",
        json={"dedupe_key": _key("view"), "service_id": "demo-api", "summary": "s"},
        headers=harness.auth(),
    )
    assert created.status_code == 201
    incident_id = created.json()["id"]
    await harness.repo.append_evidence(
        uuid.UUID(incident_id), "logs", EvidenceType.LOG, {"lines": ["hello"]}
    )

    listing = await harness.client.get("/incidents")
    assert listing.status_code == 200
    assert any(row["id"] == incident_id for row in listing.json())

    detail = await harness.client.get(f"/incidents/{incident_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["state"] == "detected"
    assert body["evidence"][0]["payload"] == {"lines": ["hello"]}
    assert body["events"][0]["kind"] == "detected"

    missing = await harness.client.get(f"/incidents/{uuid.uuid4()}")
    assert missing.status_code == 404


# --- pending recovery blocks competing fault injection ------------------------


async def test_fault_injection_refused_while_recovery_pending(harness: ApiHarness) -> None:
    created = await harness.client.post(
        "/alerts",
        json={"dedupe_key": _key("pending"), "service_id": "demo-api"},
        headers=harness.auth(),
    )
    incident_id = uuid.UUID(created.json()["id"])
    await harness.repo.transition(incident_id, IncidentState.INVESTIGATING)
    await harness.repo.transition(incident_id, IncidentState.AWAITING_APPROVAL)
    await harness.repo.transition(incident_id, IncidentState.RECOVERING)

    response = await harness.client.post(
        "/demo/faults",
        json={"target_revision": "broken-v2"},
        headers=harness.auth(),
    )
    assert response.status_code == 409
    assert harness.switch.calls == []


async def test_fault_injection_applies_fixed_target(harness: ApiHarness) -> None:
    response = await harness.client.post(
        "/demo/faults",
        json={"target_revision": "broken-v2"},
        headers=harness.auth(),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "applied"
    assert body["snapshot"]["revision"] == "broken-v2"
    assert body["snapshot"]["generation"] == 2
    assert harness.switch.calls[0]["target_revision"] == "broken-v2"


async def test_fault_injection_rejects_unknown_target(harness: ApiHarness) -> None:
    response = await harness.client.post(
        "/demo/faults",
        json={"target_revision": "healthy-v1"},
        headers=harness.auth(),
    )
    assert response.status_code == 422
