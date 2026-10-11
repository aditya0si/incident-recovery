"""Real-PostgreSQL adversarial resilience tests (Milestone 6).

These cover the deterministic adversarial cases that need a real database but no
running containers: a hostile/oversized observation, foreign and stale evidence,
malformed provider output, a stale recovery lease, and an approval that expires
during recovery admission.  Cases that can only be exercised against real
containers (worker restart, duplicate API submissions, competing reservations)
live in ``tests/e2e/test_resilience.py``.

Every test uses an isolated schema and real repository/agent/worker code; nothing
is stubbed except the HTTP observation source, which is a MockTransport.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from incident_recovery.agent import InvestigationAgent
from incident_recovery.contracts import (
    Diagnosis,
    SwitchRequest,
    ToolRequest,
)
from incident_recovery.gateway import DeploymentStore
from incident_recovery.models import (
    EvidenceType,
    IncidentState,
    LeaseLost,
    ModelProtocolError,
    utcnow,
)
from incident_recovery.repository import IncidentRepository
from incident_recovery.tools import MAX_RESPONSE_BYTES, ToolRunner

from .conftest import IntegrationDB

BASE = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
HEALTHY = "healthy-v1"
BROKEN = "broken-v2"


class _NoTools:
    """Tool double that proves a malformed provider never reaches observation."""

    async def collect(self, *args, **kwargs):
        raise AssertionError("tools must not be called")

    async def aclose(self) -> None:
        return None


async def _break_deployment(repo: IncidentRepository, store: DeploymentStore) -> None:
    snapshot = await store.get_snapshot()
    operation_id = uuid.uuid4()
    await repo.reserve(
        operation_id,
        scope="fault",
        expected_generation=snapshot.generation,
        target_revision=BROKEN,
    )
    try:
        decision = await store.switch(
            SwitchRequest(
                operation_id=operation_id,
                expected_generation=snapshot.generation,
                target_revision=BROKEN,
                scope="fault",
            )
        )
        assert decision.status == "applied"
    finally:
        await repo.release_reservation(operation_id)


async def _awaiting_incident_with_proposal(repo, store, *, ttl_seconds: int = 300):
    await _break_deployment(repo, store)
    incident, _ = await repo.ingest_alert(
        f"resilience-{uuid.uuid4()}", "demo-api", "broken deployment", {}
    )
    await repo.transition(incident.id, IncidentState.INVESTIGATING)
    await repo.transition(incident.id, IncidentState.AWAITING_APPROVAL)
    snapshot = await store.get_snapshot()
    proposal = await repo.create_proposal(
        incident_id=incident.id,
        service_id="demo-api",
        expected_generation=snapshot.generation,
        current_revision=snapshot.revision,
        target_revision=snapshot.predecessor,
        evidence_ids=[],
        digest=uuid.uuid4().hex,
    )
    return incident, proposal


# --- poisoned / oversized observations ---------------------------------------


async def test_oversized_poisoned_logs_are_bounded_redacted_and_persisted(
    test_db: IntegrationDB,
) -> None:
    repo = IncidentRepository(test_db.pool)
    incident, _ = await repo.ingest_alert(
        f"poison-{uuid.uuid4()}", "demo-api", "poisoned", {}
    )
    await repo.claim_next_investigation("w1", lease_seconds=180, now=utcnow())
    run = await repo.ensure_investigation_run(incident.id, "scripted:test", 120, now=utcnow())

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/logs"
        lines = [{"message": "y" * 900} for _ in range(200)]
        lines.append({"message": "token=supersecretvalue"})
        return httpx.Response(200, json={"lines": lines})

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://gateway.test"
    )
    tools = ToolRunner(repo, "http://gateway.test", client=client)
    try:
        evidence = await tools.collect(
            ToolRequest(tool="logs", lines=200),
            incident.id,
            run.epoch,
            worker_id="w1",
        )
    finally:
        await client.aclose()

    encoded = json.dumps(evidence.payload, separators=(",", ":"), default=str).encode("utf-8")
    assert len(encoded) <= MAX_RESPONSE_BYTES
    assert len(encoded) <= 16_384
    assert "supersecretvalue" not in json.dumps(evidence.payload)

    # It persisted as immutable evidence for this incident/epoch.
    rows = await repo.list_evidence(incident.id, epoch=run.epoch)
    assert [row.id for row in rows] == [evidence.id]
    await repo.pool.execute(
        "UPDATE incident_evidence SET payload = '{}'::jsonb WHERE id = $1", evidence.id
    )
    assert (await repo.list_evidence(incident.id, epoch=run.epoch))[0].payload != {}


# --- foreign / stale evidence -------------------------------------------------


class _CitingAdapter:
    identity = "scripted:test"

    def __init__(self, evidence_ids: list[uuid.UUID]) -> None:
        self._evidence_ids = evidence_ids

    async def next_step(self, context):
        return Diagnosis(
            symptoms=["functional failure"],
            candidate_cause="broken deployment",
            uncertainty="low",
            evidence_ids=list(self._evidence_ids),
            proposed_rollback=True,
        )


async def test_foreign_evidence_escalates_without_proposal(test_db: IntegrationDB) -> None:
    repo = IncidentRepository(test_db.pool)
    store = DeploymentStore(test_db.pool)
    await _break_deployment(repo, store)
    incident, _ = await repo.ingest_alert(f"foreign-{uuid.uuid4()}", "demo-api", "x", {})
    claimed = await repo.claim_next_investigation("w1", lease_seconds=180, now=utcnow())
    await repo.ensure_investigation_run(incident.id, "scripted:test", 120, now=utcnow())

    other, _ = await repo.ingest_alert(f"other-{uuid.uuid4()}", "demo-api", "x", {})
    foreign = await repo.append_evidence(
        other.id, "tool:health", EvidenceType.HEALTH, {"functional_ok": False, "http_status": 503}
    )

    agent = InvestigationAgent(
        repo, _NoTools(), _CitingAdapter([foreign.id]), "w1", clock=utcnow
    )
    try:
        outcome = await agent.investigate(claimed)
    finally:
        await agent.aclose()
    assert outcome.status == "escalated"
    assert outcome.reason == "foreign_evidence"
    assert await repo.get_proposal_for_incident(incident.id) is None
    assert (await repo.get_incident(incident.id)).state == IncidentState.ESCALATED


async def test_stale_epoch_evidence_escalates_without_proposal(test_db: IntegrationDB) -> None:
    repo = IncidentRepository(test_db.pool)
    store = DeploymentStore(test_db.pool)
    await _break_deployment(repo, store)
    incident, _ = await repo.ingest_alert(f"stale-{uuid.uuid4()}", "demo-api", "x", {})
    claimed = await repo.claim_next_investigation("w1", lease_seconds=180, now=utcnow())
    run = await repo.ensure_investigation_run(incident.id, "scripted:test", 120, now=utcnow())

    # Evidence from the same incident but a previous epoch is stale, not current.
    stale = await repo.append_evidence(
        incident.id,
        "tool:health",
        EvidenceType.HEALTH,
        {"functional_ok": False, "http_status": 503},
        epoch=run.epoch - 1,
    )

    agent = InvestigationAgent(
        repo, _NoTools(), _CitingAdapter([stale.id]), "w1", clock=utcnow
    )
    try:
        outcome = await agent.investigate(claimed)
    finally:
        await agent.aclose()
    assert outcome.status == "escalated"
    assert outcome.reason == "stale_evidence"
    assert await repo.get_proposal_for_incident(incident.id) is None


# --- malformed provider output -----------------------------------------------


class _RaisingAdapter:
    identity = "scripted:test"

    async def next_step(self, context):
        raise ModelProtocolError("provider_content_not_json")


async def test_malformed_provider_output_escalates_with_real_lease(
    test_db: IntegrationDB,
) -> None:
    repo = IncidentRepository(test_db.pool)
    incident, _ = await repo.ingest_alert(f"malformed-{uuid.uuid4()}", "demo-api", "x", {})
    claimed = await repo.claim_next_investigation("w1", lease_seconds=180, now=utcnow())

    agent = InvestigationAgent(
        repo, _NoTools(), _RaisingAdapter(), "w1", clock=utcnow
    )
    try:
        outcome = await agent.investigate(claimed)
    finally:
        await agent.aclose()
    assert outcome.status == "escalated"
    assert outcome.reason == "invalid_provider_json"
    run = await repo.get_investigation_run(incident.id, outcome.epoch)
    assert run is not None and run.state == "escalated"
    assert run.last_error == "invalid_provider_json"
    assert (await repo.get_incident(incident.id)).state == IncidentState.ESCALATED


# --- stale recovery lease -----------------------------------------------------


async def test_stale_lease_cannot_finalize_verification(test_db: IntegrationDB) -> None:
    repo = IncidentRepository(test_db.pool)
    store = DeploymentStore(test_db.pool)
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(
        incident.id, proposal.digest, "alice", now=BASE
    )
    await repo.claim_next_recovery("worker-a", lease_seconds=5, now=BASE)

    with pytest.raises(LeaseLost):
        await repo.finalize_verification(
            incident.id,
            "worker-a",
            operation.id,
            success=True,
            verification={"status": "verified", "checks": 3, "consecutive_successes": 3},
            now=BASE + timedelta(seconds=6),
        )
    # The stale owner could not resolve the incident or verify the operation.
    assert (await repo.get_incident(incident.id)).state == IncidentState.RECOVERING
    assert (await repo.get_operation(operation.id)).status != "verified"


# --- approval expiry during recovery admission --------------------------------


async def test_expired_approval_is_refused_at_authoritative_switch(
    test_db: IntegrationDB,
) -> None:
    repo = IncidentRepository(test_db.pool)
    store = DeploymentStore(test_db.pool)
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(
        incident.id, proposal.digest, "alice", ttl_seconds=1, now=BASE
    )

    # The approval is bound to a one-second TTL; the authoritative switch uses the
    # real wall clock, so the recovery admission must be refused.
    decision = await store.switch(
        SwitchRequest(
            operation_id=operation.id,
            expected_generation=operation.expected_generation,
            target_revision=operation.target_revision,
            scope="recovery",
        )
    )
    assert decision.status == "unauthorized"
    assert (await store.get_snapshot()).revision == BROKEN
