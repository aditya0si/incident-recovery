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

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from incident_recovery.agent import InvestigationAgent
from incident_recovery.contracts import (
    Diagnosis,
    SwitchDecision,
    SwitchRequest,
    ToolRequest,
)
from incident_recovery.executor import RecoveryExecutor
from incident_recovery.gateway import DeploymentStore
from incident_recovery.models import (
    OPERATION_EXECUTED,
    OPERATION_EXECUTING,
    EventKind,
    EvidenceType,
    IncidentState,
    LeaseLost,
    ModelProtocolError,
    utcnow,
)
from incident_recovery.repository import IncidentRepository
from incident_recovery.tools import MAX_RESPONSE_BYTES, ToolRunner

from .conftest import IntegrationDB, RealSwitchClient

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


# --- Finding 1: admission time must be refreshed after lock waits -------------


async def test_switch_expiry_after_lock_wait_cannot_mutate(
    test_db: IntegrationDB,
) -> None:
    """An approval that expires while the switch waits on the row lock is refused.

    The authoritative admission time is read with ``clock_timestamp()`` *after*
    the row lock is acquired, so a long lock wait cannot resurrect an expired
    approval.  The switch must not mutate ``deployment_state``.
    """

    repo = IncidentRepository(test_db.pool)
    store = DeploymentStore(test_db.pool)
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(
        incident.id, proposal.digest, "alice", ttl_seconds=1, now=utcnow()
    )

    holder = await test_db.pool.acquire()
    tx = holder.transaction()
    await tx.start()
    try:
        await holder.fetchrow(
            "SELECT service_id FROM deployment_state WHERE service_id = $1 FOR UPDATE",
            "demo-api",
        )
        switch_task = asyncio.create_task(
            store.switch(
                SwitchRequest(
                    operation_id=operation.id,
                    expected_generation=operation.expected_generation,
                    target_revision=operation.target_revision,
                    scope="recovery",
                )
            )
        )
        # Give the switch time to block on the lock, then outlive the 1s TTL.
        await asyncio.sleep(0.2)
        await asyncio.sleep(1.2)
    finally:
        await tx.rollback()
        await test_db.pool.release(holder)

    decision = await asyncio.wait_for(switch_task, timeout=10)
    assert decision.status == "unauthorized"
    assert (await store.get_snapshot()).revision == BROKEN
    assert (
        await repo.pool.fetchval(
            "SELECT count(*) FROM deployment_operations WHERE operation_id = $1",
            operation.id,
        )
        == 0
    )


# --- Round 2 Finding 2: expiry must be enforced after the awaited approval SELECT


async def test_expiry_enforced_after_awaited_approval_select(
    test_db: IntegrationDB,
) -> None:
    """An approval that expires while the recovery admission SELECT waits is refused.

    A competing transaction holds ``ACCESS EXCLUSIVE`` on ``approvals``, so the
    switch blocks inside the awaited approval ``SELECT ... JOIN``.  The approval
    expires during that wait.  The authoritative admission time must be sampled
    *after* the SELECT returns (atomically in the same query), so the switch is
    refused and performs no mutation.  Pre-fix, the clock was sampled before the
    SELECT and the switch applied with three writes.
    """

    repo = IncidentRepository(test_db.pool)
    store = DeploymentStore(test_db.pool)
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(
        incident.id, proposal.digest, "alice", ttl_seconds=1, now=utcnow()
    )

    blocker = await test_db.pool.acquire()
    await blocker.execute("BEGIN")
    await blocker.execute("LOCK TABLE approvals IN ACCESS EXCLUSIVE MODE")
    try:
        switch_task = asyncio.create_task(
            store.switch(
                SwitchRequest(
                    operation_id=operation.id,
                    expected_generation=operation.expected_generation,
                    target_revision=operation.target_revision,
                    scope="recovery",
                )
            )
        )
        # Let the switch block on the approval SELECT, then outlive the 1s TTL.
        await asyncio.sleep(0.3)
        await asyncio.sleep(1.3)
    finally:
        await blocker.execute("ROLLBACK")
        await test_db.pool.release(blocker)

    decision = await asyncio.wait_for(switch_task, timeout=10)
    assert decision.status == "unauthorized"
    assert (await store.get_snapshot()).revision == BROKEN
    assert (
        await repo.pool.fetchval(
            "SELECT count(*) FROM deployment_operations WHERE operation_id = $1",
            operation.id,
        )
        == 0
    )
    assert (
        await repo.pool.fetchval(
            "SELECT count(*) FROM deployment_history WHERE operation_id = $1",
            operation.id,
        )
        == 0
    )


# --- Finding 2: crash window reconciliation -----------------------------------

async def _seed_durable_switch_without_execution(
    repo: IncidentRepository, store: DeploymentStore
) -> tuple[object, object]:
    """Simulate a crash after the durable switch but before record_execution.

    Test-side interruption only: the real gateway switch is applied (creating the
    durable operation record), the approval is then expired, and no
    ``record_execution`` is written.  No production debug hook is involved.
    """

    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    approval, operation, _ = await repo.approve_incident(
        incident.id, proposal.digest, "alice", ttl_seconds=300, now=utcnow()
    )
    assert await repo.consume_approval(approval.id, operation.id)
    await repo.set_operation_status(operation.id, OPERATION_EXECUTING, bump_attempts=True)

    decision = await store.switch(
        SwitchRequest(
            operation_id=operation.id,
            expected_generation=operation.expected_generation,
            target_revision=operation.target_revision,
            scope="recovery",
        )
    )
    assert decision.status == "applied"
    assert (await store.get_snapshot()).revision == HEALTHY

    # The process "died" here; the approval later expired.
    await repo.pool.execute(
        "UPDATE approvals SET expires_at = now() - interval '5 seconds' WHERE id = $1",
        approval.id,
    )
    return incident, operation


async def test_switch_replays_exact_durable_operation_after_expiry(
    test_db: IntegrationDB,
) -> None:
    repo = IncidentRepository(test_db.pool)
    store = DeploymentStore(test_db.pool)
    _, operation = await _seed_durable_switch_without_execution(repo, store)
    before = await store.get_snapshot()

    replay = await store.switch(
        SwitchRequest(
            operation_id=operation.id,
            expected_generation=operation.expected_generation,
            target_revision=operation.target_revision,
            scope="recovery",
        )
    )
    assert replay.status == "replayed"
    assert replay.snapshot.revision == HEALTHY
    after = await store.get_snapshot()
    assert after.generation == before.generation
    assert (
        await repo.pool.fetchval(
            "SELECT count(*) FROM deployment_operations WHERE operation_id = $1",
            operation.id,
        )
        == 1
    )
    assert (
        await repo.pool.fetchval(
            "SELECT count(*) FROM deployment_history WHERE operation_id = $1",
            operation.id,
        )
        == 1
    )


async def test_switch_replay_requires_exact_scope(test_db: IntegrationDB) -> None:
    """A scope mismatch is not an exact replay and cannot be blessed."""

    repo = IncidentRepository(test_db.pool)
    store = DeploymentStore(test_db.pool)
    _, operation = await _seed_durable_switch_without_execution(repo, store)

    mismatched = await store.switch(
        SwitchRequest(
            operation_id=operation.id,
            expected_generation=operation.expected_generation,
            target_revision=operation.target_revision,
            scope="fault",
        )
    )
    assert mismatched.status != "replayed"
    assert mismatched.status != "applied"


async def test_executor_reconciles_durable_operation_on_resume(
    test_db: IntegrationDB,
) -> None:
    repo = IncidentRepository(test_db.pool)
    store = DeploymentStore(test_db.pool)
    _, operation = await _seed_durable_switch_without_execution(repo, store)

    # A later executor run (long after expiry) must reconcile, not fail closed.
    executor = RecoveryExecutor(
        repo,
        RealSwitchClient(store),
        store,
        clock=lambda: BASE + timedelta(days=1),
    )
    result = await executor.execute(operation.id)
    assert result.status == OPERATION_EXECUTED
    assert (await store.get_snapshot()).revision == HEALTHY
    assert (await repo.get_operation(operation.id)).status == OPERATION_EXECUTED


class _RejectingButAppliedClient:
    """Applies the switch, then reports a rejected (lost-response) decision."""

    def __init__(self, store: DeploymentStore) -> None:
        self._store = store

    async def switch(self, *, operation_id, expected_generation, target_revision, scope):
        decision = await self._store.switch(
            SwitchRequest(
                operation_id=operation_id,
                expected_generation=expected_generation,
                target_revision=target_revision,
                scope=scope,
            )
        )
        assert decision.status == "applied"
        return SwitchDecision(status="unauthorized", snapshot=decision.snapshot)


async def test_executor_reconciles_when_switch_response_rejected(
    test_db: IntegrationDB,
) -> None:
    repo = IncidentRepository(test_db.pool)
    store = DeploymentStore(test_db.pool)
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(
        incident.id, proposal.digest, "alice", ttl_seconds=300, now=utcnow()
    )

    executor = RecoveryExecutor(
        repo,
        _RejectingButAppliedClient(store),
        store,
        clock=lambda: BASE,
    )
    result = await executor.execute(operation.id)
    assert result.status == OPERATION_EXECUTED
    assert (await store.get_snapshot()).revision == HEALTHY


# --- Finding 4: redaction at the repository persistence boundary --------------


async def test_repository_redacts_nested_secrets_at_persistence(
    test_db: IntegrationDB,
) -> None:
    repo = IncidentRepository(test_db.pool)
    incident, _ = await repo.ingest_alert(f"redact-{uuid.uuid4()}", "demo-api", "x", {})
    sentinel = "SYNTHETIC_SENTINEL"

    evidence = await repo.append_evidence(
        incident.id,
        "tool:metrics",
        EvidenceType.METRIC,
        {
            "password": sentinel,
            "nested": {"deeper": {"password": sentinel}},
            "list": [{"token": sentinel}],
            "revision": "broken-v2",
        },
    )
    assert evidence.payload["nested"]["deeper"]["password"] == "[REDACTED]"
    assert evidence.payload["list"][0]["token"] == "[REDACTED]"
    assert evidence.payload["revision"] == "broken-v2"

    event = await repo.append_event(
        incident.id, EventKind.EVIDENCE_RECORDED, {"api_key": sentinel, "ok": 1}
    )
    assert sentinel not in json.dumps(event.payload)
    assert event.payload["ok"] == 1

    rows = await repo.list_evidence(incident.id)
    assert sentinel not in json.dumps([row.payload for row in rows])


# --- Round 2 Finding 3: raw error/trace text write sinks ----------------------


async def test_set_operation_status_redacts_last_error(
    test_db: IntegrationDB,
) -> None:
    """The reproduced defect: the raw ``last_error`` SQL parameter leaked."""

    repo = IncidentRepository(test_db.pool)
    store = DeploymentStore(test_db.pool)
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(
        incident.id, proposal.digest, "alice", now=BASE
    )

    updated = await repo.set_operation_status(
        operation.id,
        "executing",
        last_error="password=" + "SYNTHETIC_SENTINEL",
        result={"password": "SYNTHETIC_SENTINEL", "status": "ok"},
    )
    assert "SYNTHETIC_SENTINEL" not in (updated.last_error or "")
    assert updated.result["password"] == "[REDACTED]"
    assert updated.result["status"] == "ok"

    benign = await repo.set_operation_status(
        operation.id, "executing", last_error="switch_unauthorized"
    )
    assert benign.last_error == "switch_unauthorized"


async def test_fail_recovery_redacts_error_and_event(test_db: IntegrationDB) -> None:
    repo = IncidentRepository(test_db.pool)
    store = DeploymentStore(test_db.pool)
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(
        incident.id, proposal.digest, "alice", now=BASE
    )
    await repo.claim_next_recovery("worker-a", lease_seconds=60, now=BASE)

    await repo.fail_recovery(
        incident.id,
        "worker-a",
        operation.id,
        error='password="synthetic alpha bravo"',
        result={"api_key": "SYNTHETIC_SENTINEL", "reason": "boom"},
        now=BASE,
    )
    stored = await repo.get_operation(operation.id)
    assert "synthetic" not in (stored.last_error or "")
    assert "alpha" not in (stored.last_error or "")
    events = await repo.list_events(incident.id)
    blob = json.dumps([event.payload for event in events])
    assert "synthetic" not in blob
    assert "SYNTHETIC_SENTINEL" not in blob


async def test_set_investigation_run_state_redacts_last_error(
    test_db: IntegrationDB,
) -> None:
    repo = IncidentRepository(test_db.pool)
    incident, _ = await repo.ingest_alert(
        f"runerr-{uuid.uuid4()}", "demo-api", "x", {}
    )
    await repo.claim_next_investigation("w1", lease_seconds=180, now=utcnow())
    run = await repo.ensure_investigation_run(incident.id, "scripted:test", 120, now=utcnow())

    await repo.set_investigation_run_state(
        incident.id, run.epoch, "escalated",
        last_error="token=SYNTHETIC_SENTINEL", now=utcnow(),
    )
    reloaded = await repo.get_investigation_run(incident.id, run.epoch)
    assert reloaded is not None
    assert "SYNTHETIC_SENTINEL" not in (reloaded.last_error or "")
    assert "token" in (reloaded.last_error or "")
