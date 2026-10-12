"""Real-PostgreSQL integration tests for approval-gated rollback.

Covers Task 3: no action before approval, exact digest/service/generation/target
binding, five-minute expiry, rejection, approval replay, simultaneous approval,
stale revision refusal, unsupported executor fields, changed deployment, test-side
response loss, single logical operation, failed functional recovery, and the
fault-versus-recovery reservation race.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import httpx

from incident_recovery.contracts import SwitchRequest
from incident_recovery.executor import RecoveryExecutor
from incident_recovery.gateway import DeploymentStore
from incident_recovery.models import (
    OPERATION_EXECUTED,
    OPERATION_EXECUTING,
    OPERATION_FAILED,
    IncidentState,
    ReservationConflict,
    utcnow,
)
from incident_recovery.repository import IncidentRepository
from incident_recovery.verification import FunctionalCheck, RecoveryVerifier
from incident_recovery.worker import RecoveryWorker

from .conftest import ApiHarness, IntegrationDB

BASE = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
HEALTHY = "healthy-v1"
BROKEN = "broken-v2"


def _key(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4()}"


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


async def _awaiting_incident_with_proposal(
    repo: IncidentRepository,
    store: DeploymentStore,
    *,
    target: str = HEALTHY,
    service: str = "demo-api",
    expected_generation: int | None = None,
    current_revision: str | None = None,
    digest: str | None = None,
) -> tuple[object, object]:
    await _break_deployment(repo, store)
    incident, _ = await repo.ingest_alert(_key("appr"), "demo-api", "broken", {})
    await repo.transition(incident.id, IncidentState.INVESTIGATING)
    await repo.transition(incident.id, IncidentState.AWAITING_APPROVAL)
    broken = await store.get_snapshot()
    proposal = await repo.create_proposal(
        incident_id=incident.id,
        service_id=service,
        expected_generation=(
            expected_generation if expected_generation is not None else broken.generation
        ),
        current_revision=current_revision if current_revision is not None else BROKEN,
        target_revision=target,
        evidence_ids=[],
        digest=digest or uuid.uuid4().hex,
    )
    return incident, proposal


class FakeProbe:
    def __init__(self, results: list[bool]) -> None:
        self._results = results
        self.calls = 0

    async def check(self, target_revision: str) -> FunctionalCheck:
        index = min(self.calls, len(self._results) - 1)
        ok = self._results[index]
        self.calls += 1
        return FunctionalCheck(
            ok=ok,
            revision=target_revision if ok else BROKEN,
            detail="fake",
            at=BASE,
        )


def _verifier(results: list[bool]) -> RecoveryVerifier:
    time = {"t": BASE}

    async def advancing_sleep(seconds: float) -> None:
        time["t"] += timedelta(seconds=seconds)

    def clock() -> datetime:
        return time["t"]

    return RecoveryVerifier(
        FakeProbe(results),
        interval=2.0,
        required_streak=3,
        deadline_seconds=30.0,
        sleep=advancing_sleep,
        clock=clock,
    )


# --- no action before approval ----------------------------------------------


async def test_no_operation_or_switch_before_approval(
    repo: IncidentRepository, store: DeploymentStore
) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    assert await repo.get_operation_for_incident(incident.id) is None
    assert await repo.active_reservation() is None
    # Deployment is still broken and no recovery reservation exists.
    assert (await store.get_snapshot()).revision == BROKEN


# --- approval creates exactly one logical operation -------------------------


async def test_approve_creates_one_operation_and_recovery_reservation(
    harness: ApiHarness,
) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(harness.repo, harness.store)
    response = await harness.client.post(
        f"/incidents/{incident.id}/approve",
        json={"proposal_digest": proposal.digest, "actor": "alice"},
        headers=harness.auth(),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    operation_id = uuid.UUID(body["operation"]["id"])
    assert body["created"] is True

    reread = await harness.repo.get_incident(incident.id)
    assert reread.state == IncidentState.RECOVERING
    reservation = await harness.repo.get_reservation(operation_id)
    assert reservation is not None and reservation.scope == "recovery"

    events = await harness.repo.list_events(incident.id)
    kinds = [event.kind.value for event in events]
    assert "approved" in kinds and "recovery_started" in kinds


async def test_simultaneous_approve_yields_one_logical_operation(
    harness: ApiHarness,
) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(harness.repo, harness.store)
    payload = {"proposal_digest": proposal.digest, "actor": "alice"}

    responses = await asyncio.gather(
        harness.client.post(
            f"/incidents/{incident.id}/approve", json=payload, headers=harness.auth()
        ),
        harness.client.post(
            f"/incidents/{incident.id}/approve", json=payload, headers=harness.auth()
        ),
    )
    assert [r.status_code for r in responses] == [200, 200]
    operation_ids = {r.json()["operation"]["id"] for r in responses}
    assert len(operation_ids) == 1
    count = await harness.repo.pool.fetchval(
        "SELECT count(*) FROM recovery_operations WHERE incident_id = $1", incident.id
    )
    assert count == 1


async def test_approval_replay_returns_same_operation(harness: ApiHarness) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(harness.repo, harness.store)
    payload = {"proposal_digest": proposal.digest, "actor": "alice"}
    first = await harness.client.post(
        f"/incidents/{incident.id}/approve", json=payload, headers=harness.auth()
    )
    second = await harness.client.post(
        f"/incidents/{incident.id}/approve", json=payload, headers=harness.auth()
    )
    assert first.json()["operation"]["id"] == second.json()["operation"]["id"]
    assert second.json()["created"] is False


# --- rejection --------------------------------------------------------------


async def test_rejection_never_creates_operation_and_no_switch(
    harness: ApiHarness,
) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(harness.repo, harness.store)
    response = await harness.client.post(
        f"/incidents/{incident.id}/reject",
        json={"actor": "bob", "proposal_digest": proposal.digest, "reason": "not safe"},
        headers=harness.auth(),
    )
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "rejected"
    assert await harness.repo.get_operation_for_incident(incident.id) is None
    assert await harness.repo.active_reservation() is None
    assert harness.switch.calls == []


async def test_reject_refuses_a_foreign_incident_and_leaves_it_unchanged(
    harness: ApiHarness,
) -> None:
    """A foreign service's awaiting-approval incident cannot be rejected (404)."""

    foreign, _ = await harness.repo.ingest_alert(
        _key("foreign"), "foreign-service", "foreign incident", {}
    )
    await harness.repo.transition(foreign.id, IncidentState.INVESTIGATING)
    await harness.repo.transition(foreign.id, IncidentState.AWAITING_APPROVAL)

    response = await harness.client.post(
        f"/incidents/{foreign.id}/reject",
        json={"actor": "mallory", "reason": "cross-service"},
        headers=harness.auth(),
    )
    assert response.status_code == 404, response.text
    unchanged = await harness.repo.get_incident(foreign.id)
    assert unchanged is not None and unchanged.state is IncidentState.AWAITING_APPROVAL


# --- validation: digest, service, target, generation ------------------------

async def test_unknown_digest_is_refused(harness: ApiHarness) -> None:
    incident, _ = await _awaiting_incident_with_proposal(harness.repo, harness.store)
    response = await harness.client.post(
        f"/incidents/{incident.id}/approve",
        json={"proposal_digest": "no-such-digest", "actor": "alice"},
        headers=harness.auth(),
    )
    assert response.status_code == 404
    assert await harness.repo.active_reservation() is None


async def test_stale_generation_is_refused(harness: ApiHarness) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(
        harness.repo, harness.store, expected_generation=999
    )
    response = await harness.client.post(
        f"/incidents/{incident.id}/approve",
        json={"proposal_digest": proposal.digest, "actor": "alice"},
        headers=harness.auth(),
    )
    assert response.status_code == 409
    assert await harness.repo.active_reservation() is None
    assert (await harness.repo.get_incident(incident.id)).state == IncidentState.AWAITING_APPROVAL


async def test_target_must_be_recorded_predecessor(harness: ApiHarness) -> None:
    # Propose staying/going to the currently active broken revision: refused.
    incident, proposal = await _awaiting_incident_with_proposal(
        harness.repo, harness.store, target=BROKEN
    )
    response = await harness.client.post(
        f"/incidents/{incident.id}/approve",
        json={"proposal_digest": proposal.digest, "actor": "alice"},
        headers=harness.auth(),
    )
    assert response.status_code == 409
    assert await harness.repo.active_reservation() is None


async def test_service_mismatch_is_refused(harness: ApiHarness) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(
        harness.repo, harness.store, service="other-service"
    )
    response = await harness.client.post(
        f"/incidents/{incident.id}/approve",
        json={"proposal_digest": proposal.digest, "actor": "alice"},
        headers=harness.auth(),
    )
    assert response.status_code == 409
    assert await harness.repo.active_reservation() is None


# --- executor: expiry, consumption, mutation, response loss -----------------


async def test_executor_rolls_back_broken_to_healthy(repo: IncidentRepository, store: DeploymentStore) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(incident.id, proposal.digest, "alice", now=utcnow())
    executor = RecoveryExecutor(repo, _store_client(store), store, clock=lambda: BASE)
    executed = await executor.execute(operation.id)
    assert executed.status == OPERATION_EXECUTED
    assert (await store.get_snapshot()).revision == HEALTHY

    events = await repo.list_events(incident.id)
    assert "recovery_executed" in [e.kind.value for e in events]


async def test_expired_approval_fails_closed_and_does_not_switch(
    repo: IncidentRepository, store: DeploymentStore
) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(
        incident.id, proposal.digest, "alice", ttl_seconds=1, now=BASE
    )
    executor = RecoveryExecutor(repo, _store_client(store), store, clock=lambda: BASE + timedelta(seconds=5))
    result = await executor.execute(operation.id)
    assert result.status == OPERATION_FAILED
    assert (await store.get_snapshot()).revision == BROKEN


async def test_executor_dependency_recheck_refuses_rollback_when_dependencies_fail(
    repo: IncidentRepository, store: DeploymentStore
) -> None:
    """A deployment that became dependency-unhealthy after approval is not rolled back."""

    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(incident.id, proposal.digest, "alice", now=utcnow())

    async def unhealthy() -> bool:
        return False

    executor = RecoveryExecutor(
        repo, _store_client(store), store, clock=lambda: BASE, dependency_check=unhealthy
    )
    result = await executor.execute(operation.id)
    assert result.status == OPERATION_FAILED
    assert result.last_error == "dependencies_unhealthy"
    # The rollback never happened and the approval was not consumed by the refusal.
    assert (await store.get_snapshot()).revision == BROKEN
    approval = await repo.get_approval_for_incident(incident.id)
    assert approval is not None and approval.consumed_by_operation is None


async def test_executor_dependency_recheck_allows_rollback_when_dependencies_healthy(
    repo: IncidentRepository, store: DeploymentStore
) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(incident.id, proposal.digest, "alice", now=utcnow())

    async def healthy() -> bool:
        return True

    executor = RecoveryExecutor(
        repo, _store_client(store), store, clock=lambda: BASE, dependency_check=healthy
    )
    executed = await executor.execute(operation.id)
    assert executed.status == OPERATION_EXECUTED
    assert (await store.get_snapshot()).revision == HEALTHY


async def test_executor_rechecks_dependencies_after_admission_before_switch(
    repo: IncidentRepository, store: DeploymentStore
) -> None:
    """A dependency that fails while the approval is consumed still refuses.

    Reproduces the parent's consumption-flip shape: the pre-admission check is
    healthy, but the dependency turns unhealthy during the awaited approval
    consumption, so the switch must never be invoked.
    """

    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(
        incident.id, proposal.digest, "alice", now=utcnow()
    )

    calls = {"n": 0}

    async def flips_unhealthy_after_first_check() -> bool:
        calls["n"] += 1
        return calls["n"] == 1

    client = _store_client(store)
    executor = RecoveryExecutor(
        repo,
        client,
        store,
        clock=lambda: BASE,
        dependency_check=flips_unhealthy_after_first_check,
    )
    result = await executor.execute(operation.id)
    assert result.status == OPERATION_FAILED
    assert result.last_error == "dependencies_unhealthy"
    assert calls["n"] == 2, "the dependency must be re-observed after admission"
    assert client.calls == [], "no switch may run once the dependency has flipped"
    assert (await store.get_snapshot()).revision == BROKEN
    # The admission step consumed the approval before the flip was observed.
    approval = await repo.get_approval_for_incident(incident.id)
    assert approval is not None and approval.consumed_by_operation == operation.id


class _FlipDependencyAfterStatusWrite:
    """A repo proxy that flips an external dependency during the EXECUTING write.

    It reproduces the parent's status-write-flip shape: the pre-admission
    attestation observes a healthy dependency, but the dependency turns unhealthy
    during the awaited ``set_operation_status(OPERATION_EXECUTING)`` round-trip.
    """

    def __init__(self, repo: IncidentRepository, flip) -> None:
        self._repo = repo
        self._flip = flip

    def __getattr__(self, name):
        return getattr(self._repo, name)

    async def set_operation_status(self, operation_id, status, **kwargs):
        result = await self._repo.set_operation_status(operation_id, status, **kwargs)
        if status == OPERATION_EXECUTING:
            self._flip()
        return result


async def test_executor_rechecks_dependencies_after_status_write_before_switch(
    repo: IncidentRepository, store: DeploymentStore
) -> None:
    """A dependency that fails during the executing-status write still refuses.

    Reproduces the parent's status-write-flip shape: the pre-admission attestation
    observes a healthy dependency, but the dependency turns unhealthy during the
    awaited ``set_operation_status(OPERATION_EXECUTING)`` write.  Because the final
    bounded attestation now runs *after* that write and immediately before the
    switch, the mutation is refused and recorded failed.
    """

    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(
        incident.id, proposal.digest, "alice", now=utcnow()
    )

    state = {"flipped": False}

    async def healthy_until_flip() -> bool:
        return not state["flipped"]

    def flip() -> None:
        state["flipped"] = True

    proxied = _FlipDependencyAfterStatusWrite(repo, flip)
    client = _store_client(store)
    executor = RecoveryExecutor(
        proxied, client, store, clock=lambda: BASE, dependency_check=healthy_until_flip
    )
    result = await executor.execute(operation.id)
    assert result.status == OPERATION_FAILED
    assert result.last_error == "dependencies_unhealthy"
    assert state["flipped"] is True
    assert client.calls == [], "no switch may run once the dependency has flipped"
    assert (await store.get_snapshot()).revision == BROKEN
    # The admission step consumed the approval before the flip was observed.
    approval = await repo.get_approval_for_incident(incident.id)
    assert approval is not None and approval.consumed_by_operation == operation.id


async def test_executor_fails_closed_when_a_dependency_attestation_errors(
    repo: IncidentRepository, store: DeploymentStore
) -> None:
    """A raising/missing attestation is never treated as healthy."""

    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(
        incident.id, proposal.digest, "alice", now=utcnow()
    )

    async def raises() -> bool:
        raise RuntimeError("probe unavailable")

    client = _store_client(store)
    executor = RecoveryExecutor(
        repo, client, store, clock=lambda: BASE, dependency_check=raises
    )
    result = await executor.execute(operation.id)
    assert result.status == OPERATION_FAILED
    assert result.last_error == "dependencies_unhealthy"
    assert client.calls == []
    assert (await store.get_snapshot()).revision == BROKEN


async def test_consumed_approval_cannot_authorize_second_operation(
    repo: IncidentRepository, store: DeploymentStore
) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    approval, operation, _ = await repo.approve_incident(
        incident.id, proposal.digest, "alice", now=utcnow()
    )
    executor = RecoveryExecutor(repo, _store_client(store), store, clock=lambda: BASE)
    await executor.execute(operation.id)

    # A second operation pointing at the same consumed approval is refused at
    # the authoritative switch boundary.
    other = uuid.uuid4()
    await repo.create_operation(
        operation_id=other,
        incident_id=incident.id,
        approval_id=approval.id,
        target_revision=HEALTHY,
        service_id="demo-api",
        expected_generation=operation.expected_generation,
    )
    # The gateway switch refuses an operation with no matching reservation.
    decision = await store.switch(
        SwitchRequest(
            operation_id=other,
            expected_generation=operation.expected_generation,
            target_revision=HEALTHY,
            scope="recovery",
        )
    )
    assert decision.status == "unauthorized"


async def test_response_loss_reconciles_to_single_logical_operation(
    repo: IncidentRepository, store: DeploymentStore
) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(incident.id, proposal.digest, "alice", now=utcnow())

    client = _store_client(store)
    client.after_apply_error = _switch_unreachable()
    executor = RecoveryExecutor(repo, client, store, clock=lambda: BASE)
    result = await executor.execute(operation.id)

    assert result.status == OPERATION_EXECUTED
    rows = await repo.pool.fetchval(
        "SELECT count(*) FROM deployment_operations WHERE operation_id = $1", operation.id
    )
    assert rows == 1
    assert (await store.get_snapshot()).revision == HEALTHY


async def test_reconciliation_cannot_manufacture_success_from_unrelated_change(
    repo: IncidentRepository, store: DeploymentStore
) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(incident.id, proposal.digest, "alice", now=utcnow())

    # An unrelated change moves the deployment to the target revision without
    # recording this operation. Reconciliation must key on the operation record.
    await repo.pool.execute(
        "UPDATE deployment_state SET revision = $1, generation = generation + 1, "
        "predecessor = $2 WHERE service_id = $3",
        HEALTHY,
        BROKEN,
        "demo-api",
    )

    client = _store_client(store)
    client.unreachable = True
    executor = RecoveryExecutor(repo, client, store, clock=lambda: BASE)
    result = await executor.execute(operation.id)
    assert result.status != OPERATION_EXECUTED
    assert (await repo.get_operation(operation.id)).status != OPERATION_EXECUTED


async def test_changed_deployment_fails_closed(
    repo: IncidentRepository, store: DeploymentStore
) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(incident.id, proposal.digest, "alice", now=utcnow())

    # A competing authoritative change moves the deployment while recovery owns
    # it; the switch revalidates preconditions and refuses.
    await repo.pool.execute(
        "UPDATE deployment_state SET generation = generation + 1 WHERE service_id = $1",
        "demo-api",
    )
    executor = RecoveryExecutor(repo, _store_client(store), store, clock=lambda: BASE)
    result = await executor.execute(operation.id)
    assert result.status == OPERATION_FAILED


# --- reservation race: unauthorized competing changes never win --------------


async def test_concurrent_fault_and_recovery_reservations_are_mutually_exclusive(
    repo: IncidentRepository,
) -> None:
    fault_op = uuid.uuid4()
    recovery_op = uuid.uuid4()

    async def reserve_fault() -> str:
        try:
            await repo.reserve(
                fault_op, scope="fault", expected_generation=1, target_revision=BROKEN
            )
            return "fault"
        except ReservationConflict:
            return "blocked"

    async def reserve_recovery() -> str:
        try:
            await repo.reserve(
                recovery_op, scope="recovery", expected_generation=1, target_revision=HEALTHY
            )
            return "recovery"
        except ReservationConflict:
            return "blocked"

    results = await asyncio.gather(reserve_fault(), reserve_recovery())
    assert results.count("blocked") == 1
    active = await repo.pool.fetchval(
        "SELECT count(*) FROM deployment_reservations WHERE status = 'active'"
    )
    assert active == 1


async def test_switch_refuses_operation_that_does_not_own_reservation(
    repo: IncidentRepository, store: DeploymentStore
) -> None:
    await repo.reserve(
        uuid.uuid4(), scope="recovery", expected_generation=1, target_revision=HEALTHY
    )
    decision = await store.switch(
        SwitchRequest(
            operation_id=uuid.uuid4(),
            expected_generation=1,
            target_revision=BROKEN,
            scope="fault",
        )
    )
    assert decision.status == "unauthorized"
    assert (await store.get_snapshot()).revision == HEALTHY


async def test_approved_recovery_blocks_competing_fault_injection(
    harness: ApiHarness,
) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(harness.repo, harness.store)
    approved = await harness.client.post(
        f"/incidents/{incident.id}/approve",
        json={"proposal_digest": proposal.digest, "actor": "alice"},
        headers=harness.auth(),
    )
    assert approved.status_code == 200, approved.text

    # Recovery now owns the deployment; a competing fault must not win.
    fault = await harness.client.post(
        "/demo/faults", json={"target_revision": BROKEN}, headers=harness.auth()
    )
    assert fault.status_code == 409
    assert (await harness.store.get_snapshot()).revision == BROKEN
    # The competing fault never reached the switch.
    assert harness.switch.calls == []


# --- worker: resume, verification, failure ----------------------------------


async def test_worker_resumes_recovering_after_takeover(
    repo: IncidentRepository, store: DeploymentStore
) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(incident.id, proposal.digest, "alice", now=utcnow())

    # Worker A claims but "crashes" after the mutation is applied.
    await repo.claim_next_recovery("worker-a", lease_seconds=30, now=BASE)
    client = _store_client(store)
    await RecoveryExecutor(repo, client, store, clock=lambda: BASE).execute(operation.id)

    # After the lease expires, worker B takes over and completes verification.
    later = BASE + timedelta(seconds=31)
    worker_b = RecoveryWorker(
        repo,
        RecoveryExecutor(repo, client, store, clock=lambda: later),
        _verifier([True]),
        "worker-b",
        lease_seconds=30,
        clock=lambda: later,
    )
    assert await worker_b.run_once() is True
    assert (await repo.get_incident(incident.id)).state == IncidentState.RESOLVED
    assert (await store.get_snapshot()).revision == HEALTHY
    events = await repo.list_events(incident.id)
    assert "recovery_verified" in [e.kind.value for e in events]


async def test_failed_functional_recovery_becomes_recovery_failed(
    repo: IncidentRepository, store: DeploymentStore
) -> None:
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(incident.id, proposal.digest, "alice", now=utcnow())
    worker = RecoveryWorker(
        repo,
        RecoveryExecutor(repo, _store_client(store), store, clock=lambda: BASE),
        _verifier([False]),
        "worker-a",
        lease_seconds=120,
        clock=lambda: BASE,
    )
    assert await worker.run_once() is True
    incident_state = (await repo.get_incident(incident.id)).state
    assert incident_state == IncidentState.RECOVERY_FAILED
    assert (await repo.get_operation(operation.id)).status == OPERATION_FAILED


async def test_executor_success_alone_does_not_resolve(
    repo: IncidentRepository, store: DeploymentStore
) -> None:
    """Deployment reached healthy, but failing functional checks must not resolve."""
    incident, proposal = await _awaiting_incident_with_proposal(repo, store)
    _, operation, _ = await repo.approve_incident(incident.id, proposal.digest, "alice", now=utcnow())
    worker = RecoveryWorker(
        repo,
        RecoveryExecutor(repo, _store_client(store), store, clock=lambda: BASE),
        _verifier([False]),
        "worker-a",
        lease_seconds=120,
        clock=lambda: BASE,
    )
    await worker.run_once()
    assert (await store.get_snapshot()).revision == HEALTHY
    assert (await repo.get_incident(incident.id)).state == IncidentState.RECOVERY_FAILED


# --- executor HTTP boundary -------------------------------------------------


async def test_executor_rejects_unsupported_fields_and_unknown_operation(
    test_db: IntegrationDB,
) -> None:
    from incident_recovery.executor import create_executor_app

    repo = IncidentRepository(test_db.pool)
    store = DeploymentStore(test_db.pool)
    app = create_executor_app(repo, _store_client(store), store, internal_token="exec-token")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://exec.test") as client:
        unsupported = await client.post(
            "/internal/execute",
            json={"operation_id": str(uuid.uuid4()), "command": "sh -c rm -rf /"},
            headers={"X-Internal-Token": "exec-token"},
        )
        assert unsupported.status_code == 422

        unknown = await client.post(
            "/internal/execute",
            json={"operation_id": str(uuid.uuid4())},
            headers={"X-Internal-Token": "exec-token"},
        )
        assert unknown.status_code == 404

        unauthorized = await client.post(
            "/internal/execute",
            json={"operation_id": str(uuid.uuid4())},
        )
        assert unauthorized.status_code == 401


async def test_executor_requires_persisted_operation(
    test_db: IntegrationDB,
) -> None:
    from incident_recovery.executor import create_executor_app

    repo = IncidentRepository(test_db.pool)
    store = DeploymentStore(test_db.pool)
    app = create_executor_app(repo, _store_client(store), store, internal_token="exec-token")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://exec.test") as client:
        response = await client.post(
            "/internal/execute",
            json={"operation_id": str(uuid.uuid4())},
            headers={"X-Internal-Token": "exec-token"},
        )
        assert response.status_code == 404


def _store_client(store: DeploymentStore):
    from .conftest import RealSwitchClient

    return RealSwitchClient(store)


def _switch_unreachable() -> BaseException:
    from incident_recovery.api import SwitchUnreachable

    return SwitchUnreachable("simulated response loss")
