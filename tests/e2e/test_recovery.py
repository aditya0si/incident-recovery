"""Real Docker end-to-end approval-gated rollback for Milestone 3.

These run against the live Compose stack (``incident-recovery`` project) with the
durable recovery worker and restricted executor running.  Every deployment and
verification assertion is the result of a real container response: the fault is
injected through the authenticated API, the approval goes through the API, and
the rollback plus sustained functional checks are performed by the real worker.
No API response is manufactured here.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import time
import uuid
from dataclasses import dataclass

import asyncpg
import httpx
import pytest
import pytest_asyncio

from incident_recovery import db as db_module
from incident_recovery.contracts import SwitchRequest
from incident_recovery.gateway import DeploymentStore
from incident_recovery.models import IncidentState
from incident_recovery.repository import IncidentRepository

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://127.0.0.1:18080")
API_URL = os.environ.get("API_URL", f"http://127.0.0.1:{os.environ.get('API_PORT', '18082')}")
OPERATOR_TOKEN = os.environ.get("OPERATOR_TOKEN", "")
HEALTHY = "healthy-v1"
BROKEN = "broken-v2"


def _host_dsn() -> str:
    user = os.environ.get("POSTGRES_USER")
    password = os.environ.get("POSTGRES_PASSWORD")
    name = os.environ.get("POSTGRES_DB")
    port = os.environ.get("POSTGRES_PORT", "15432")
    if not (user and password and name):
        raise RuntimeError("E2E recovery tests require POSTGRES_* values in .env")
    return f"postgresql://{user}:{password}@127.0.0.1:{port}/{name}"


def _wait_ready(url: str, timeout: float = 90.0) -> None:
    deadline = time.time() + timeout
    last = "no attempt"
    while time.time() < deadline:
        try:
            response = httpx.get(url, timeout=3.0)
            if response.status_code == 200:
                return
            last = f"status {response.status_code}"
        except Exception as exc:  # noqa: BLE001 - recorded as evidence
            last = repr(exc)
        time.sleep(1.0)
    raise AssertionError(f"{url} not ready within {timeout}s: {last}")


@dataclass
class Live:
    api_url: str
    gateway_url: str
    token: str

    def auth(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}


@pytest_asyncio.fixture
async def live() -> Live:
    if not OPERATOR_TOKEN:
        pytest.fail(
            "OPERATOR_TOKEN is not set. Generate it in .env and bring the stack up "
            "before running the real recovery E2E suite."
        )
    try:
        _wait_ready(f"{GATEWAY_URL}/healthz")
        _wait_ready(f"{API_URL}/healthz")
    except AssertionError as exc:
        pytest.fail(f"stack not reachable; bring it up first: {exc}")
    return Live(api_url=API_URL, gateway_url=GATEWAY_URL, token=OPERATOR_TOKEN)


@pytest_asyncio.fixture
async def pool(live: Live):
    connection = await db_module.create_pool(_host_dsn())
    try:
        yield connection
    finally:
        await connection.close()


async def _release_reservations(pool: asyncpg.Pool) -> None:
    await pool.execute(
        "UPDATE deployment_reservations SET status = 'released', released_at = now() "
        "WHERE status = 'active'"
    )


async def _restore_healthy(pool: asyncpg.Pool) -> None:
    await _release_reservations(pool)
    store = DeploymentStore(pool)
    repo = IncidentRepository(pool)
    snapshot = await store.get_snapshot()
    if snapshot.revision == HEALTHY:
        return
    operation_id = uuid.uuid4()
    await repo.reserve(
        operation_id,
        scope="fault",
        expected_generation=snapshot.generation,
        target_revision=HEALTHY,
    )
    try:
        decision = await store.switch(
            SwitchRequest(
                operation_id=operation_id,
                expected_generation=snapshot.generation,
                target_revision=HEALTHY,
                scope="fault",
            )
        )
        assert decision.status == "applied"
    finally:
        await repo.release_reservation(operation_id)


async def _inject_fault(live: Live, revision: str = BROKEN) -> None:
    response = httpx.post(
        f"{live.api_url}/demo/faults",
        json={"target_revision": revision},
        headers=live.auth(),
        timeout=10.0,
    )
    assert response.status_code == 200, response.text


async def _awaiting_incident_with_proposal(
    pool: asyncpg.Pool, service_id: str = "demo-api"
) -> tuple[uuid.UUID, str, str]:
    # The worker now auto-investigates `detected` incidents, so this Task 3 suite
    # deliberately seeds its incident directly in `awaiting_approval` with an
    # explicit proposal.  That isolates the approval/recovery path under test
    # instead of racing the investigation stage; it is test-side setup, not a
    # production debug route.
    repo = IncidentRepository(pool)
    store = DeploymentStore(pool)
    incident_id = uuid.uuid4()
    await pool.execute(
        "INSERT INTO incidents "
        "(id, dedupe_key, service_id, state, summary, alert_payload, detected_at, updated_at, version) "
        "VALUES ($1, $2, $3, 'awaiting_approval', $4, '{}'::jsonb, now(), now(), 2)",
        incident_id,
        f"e2e-{uuid.uuid4()}",
        service_id,
        "broken deployment",
    )
    snapshot = await store.get_snapshot()
    digest = uuid.uuid4().hex
    await repo.create_proposal(
        incident_id=incident_id,
        service_id=service_id,
        expected_generation=snapshot.generation,
        current_revision=snapshot.revision,
        target_revision=snapshot.predecessor,
        evidence_ids=[],
        digest=digest,
    )
    return incident_id, digest, snapshot.revision


async def _wait_for_state(
    live: Live, incident_id: uuid.UUID, states: set[str], timeout: float = 90.0
) -> dict:
    deadline = time.time() + timeout
    last: dict = {}
    while time.time() < deadline:
        response = httpx.get(f"{live.api_url}/incidents/{incident_id}", timeout=10.0)
        if response.status_code == 200:
            last = response.json()
            if last["state"] in states:
                return last
        time.sleep(1.0)
    raise AssertionError(f"incident {incident_id} did not reach {states} in {timeout}s: {last}")


async def _delete_incident(pool: asyncpg.Pool, incident_id: uuid.UUID) -> None:
    await pool.execute("DELETE FROM incidents WHERE id = $1", incident_id)


# --- approved rollback with sustained functional checks ----------------------


async def test_approved_rollback_returns_real_traffic_and_verifies(
    live: Live, pool: asyncpg.Pool
) -> None:
    await _restore_healthy(pool)
    incident_id: uuid.UUID | None = None
    try:
        await _inject_fault(live)
        broken_work = httpx.get(f"{live.gateway_url}/api/work", timeout=5.0)
        assert broken_work.status_code == 500
        assert broken_work.json()["ok"] is False

        incident_id, digest, current = await _awaiting_incident_with_proposal(pool)
        assert current == BROKEN

        # No recovery may occur before approval.
        before = httpx.get(f"{live.gateway_url}/snapshot", timeout=5.0).json()
        assert before["revision"] == BROKEN

        approved = httpx.post(
            f"{live.api_url}/incidents/{incident_id}/approve",
            json={"proposal_digest": digest, "actor": "e2e-operator"},
            headers=live.auth(),
            timeout=10.0,
        )
        assert approved.status_code == 200, approved.text
        assert approved.json()["operation"]["status"] in ("pending", "executing")

        detail = await _wait_for_state(live, incident_id, {"resolved", "recovery_failed"})
        assert detail["state"] == "resolved", detail
        assert detail["operation"]["status"] == "verified"
        assert detail["verification"] is not None
        assert detail["verification"]["consecutive_successes"] >= 3
        assert detail["verification"]["checks"] >= 3
        assert detail["approval"]["actor"] == "e2e-operator"

        # Real traffic is healthy again through the stable gateway.
        healthy_work = httpx.get(f"{live.gateway_url}/api/work", timeout=5.0)
        assert healthy_work.status_code == 200 and healthy_work.json()["ok"] is True
        assert httpx.get(f"{live.gateway_url}/snapshot", timeout=5.0).json()["revision"] == HEALTHY

        events = [event["kind"] for event in detail["events"]]
        assert "approved" in events
        assert "recovery_executed" in events
        assert "recovery_verified" in events
    finally:
        if incident_id is not None:
            await _delete_incident(pool, incident_id)
        await _restore_healthy(pool)


# --- rejection --------------------------------------------------------------


async def test_rejection_prevents_recovery(live: Live, pool: asyncpg.Pool) -> None:
    await _restore_healthy(pool)
    incident_id: uuid.UUID | None = None
    try:
        await _inject_fault(live)
        incident_id, digest, _ = await _awaiting_incident_with_proposal(pool)

        rejected = httpx.post(
            f"{live.api_url}/incidents/{incident_id}/reject",
            json={"actor": "e2e-operator", "proposal_digest": digest, "reason": "hold"},
            headers=live.auth(),
            timeout=10.0,
        )
        assert rejected.status_code == 200, rejected.text
        assert rejected.json()["state"] == "rejected"

        # Give the worker a moment; it must not recover a rejected incident.
        await asyncio.sleep(3)
        detail = httpx.get(f"{live.api_url}/incidents/{incident_id}", timeout=10.0).json()
        assert detail["state"] == "rejected"
        assert detail["operation"] is None
        assert httpx.get(f"{live.gateway_url}/snapshot", timeout=5.0).json()["revision"] == BROKEN
    finally:
        if incident_id is not None:
            await _delete_incident(pool, incident_id)
        await _restore_healthy(pool)


# --- worker process restart during recovery ---------------------------------


async def test_worker_restart_resumes_pending_recovery(
    live: Live, pool: asyncpg.Pool
) -> None:
    await _restore_healthy(pool)
    incident_id: uuid.UUID | None = None
    try:
        await _inject_fault(live)
        incident_id, digest, _ = await _awaiting_incident_with_proposal(pool)

        # Stop the real worker so the approval persists but cannot be executed.
        subprocess.run(
            ["docker", "compose", "-p", "incident-recovery", "stop", "worker"],
            check=True,
            capture_output=True,
        )
        approved = httpx.post(
            f"{live.api_url}/incidents/{incident_id}/approve",
            json={"proposal_digest": digest, "actor": "e2e-operator"},
            headers=live.auth(),
            timeout=10.0,
        )
        assert approved.status_code == 200, approved.text

        # A real (re)start of the worker process must resume from persisted state.
        subprocess.run(
            ["docker", "compose", "-p", "incident-recovery", "start", "worker"],
            check=True,
            capture_output=True,
        )
        detail = await _wait_for_state(live, incident_id, {"resolved", "recovery_failed"})
        assert detail["state"] == "resolved", detail
        assert httpx.get(f"{live.gateway_url}/snapshot", timeout=5.0).json()["revision"] == HEALTHY
    finally:
        subprocess.run(
            ["docker", "compose", "-p", "incident-recovery", "start", "worker"],
            capture_output=True,
        )
        if incident_id is not None:
            await _delete_incident(pool, incident_id)
        await _restore_healthy(pool)
