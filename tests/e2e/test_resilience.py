"""Real Docker adversarial resilience end-to-end checks (Milestone 6).

These run against the live Compose stack with the test-only control override
(``compose.test.yaml``) and the explicit scripted-investigation override
(``compose.investigation.yaml``) applied.  Every deployment, reservation,
approval, and recovery assertion is the result of a real container or real
PostgreSQL observation.

Covered adversarial scenarios:

* duplicate alerts and duplicate approvals collapse to one logical incident /
  one logical operation through the real authenticated API,
* a worker restart resumes the same investigation epoch with the same budget and
  the same deadline (never resetting the limits),
* a competing fault injection is refused while a recovery owns the deployment,
* an approval that expired during recovery admission is refused at the
  authoritative internal switch (not just in the executor),
* the public gateway exposes no switch, the internal switch requires the internal
  token, no container is mounted with the Docker socket, and the executor
  publishes no host port,
* an unsuccessful recovery (a stale-generation admission) becomes
  ``recovery_failed`` through the real worker/executor rather than resolving,
* persisted evidence and events never contain the runtime secrets.

Test-side fixtures are used only to seed deterministic persisted state (an
investigation epoch, or a deliberately stale recovery admission) and are clearly
labelled as such; no production debug switch exists to force a race.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

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
CONTROL_URL = os.environ.get("CONTROL_URL", f"http://127.0.0.1:{os.environ.get('CONTROL_PORT', '18081')}")
OPERATOR_TOKEN = os.environ.get("OPERATOR_TOKEN", "")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "")
PROJECT = "incident-recovery"
HEALTHY = "healthy-v1"
BROKEN = "broken-v2"


def _host_dsn() -> str:
    user = os.environ.get("POSTGRES_USER")
    password = os.environ.get("POSTGRES_PASSWORD")
    name = os.environ.get("POSTGRES_DB")
    port = os.environ.get("POSTGRES_PORT", "15432")
    if not (user and password and name):
        raise RuntimeError("Resilience E2E tests require POSTGRES_* values in .env")
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


def _compose(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-p", PROJECT, *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _stop_worker() -> None:
    result = _compose("stop", "worker")
    assert result.returncode == 0, result.stderr


def _start_worker() -> None:
    result = _compose("start", "worker")
    assert result.returncode == 0, result.stderr


@dataclass
class Live:
    api_url: str
    gateway_url: str
    control_url: str
    token: str
    internal_token: str

    def auth(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}


@pytest_asyncio.fixture
async def live() -> Live:
    if not OPERATOR_TOKEN or not INTERNAL_TOKEN:
        pytest.fail(
            "OPERATOR_TOKEN and INTERNAL_TOKEN must be set in .env before running "
            "the real resilience E2E suite."
        )
    try:
        _wait_ready(f"{GATEWAY_URL}/healthz")
        _wait_ready(f"{API_URL}/healthz")
        _wait_ready(f"{CONTROL_URL}/healthz")
    except AssertionError as exc:
        pytest.fail(
            "stack not reachable; bring it up with compose.yaml + compose.test.yaml + "
            f"compose.investigation.yaml first: {exc}"
        )
    return Live(
        api_url=API_URL,
        gateway_url=GATEWAY_URL,
        control_url=CONTROL_URL,
        token=OPERATOR_TOKEN,
        internal_token=INTERNAL_TOKEN,
    )


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
        operation_id, scope="fault", expected_generation=snapshot.generation, target_revision=HEALTHY
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


def _inject_fault(live: Live) -> None:
    response = httpx.post(
        f"{live.api_url}/demo/faults",
        json={"target_revision": BROKEN},
        headers=live.auth(),
        timeout=10.0,
    )
    assert response.status_code == 200, response.text


async def _seed_awaiting(pool: asyncpg.Pool) -> tuple[uuid.UUID, str, str]:
    """Test-side fixture: persist an ``awaiting_approval`` incident + proposal."""
    repo = IncidentRepository(pool)
    store = DeploymentStore(pool)
    incident_id = uuid.uuid4()
    await pool.execute(
        "INSERT INTO incidents "
        "(id, dedupe_key, service_id, state, summary, alert_payload, detected_at, updated_at, version) "
        "VALUES ($1, $2, 'demo-api', 'awaiting_approval', $3, '{}'::jsonb, now(), now(), 2)",
        incident_id,
        f"resilience-seed-{uuid.uuid4()}",
        "seeded broken deployment",
    )
    snapshot = await store.get_snapshot()
    digest = uuid.uuid4().hex
    await repo.create_proposal(
        incident_id=incident_id,
        service_id="demo-api",
        expected_generation=snapshot.generation,
        current_revision=snapshot.revision,
        target_revision=snapshot.predecessor,
        evidence_ids=[],
        digest=digest,
    )
    return incident_id, digest, snapshot.revision


async def _seed_stale_recovery(pool: asyncpg.Pool) -> tuple[uuid.UUID, uuid.UUID]:
    """Test-side fixture: a recovery admission whose expected generation is stale.

    The real worker/executor will attempt it, the authoritative switch will refuse
    the stale generation, and the incident must end in ``recovery_failed``.
    """
    store = DeploymentStore(pool)
    repo = IncidentRepository(pool)
    await _release_reservations(pool)
    snapshot = await store.get_snapshot()
    if snapshot.revision != BROKEN:
        operation_id = uuid.uuid4()
        await repo.reserve(
            operation_id,
            scope="fault",
            expected_generation=snapshot.generation,
            target_revision=BROKEN,
        )
        try:
            await store.switch(
                SwitchRequest(
                    operation_id=operation_id,
                    expected_generation=snapshot.generation,
                    target_revision=BROKEN,
                    scope="fault",
                )
            )
        finally:
            await repo.release_reservation(operation_id)
        snapshot = await store.get_snapshot()

    stale_generation = snapshot.generation - 1
    incident_id = uuid.uuid4()
    await pool.execute(
        "INSERT INTO incidents "
        "(id, dedupe_key, service_id, state, summary, alert_payload, detected_at, updated_at, version) "
        "VALUES ($1, $2, 'demo-api', 'awaiting_approval', $3, '{}'::jsonb, now(), now(), 2)",
        incident_id,
        f"resilience-stale-{uuid.uuid4()}",
        "stale recovery admission",
    )
    proposal = await repo.create_proposal(
        incident_id=incident_id,
        service_id="demo-api",
        expected_generation=stale_generation,
        current_revision=snapshot.revision,
        target_revision=snapshot.predecessor,
        evidence_ids=[],
        digest=uuid.uuid4().hex,
    )
    approval = await repo.create_approval(
        incident_id=incident_id,
        proposal_id=proposal.id,
        proposal_digest=proposal.digest,
        service_id="demo-api",
        expected_revision=snapshot.revision,
        target_revision=snapshot.predecessor,
        actor="e2e-resilience",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    operation_id = uuid.uuid4()
    await repo.create_operation(
        operation_id=operation_id,
        incident_id=incident_id,
        approval_id=approval.id,
        target_revision=snapshot.predecessor,
        service_id="demo-api",
        expected_generation=stale_generation,
    )
    await repo.reserve(
        operation_id,
        scope="recovery",
        expected_generation=stale_generation,
        target_revision=snapshot.predecessor,
    )
    await repo.transition(incident_id, IncidentState.RECOVERING)
    return incident_id, operation_id


async def _wait_for_state(
    live: Live, incident_id: uuid.UUID, states: set[str], timeout: float = 150.0
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


async def _cleanup_incident(pool: asyncpg.Pool, incident_id: uuid.UUID | None) -> None:
    if incident_id is None:
        return
    await pool.execute(
        "UPDATE incidents SET state = 'recovery_failed', lease_owner = NULL, "
        "lease_expires_at = NULL, updated_at = now() "
        "WHERE id = $1 AND state NOT IN ('resolved','escalated','rejected','recovery_failed')",
        incident_id,
    )


# --- duplicate alerts and approvals ------------------------------------------


async def test_duplicate_alerts_collapse_through_real_api(
    live: Live, pool: asyncpg.Pool
) -> None:
    await _restore_healthy(pool)
    key = f"resilience-dup-{uuid.uuid4()}"
    async with httpx.AsyncClient(
        base_url=live.api_url, headers=live.auth(), timeout=10.0
    ) as api:
        responses = await asyncio.gather(
            *[
                api.post(
                    "/alerts",
                    json={"dedupe_key": key, "service_id": "demo-api", "summary": "duplicate"},
                )
                for _ in range(6)
            ]
        )
    ids = {response.json()["id"] for response in responses}
    assert len(ids) == 1
    assert all(response.status_code in (200, 201) for response in responses)
    assert sum(1 for response in responses if response.status_code == 201) == 1
    count = await pool.fetchval(
        "SELECT count(*) FROM incidents WHERE dedupe_key = $1", key
    )
    assert count == 1
    await _cleanup_incident(pool, uuid.UUID(next(iter(ids))))


async def test_duplicate_approvals_create_one_operation(
    live: Live, pool: asyncpg.Pool
) -> None:
    await _restore_healthy(pool)
    incident_id: uuid.UUID | None = None
    try:
        _inject_fault(live)
        incident_id, digest, current = await _seed_awaiting(pool)
        assert current == BROKEN
        payload = {"proposal_digest": digest, "actor": "e2e-resilience"}
        async with httpx.AsyncClient(
            base_url=live.api_url, headers=live.auth(), timeout=10.0
        ) as api:
            responses = await asyncio.gather(
                api.post(f"/incidents/{incident_id}/approve", json=payload),
                api.post(f"/incidents/{incident_id}/approve", json=payload),
                api.post(f"/incidents/{incident_id}/approve", json=payload),
            )
        assert all(response.status_code == 200 for response in responses)
        operation_ids = {response.json()["operation"]["id"] for response in responses}
        assert len(operation_ids) == 1
        count = await pool.fetchval(
            "SELECT count(*) FROM recovery_operations WHERE incident_id = $1", incident_id
        )
        assert count == 1
    finally:
        await _cleanup_incident(pool, incident_id)
        await _restore_healthy(pool)


# --- worker restart preserves investigation budget and epoch ------------------


async def test_worker_restart_preserves_investigation_budget_and_epoch(
    live: Live, pool: asyncpg.Pool
) -> None:
    await _restore_healthy(pool)
    _stop_worker()
    incident_id: uuid.UUID | None = None
    try:
        _inject_fault(live)
        created = httpx.post(
            f"{live.api_url}/alerts",
            json={
                "dedupe_key": f"resilience-restart-{uuid.uuid4()}",
                "service_id": "demo-api",
                "summary": "restart budget",
            },
            headers=live.auth(),
            timeout=10.0,
        )
        assert created.status_code == 201, created.text
        incident_id = uuid.UUID(created.json()["id"])

        # Test-side fixture: a partially-consumed running epoch.  A restarted
        # worker must resume this epoch instead of resetting the budget.
        deadline = datetime.now(timezone.utc) + timedelta(seconds=120)
        await pool.execute(
            "INSERT INTO investigation_runs "
            "(incident_id, epoch, adapter, state, tool_calls, deadline_at, started_at, updated_at) "
            "VALUES ($1, 1, 'scripted:demo', 'running', 1, $2, now(), now())",
            incident_id,
            deadline,
        )

        _start_worker()
        detail = await _wait_for_state(
            live, incident_id, {"awaiting_approval", "escalated"}
        )
        assert detail["state"] == "awaiting_approval", detail

        run = await pool.fetchrow(
            "SELECT epoch, tool_calls, deadline_at FROM investigation_runs "
            "WHERE incident_id = $1 ORDER BY epoch DESC LIMIT 1",
            incident_id,
        )
        assert run is not None
        assert run["epoch"] == 1, run
        assert 1 <= run["tool_calls"] <= 12, run
        assert abs((run["deadline_at"] - deadline).total_seconds()) < 0.001, run
    finally:
        _start_worker()
        await _cleanup_incident(pool, incident_id)
        await _restore_healthy(pool)


# --- competing fault while a recovery owns the deployment ---------------------


async def test_competing_fault_refused_while_recovery_pending(
    live: Live, pool: asyncpg.Pool
) -> None:
    await _restore_healthy(pool)
    _stop_worker()
    incident_id: uuid.UUID | None = None
    try:
        _inject_fault(live)
        incident_id, digest, _ = await _seed_awaiting(pool)
        approved = httpx.post(
            f"{live.api_url}/incidents/{incident_id}/approve",
            json={"proposal_digest": digest, "actor": "e2e-resilience"},
            headers=live.auth(),
            timeout=10.0,
        )
        assert approved.status_code == 200, approved.text

        competing = httpx.post(
            f"{live.api_url}/demo/faults",
            json={"target_revision": BROKEN},
            headers=live.auth(),
            timeout=10.0,
        )
        assert competing.status_code == 409
        assert httpx.get(f"{live.gateway_url}/snapshot", timeout=5.0).json()["revision"] == BROKEN
    finally:
        _start_worker()
        await _cleanup_incident(pool, incident_id)
        await _restore_healthy(pool)


# --- expired approval at the authoritative switch -----------------------------


async def test_expired_approval_refused_at_real_control_switch(
    live: Live, pool: asyncpg.Pool
) -> None:
    await _restore_healthy(pool)
    _stop_worker()
    incident_id: uuid.UUID | None = None
    try:
        _inject_fault(live)
        incident_id, digest, _ = await _seed_awaiting(pool)
        repo = IncidentRepository(pool)
        past = datetime.now(timezone.utc) - timedelta(seconds=10)
        _, operation, _ = await repo.approve_incident(
            incident_id, digest, "e2e-resilience", ttl_seconds=1, now=past
        )

        response = httpx.post(
            f"{live.control_url}/internal/switch",
            json={
                "operation_id": str(operation.id),
                "expected_generation": operation.expected_generation,
                "target_revision": operation.target_revision,
                "scope": "recovery",
            },
            headers={"X-Internal-Token": live.internal_token},
            timeout=10.0,
        )
        assert response.status_code == 409, response.text
        assert response.json()["status"] == "unauthorized"
        assert httpx.get(f"{live.gateway_url}/snapshot", timeout=5.0).json()["revision"] == BROKEN
    finally:
        _start_worker()
        await _cleanup_incident(pool, incident_id)
        await _restore_healthy(pool)


# --- unauthorized direct switch / privileged-surface boundaries ---------------


def _switch_payload() -> dict:
    return {
        "operation_id": str(uuid.uuid4()),
        "expected_generation": 1,
        "target_revision": BROKEN,
        "scope": "fault",
    }


def test_public_gateway_has_no_switch_and_control_requires_token(live: Live) -> None:
    public = httpx.post(
        f"{live.gateway_url}/internal/switch", json=_switch_payload(), timeout=10.0
    )
    assert public.status_code == 404

    missing = httpx.post(
        f"{live.control_url}/internal/switch", json=_switch_payload(), timeout=10.0
    )
    assert missing.status_code == 401

    wrong = httpx.post(
        f"{live.control_url}/internal/switch",
        json=_switch_payload(),
        headers={"X-Internal-Token": "not-the-internal-token"},
        timeout=10.0,
    )
    assert wrong.status_code == 401


def _inspect(service: str) -> dict:
    container_id = subprocess.run(
        ["docker", "compose", "-p", PROJECT, "ps", "-q", service],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert container_id, f"service {service} is not running"
    inspected = subprocess.run(
        ["docker", "inspect", container_id],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return json.loads(inspected)[0]


def test_no_container_has_docker_socket_and_executor_has_no_host_port() -> None:
    for service in (
        "postgres",
        "demo-healthy-v1",
        "demo-broken-v2",
        "gateway",
        "gateway-control",
        "api",
        "console",
        "executor",
        "worker",
    ):
        container = _inspect(service)
        mounts = container.get("Mounts", [])
        assert not any("docker.sock" in mount.get("Source", "") for mount in mounts), service
        host_config = container.get("HostConfig", {})
        binds = host_config.get("Binds") or []
        assert not any("docker.sock" in bind for bind in binds), service
        assert not any(
            "docker.sock" in (mount.get("Source") or "")
            for mount in (host_config.get("Mounts") or [])
        ), service

    executor = _inspect("executor")
    assert not executor.get("NetworkSettings", {}).get("Ports") or all(
        not binding for binding in executor["NetworkSettings"]["Ports"].values()
    ), "executor must publish no host port"


# --- unsuccessful recovery becomes recovery_failed ----------------------------


async def test_unsuccessful_recovery_becomes_recovery_failed(
    live: Live, pool: asyncpg.Pool
) -> None:
    await _restore_healthy(pool)
    incident_id: uuid.UUID | None = None
    try:
        incident_id, operation_id = await _seed_stale_recovery(pool)
        detail = await _wait_for_state(
            live, incident_id, {"resolved", "recovery_failed"}
        )
        assert detail["state"] == "recovery_failed", detail
        assert detail["operation"]["status"] == "failed", detail
        assert detail["operation"]["last_error"] == "stale_revision", detail
        # The deployment was never mutated by the refused recovery.
        assert httpx.get(f"{live.gateway_url}/snapshot", timeout=5.0).json()["revision"] == BROKEN
    finally:
        await _cleanup_incident(pool, incident_id)
        await _restore_healthy(pool)


# --- secrets never persist in evidence or events ------------------------------


async def test_secrets_never_persist_in_evidence_or_events(
    live: Live, pool: asyncpg.Pool
) -> None:
    await _restore_healthy(pool)
    incident_id: uuid.UUID | None = None
    try:
        _inject_fault(live)
        created = httpx.post(
            f"{live.api_url}/alerts",
            json={
                "dedupe_key": f"resilience-secret-{uuid.uuid4()}",
                "service_id": "demo-api",
                "summary": "secret redaction",
            },
            headers=live.auth(),
            timeout=10.0,
        )
        assert created.status_code == 201, created.text
        incident_id = uuid.UUID(created.json()["id"])
        await _wait_for_state(live, incident_id, {"awaiting_approval", "escalated"})

        evidence = await pool.fetch(
            "SELECT payload FROM incident_evidence WHERE incident_id = $1", incident_id
        )
        events = await pool.fetch(
            "SELECT payload FROM incident_events WHERE incident_id = $1", incident_id
        )
        blob = json.dumps(
            [row["payload"] for row in evidence] + [row["payload"] for row in events],
            default=str,
        )
        secrets = [
            os.environ.get(name, "")
            for name in ("INTERNAL_TOKEN", "OPERATOR_TOKEN", "POSTGRES_PASSWORD")
        ]
        for secret in secrets:
            if len(secret) >= 4:
                assert secret not in blob
                assert secret not in httpx.get(
                    f"{live.gateway_url}/api/logs", timeout=5.0
                ).text
    finally:
        await _cleanup_incident(pool, incident_id)
        await _restore_healthy(pool)
