"""Real Docker end-to-end bounded investigation for Task 4.

Runs against the live Compose stack with the worker configured with the explicit,
opt-in scripted adapter (``compose.investigation.yaml``), which is the only place
scripted investigation is enabled.  The scripted run is clearly labeled
``scripted:demo``; the default stack requires a real provider and escalates when
credentials are absent.

Everything asserted here is the result of a real container or real PostgreSQL
observation: an authenticated alert starts a real worker investigation that calls
the real gateway health/logs/metrics tools and reads authoritative deployment
state, produces an evidence-linked proposal, and then proceeds through the real
approval, executor rollback, and sustained verification path.

Bring the stack up with the investigation override first:

    docker compose -p incident-recovery -f compose.yaml -f compose.investigation.yaml up --build -d --wait
    uv run pytest tests/e2e/test_investigation.py -v
    docker compose -p incident-recovery up --build -d --wait   # restore default
"""

from __future__ import annotations

import os
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
        raise RuntimeError("E2E investigation tests require POSTGRES_* values in .env")
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
        pytest.fail("OPERATOR_TOKEN is not set; generate it in .env and start the stack.")
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


async def _restore_healthy(pool: asyncpg.Pool) -> None:
    await pool.execute(
        "UPDATE deployment_reservations SET status = 'released', released_at = now() "
        "WHERE status = 'active'"
    )
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


def _wait_for_state(live: Live, incident_id: uuid.UUID, states: set[str], timeout: float = 120.0) -> dict:
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


async def test_alert_to_scripted_investigation_to_real_rollback(live: Live, pool: asyncpg.Pool) -> None:
    await _restore_healthy(pool)
    incident_id: uuid.UUID | None = None
    try:
        _inject_fault(live)
        broken = httpx.get(f"{live.gateway_url}/api/work", timeout=5.0)
        assert broken.status_code == 500 and broken.json()["ok"] is False

        created = httpx.post(
            f"{live.api_url}/alerts",
            json={"dedupe_key": f"invest-{uuid.uuid4()}", "service_id": "demo-api",
                  "summary": "functional failure on demo-api"},
            headers=live.auth(),
            timeout=10.0,
        )
        assert created.status_code == 201, created.text
        incident_id = uuid.UUID(created.json()["id"])

        detail = _wait_for_state(live, incident_id, {"awaiting_approval", "escalated"})
        if detail["state"] == "escalated":
            pytest.fail(
                "worker escalated instead of proposing: bring the stack up with "
                "compose.investigation.yaml so the explicit scripted adapter is enabled"
            )

        # Real evidence-backed proposal produced by the scripted investigation.
        proposal = detail["proposal"]
        assert proposal is not None, detail
        assert proposal["target_revision"] == HEALTHY
        assert proposal["current_revision"] == BROKEN
        assert len(proposal["evidence_ids"]) >= 2

        rows = await pool.fetch(
            "SELECT source, payload FROM incident_evidence WHERE incident_id = $1", incident_id
        )
        sources = {row["source"] for row in rows}
        assert "tool:health" in sources
        assert "tool:deployments" in sources

        run = await pool.fetchrow(
            "SELECT adapter, state, tool_calls, started_at, deadline_at "
            "FROM investigation_runs WHERE incident_id = $1 ORDER BY epoch DESC LIMIT 1",
            incident_id,
        )
        assert run is not None
        assert run["adapter"] == "scripted:demo"
        assert run["state"] == "decided"
        assert 1 <= run["tool_calls"] <= 12
        assert (run["deadline_at"] - run["started_at"]).total_seconds() <= 120.5

        # Approve by exact digest and let the real recovery path proceed.
        approved = httpx.post(
            f"{live.api_url}/incidents/{incident_id}/approve",
            json={"proposal_digest": proposal["digest"], "actor": "e2e-investigator"},
            headers=live.auth(),
            timeout=10.0,
        )
        assert approved.status_code == 200, approved.text

        final = _wait_for_state(live, incident_id, {"resolved", "recovery_failed"})
        assert final["state"] == "resolved", final
        assert final["verification"]["consecutive_successes"] >= 3
        healthy = httpx.get(f"{live.gateway_url}/api/work", timeout=5.0)
        assert healthy.status_code == 200 and healthy.json()["ok"] is True
        assert httpx.get(f"{live.gateway_url}/snapshot", timeout=5.0).json()["revision"] == HEALTHY
    finally:
        # Evidence is immutable by design, so the audit incident is not force-
        # deleted.  Any incident left mid-flight (e.g. a failed assertion) is
        # failed closed so it cannot block the next run's fault injection, and
        # the deployment is always restored to healthy.
        if incident_id is not None:
            await pool.execute(
                "UPDATE incidents SET state = 'recovery_failed', lease_owner = NULL, "
                "lease_expires_at = NULL, updated_at = now() "
                "WHERE id = $1 AND state NOT IN "
                "('resolved','escalated','rejected','recovery_failed')",
                incident_id,
            )
        await _restore_healthy(pool)
