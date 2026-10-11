"""Live stack integration tests: real fault injection, API restart persistence.

These run against the running Compose stack.  They fail loudly when the stack is
not up rather than skipping, so a green run is real evidence.
"""

from __future__ import annotations

import os
import subprocess
import time
import uuid
from dataclasses import dataclass

import httpx
import pytest
import pytest_asyncio

from incident_recovery import db as db_module
from incident_recovery.contracts import SwitchRequest
from incident_recovery.gateway import DeploymentStore

from .conftest import _host_dsn

HEALTHY = "healthy-v1"
BROKEN = "broken-v2"


@dataclass
class LiveStack:
    api_url: str
    gateway_url: str
    token: str

    def auth(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}


def _wait_ready(url: str, timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    last = "no attempt"
    while time.time() < deadline:
        try:
            response = httpx.get(url, timeout=3.0)
            if response.status_code == 200:
                return
            last = f"status {response.status_code}"
        except Exception as exc:  # noqa: BLE001 - reported if it never becomes ready
            last = repr(exc)
        time.sleep(1.0)
    raise AssertionError(f"{url} not ready within {timeout}s: {last}")


@pytest_asyncio.fixture
async def live() -> LiveStack:
    token = os.environ.get("OPERATOR_TOKEN", "")
    if not token:
        pytest.fail(
            "OPERATOR_TOKEN is not set. Generate it in .env and restart the stack "
            "before running live integration tests."
        )
    api_url = f"http://127.0.0.1:{os.environ.get('API_PORT', '18082')}"
    gateway_url = f"http://127.0.0.1:{os.environ.get('GATEWAY_PORT', '18080')}"
    _wait_ready(f"{api_url}/healthz")
    _wait_ready(f"{gateway_url}/healthz")
    return LiveStack(api_url=api_url, gateway_url=gateway_url, token=token)


async def _restore_healthy() -> None:
    """Repository-local authoritative restore; only touches deployment_state rows."""
    pool = await db_module.create_pool(_host_dsn())
    try:
        store = DeploymentStore(pool)
        snapshot = await store.get_snapshot()
        if snapshot.revision != HEALTHY:
            await store.switch(
                SwitchRequest(
                    operation_id=uuid.uuid4(),
                    expected_generation=snapshot.generation,
                    target_revision=HEALTHY,
                )
            )
    finally:
        await pool.close()


async def test_real_fault_injection_breaks_traffic_and_recovers(live: LiveStack) -> None:
    await _restore_healthy()
    try:
        before = httpx.get(f"{live.gateway_url}/snapshot", timeout=5.0).json()
        assert before["revision"] == HEALTHY

        injected = httpx.post(
            f"{live.api_url}/demo/faults",
            json={"target_revision": BROKEN},
            headers=live.auth(),
            timeout=10.0,
        )
        assert injected.status_code == 200, injected.text
        assert injected.json()["snapshot"]["revision"] == BROKEN
        assert injected.json()["snapshot"]["generation"] == before["generation"] + 1

        broken_work = httpx.get(f"{live.gateway_url}/api/work", timeout=5.0)
        assert broken_work.status_code == 500
        assert broken_work.json()["ok"] is False

        readback = httpx.get(f"{live.gateway_url}/snapshot", timeout=5.0).json()
        assert readback["revision"] == BROKEN
    finally:
        await _restore_healthy()

    healthy_work = httpx.get(f"{live.gateway_url}/api/work", timeout=5.0)
    assert healthy_work.status_code == 200 and healthy_work.json()["ok"] is True


async def test_fault_injection_requires_operator_token(live: LiveStack) -> None:
    response = httpx.post(
        f"{live.api_url}/demo/faults",
        json={"target_revision": BROKEN},
        timeout=10.0,
    )
    assert response.status_code == 401


async def test_incident_persists_across_api_restart(live: LiveStack) -> None:
    key = f"restart-{uuid.uuid4()}"
    created = httpx.post(
        f"{live.api_url}/alerts",
        json={"dedupe_key": key, "service_id": "demo-api", "summary": "restart check"},
        headers=live.auth(),
        timeout=10.0,
    )
    assert created.status_code == 201, created.text
    incident_id = created.json()["id"]

    subprocess.run(
        ["docker", "compose", "-p", "incident-recovery", "restart", "api"],
        check=True,
        capture_output=True,
    )
    _wait_ready(f"{live.api_url}/healthz", timeout=90.0)

    reread = httpx.get(f"{live.api_url}/incidents/{incident_id}", timeout=10.0)
    assert reread.status_code == 200, reread.text
    assert reread.json()["id"] == incident_id
    assert reread.json()["state"] == "detected"

    # Clean up our own test row only (events cascade); never touch other data.
    pool = await db_module.create_pool(_host_dsn())
    try:
        await pool.execute("DELETE FROM incidents WHERE id = $1", uuid.UUID(incident_id))
    finally:
        await pool.close()
