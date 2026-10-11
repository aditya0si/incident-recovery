"""Real Docker end-to-end deployment checks (Milestone 1, updated for Milestone 3).

These run against the live Compose stack (``incident-recovery`` project) and
assert observed HTTP behaviour through the stable public gateway plus revision
read-back. No deployment responses are fabricated here: every assertion is the
result of a real container response.

Milestone 3 made the internal switch an authoritatively gated mutation: every
switch must present an active persisted reservation (with matching scope), and a
switch without one is refused.  This suite therefore provisions its own
test-side fault reservations directly through the repository (a test fixture, not
a production debug route) and proves the bypass is closed.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid

import httpx
import pytest

from incident_recovery import db as db_module
from incident_recovery.repository import IncidentRepository

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://127.0.0.1:18080")
CONTROL_URL = os.environ.get("CONTROL_URL", "http://127.0.0.1:18081")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "")
HEALTHY = "healthy-v1"
BROKEN = "broken-v2"


def _host_dsn() -> str:
    user = os.environ.get("POSTGRES_USER")
    password = os.environ.get("POSTGRES_PASSWORD")
    name = os.environ.get("POSTGRES_DB")
    port = os.environ.get("POSTGRES_PORT", "15432")
    if not (user and password and name):
        raise RuntimeError("Deployment E2E requires POSTGRES_* values in .env")
    return f"postgresql://{user}:{password}@127.0.0.1:{port}/{name}"


async def _reserve(operation_id: uuid.UUID, generation: int, target: str, scope: str = "fault") -> None:
    pool = await db_module.create_pool(_host_dsn())
    try:
        await IncidentRepository(pool).reserve(
            operation_id,
            scope=scope,
            expected_generation=generation,
            target_revision=target,
        )
    finally:
        await pool.close()


async def _release(operation_id: uuid.UUID) -> None:
    pool = await db_module.create_pool(_host_dsn())
    try:
        await IncidentRepository(pool).release_reservation(operation_id)
    finally:
        await pool.close()


def _wait_ready(url: str, timeout: float = 90.0) -> None:
    deadline = time.time() + timeout
    last: str = "no attempt"
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


@pytest.fixture(scope="module")
def ready() -> None:
    # Prerequisites fail loudly: no silent skip may ever masquerade as success.
    if not INTERNAL_TOKEN:
        pytest.fail(
            "INTERNAL_TOKEN is not set. Source .env and bring up the stack with the "
            "test-only Compose override so gateway-control is reachable (see README)."
        )
    try:
        _wait_ready(f"{GATEWAY_URL}/healthz")
    except AssertionError as exc:
        pytest.fail(f"public gateway not reachable; bring up the stack first: {exc}")
    try:
        _wait_ready(f"{CONTROL_URL}/healthz")
    except AssertionError as exc:
        pytest.fail(
            "internal switch not reachable on the host. Bring the stack up with "
            f"`compose.yaml + compose.test.yaml` (test-only override): {exc}"
        )


def _switch(
    operation_id: uuid.UUID, generation: int, target: str, scope: str = "fault"
) -> httpx.Response:
    return httpx.post(
        f"{CONTROL_URL}/internal/switch",
        json={
            "operation_id": str(operation_id),
            "expected_generation": generation,
            "target_revision": target,
            "scope": scope,
        },
        headers={"X-Internal-Token": INTERNAL_TOKEN},
        timeout=10.0,
    )


def _snapshot() -> dict:
    response = httpx.get(f"{GATEWAY_URL}/snapshot", timeout=5.0)
    assert response.status_code == 200, response.text
    return response.json()


def _reset_to_healthy() -> None:
    snapshot = _snapshot()
    if snapshot["revision"] == HEALTHY:
        return
    operation_id = uuid.uuid4()
    asyncio.run(_reserve(operation_id, snapshot["generation"], HEALTHY))
    try:
        _switch(operation_id, snapshot["generation"], HEALTHY)
    finally:
        asyncio.run(_release(operation_id))


def test_switch_without_reservation_is_refused(ready: None) -> None:
    snapshot = _snapshot()
    target = BROKEN if snapshot["revision"] == HEALTHY else HEALTHY
    response = _switch(uuid.uuid4(), snapshot["generation"], target)
    assert response.status_code == 409, response.text
    assert response.json()["status"] == "unauthorized"
    # The unauthorized request did not change the deployment.
    assert _snapshot()["generation"] == snapshot["generation"]


def test_healthy_then_broken_then_healthy_through_gateway(ready: None) -> None:
    _reset_to_healthy()
    start = _snapshot()
    generation0 = start["generation"]
    assert start["revision"] == HEALTHY

    # Healthy revision serves real functional traffic.
    work = httpx.get(f"{GATEWAY_URL}/api/work", timeout=5.0)
    assert work.status_code == 200 and work.json()["ok"] is True
    assert httpx.get(f"{GATEWAY_URL}/api/health", timeout=5.0).status_code == 200

    # Inject the broken deployment through the authenticated, reservation-gated
    # internal switch (the fault reservation is a test-side fixture).
    op_break = uuid.uuid4()
    asyncio.run(_reserve(op_break, generation0, BROKEN))
    broken = _switch(op_break, generation0, BROKEN)
    assert broken.status_code == 200, broken.text
    assert broken.json()["status"] == "applied"
    assert broken.json()["snapshot"]["revision"] == BROKEN
    assert broken.json()["snapshot"]["generation"] == generation0 + 1
    assert broken.json()["snapshot"]["predecessor"] == HEALTHY

    # Broken revision genuinely fails functional requests through the gateway.
    broken_work = httpx.get(f"{GATEWAY_URL}/api/work", timeout=5.0)
    assert broken_work.status_code == 500
    assert broken_work.json()["ok"] is False
    assert httpx.get(f"{GATEWAY_URL}/api/health", timeout=5.0).status_code == 503

    # Read-back from persistent state confirms the active revision.
    readback = _snapshot()
    assert readback["revision"] == BROKEN
    assert readback["generation"] == generation0 + 1

    # Exact operation replay returns the recorded result without a second switch.
    replay = _switch(op_break, generation0, BROKEN)
    assert replay.status_code == 200, replay.text
    assert replay.json()["status"] == "replayed"
    assert replay.json()["snapshot"]["generation"] == generation0 + 1
    assert _snapshot()["generation"] == generation0 + 1

    # Conflicting replay (same operation id, different target) is refused.
    conflict = _switch(op_break, generation0 + 1, HEALTHY)
    assert conflict.status_code == 409, conflict.text

    asyncio.run(_release(op_break))

    # Stale generation is refused.
    op_stale = uuid.uuid4()
    asyncio.run(_reserve(op_stale, generation0, HEALTHY))
    try:
        stale = _switch(op_stale, generation0, HEALTHY)
        assert stale.status_code == 409, stale.text
    finally:
        asyncio.run(_release(op_stale))

    # Roll back to the known-good predecessor.
    op_rollback = uuid.uuid4()
    asyncio.run(_reserve(op_rollback, generation0 + 1, HEALTHY))
    try:
        rolled = _switch(op_rollback, generation0 + 1, HEALTHY)
        assert rolled.status_code == 200, rolled.text
        assert rolled.json()["snapshot"]["generation"] == generation0 + 2
        assert rolled.json()["snapshot"]["revision"] == HEALTHY
        assert rolled.json()["snapshot"]["predecessor"] == BROKEN
    finally:
        asyncio.run(_release(op_rollback))

    healthy_work = httpx.get(f"{GATEWAY_URL}/api/work", timeout=5.0)
    assert healthy_work.status_code == 200 and healthy_work.json()["ok"] is True

    final = _snapshot()
    assert final["revision"] == HEALTHY
    assert final["generation"] == generation0 + 2


def test_switch_requires_internal_credential(ready: None) -> None:
    missing = httpx.post(
        f"{CONTROL_URL}/internal/switch",
        json={
            "operation_id": str(uuid.uuid4()),
            "expected_generation": 1,
            "target_revision": BROKEN,
            "scope": "fault",
        },
        timeout=10.0,
    )
    assert missing.status_code == 401

    wrong = httpx.post(
        f"{CONTROL_URL}/internal/switch",
        json={
            "operation_id": str(uuid.uuid4()),
            "expected_generation": 1,
            "target_revision": BROKEN,
            "scope": "fault",
        },
        headers={"X-Internal-Token": "not-the-token"},
        timeout=10.0,
    )
    assert wrong.status_code == 401


def test_public_gateway_does_not_expose_switch(ready: None) -> None:
    response = httpx.post(
        f"{GATEWAY_URL}/internal/switch",
        json={
            "operation_id": str(uuid.uuid4()),
            "expected_generation": 1,
            "target_revision": BROKEN,
            "scope": "fault",
        },
        timeout=10.0,
    )
    assert response.status_code == 404
