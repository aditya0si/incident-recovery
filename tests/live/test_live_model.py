"""Optional live-model investigation check (Milestone 6).

This module is deliberately *not* part of the default host or Docker E2E gates:
it runs only when the verification driver passes ``--live`` and a real
OpenAI-compatible runtime model is already configured through
``MODEL_BASE_URL`` / ``MODEL_NAME`` / ``MODEL_API_KEY`` (separate from any coding
CLI credential).  When those credentials are absent the driver reports the check
as ``blocked`` and never as a success.

It performs a real provider call and then drives a real alert through the default
stack (no scripted override), asserting that the recorded investigation adapter
is a real ``openai-compatible:*`` adapter - never ``scripted:demo`` or
``missing-credentials``.
"""

from __future__ import annotations

import os
import time
import uuid

import asyncpg
import httpx
import pytest

from incident_recovery import db as db_module
from incident_recovery.contracts import SwitchRequest
from incident_recovery.gateway import DeploymentStore
from incident_recovery.model_adapter import OpenAICompatibleAdapter, build_adapter_from_env
from incident_recovery.repository import IncidentRepository

RUN_LIVE = os.environ.get("RUN_LIVE_MODEL") == "1"

pytestmark = pytest.mark.skipif(
    not RUN_LIVE,
    reason="live model check is opt-in (run via scripts/verify.py --live with runtime credentials)",
)

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
        raise RuntimeError("Live model check requires POSTGRES_* values in .env")
    return f"postgresql://{user}:{password}@127.0.0.1:{port}/{name}"


def _wait_ready(url: str, timeout: float = 90.0) -> None:
    deadline = time.time() + timeout
    last = "no attempt"
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=3.0).status_code == 200:
                return
            last = "not ready"
        except Exception as exc:  # noqa: BLE001 - recorded as evidence
            last = repr(exc)
        time.sleep(1.0)
    raise AssertionError(f"{url} not ready within {timeout}s: {last}")


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


async def test_live_adapter_makes_a_real_provider_call() -> None:
    adapter = build_adapter_from_env()
    assert isinstance(adapter, OpenAICompatibleAdapter), (
        "live check requires MODEL_BASE_URL/MODEL_NAME/MODEL_API_KEY; got "
        f"{adapter.identity!r}"
    )
    step = await adapter.next_step(None)
    assert step is not None
    await adapter.aclose()


async def test_live_investigation_records_real_adapter_identity() -> None:
    if not OPERATOR_TOKEN:
        pytest.fail("OPERATOR_TOKEN is not set; start the default stack first.")
    _wait_ready(f"{GATEWAY_URL}/healthz")
    _wait_ready(f"{API_URL}/healthz")

    pool = await db_module.create_pool(_host_dsn())
    headers = {"Authorization": f"Bearer {OPERATOR_TOKEN}"}
    try:
        await _restore_healthy(pool)
        fault = httpx.post(
            f"{API_URL}/demo/faults",
            json={"target_revision": BROKEN},
            headers=headers,
            timeout=10.0,
        )
        assert fault.status_code == 200, fault.text

        created = httpx.post(
            f"{API_URL}/alerts",
            json={
                "dedupe_key": f"live-{uuid.uuid4()}",
                "service_id": "demo-api",
                "summary": "live model investigation",
            },
            headers=headers,
            timeout=10.0,
        )
        assert created.status_code == 201, created.text
        incident_id = created.json()["id"]

        deadline = time.time() + 240
        last: dict = {}
        while time.time() < deadline:
            response = httpx.get(f"{API_URL}/incidents/{incident_id}", timeout=10.0)
            if response.status_code == 200:
                last = response.json()
                if last["state"] in {"awaiting_approval", "escalated", "resolved"}:
                    break
            time.sleep(2.0)

        investigation = last.get("investigation") or {}
        run = investigation.get("run") or {}
        adapter = run.get("adapter", "")
        assert adapter.startswith("openai-compatible:"), (
            f"expected a real live adapter identity, got {adapter!r} ({last.get('state')})"
        )
        assert last.get("state") in {"awaiting_approval", "escalated", "resolved"}, last
    finally:
        await _restore_healthy(pool)
        await pool.close()
