"""Read-only API surface added for the Task 5 console.

The console must display the authoritative active deployment and the recorded
investigation identity/tool trace (including a clearly labeled ``scripted:demo``
or ``missing-credentials`` adapter).  These tests pin that read-only surface
against real PostgreSQL; they add no write path and no production test hooks.
"""

from __future__ import annotations

import uuid

from incident_recovery.models import RUN_ESCALATED


async def test_deployment_endpoint_returns_authoritative_snapshot(harness) -> None:
    response = await harness.client.get("/deployment")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["service_id"] == "demo-api"
    assert body["revision"] in ("healthy-v1", "broken-v2")
    assert body["generation"] >= 1
    assert body["activated_at"]
    assert "predecessor" in body


async def test_incident_detail_exposes_investigation_identity_and_tool_trace(harness) -> None:
    created = await harness.client.post(
        "/alerts",
        json={
            "dedupe_key": f"console-{uuid.uuid4()}",
            "service_id": "demo-api",
            "summary": "console trace",
        },
        headers=harness.auth(harness.origin),
    )
    assert created.status_code == 201, created.text
    incident_id = uuid.UUID(created.json()["id"])

    claimed = await harness.repo.claim_next_investigation("w-console", lease_seconds=300)
    assert claimed is not None and claimed.id == incident_id
    run = await harness.repo.ensure_investigation_run(
        incident_id, "scripted:demo", 120.0
    )
    await harness.repo.record_investigation_step(
        incident_id,
        run.epoch,
        "run_started",
        {"adapter": run.adapter},
        worker_id="w-console",
    )
    await harness.repo.record_investigation_step(
        incident_id,
        run.epoch,
        "tool_request",
        {"tool": "health", "reason": "observe functional health", "lines": None},
        worker_id="w-console",
    )

    response = await harness.client.get(f"/incidents/{incident_id}")
    assert response.status_code == 200, response.text
    detail = response.json()
    investigation = detail["investigation"]
    assert investigation is not None
    assert investigation["run"]["adapter"] == "scripted:demo"
    assert investigation["run"]["epoch"] == run.epoch
    assert investigation["run"]["state"] == "running"
    assert investigation["run"]["tool_calls"] == 0
    kinds = [step["kind"] for step in investigation["steps"]]
    assert "run_started" in kinds
    assert "tool_request" in kinds
    tool_requests = [s for s in investigation["steps"] if s["kind"] == "tool_request"]
    assert tool_requests[0]["payload"]["tool"] == "health"


async def test_incident_detail_exposes_missing_credentials_escalation(harness) -> None:
    created = await harness.client.post(
        "/alerts",
        json={
            "dedupe_key": f"console-esc-{uuid.uuid4()}",
            "service_id": "demo-api",
            "summary": "no model",
        },
        headers=harness.auth(harness.origin),
    )
    incident_id = uuid.UUID(created.json()["id"])
    claimed = await harness.repo.claim_next_investigation("w-console", lease_seconds=300)
    assert claimed is not None and claimed.id == incident_id
    run = await harness.repo.ensure_investigation_run(
        incident_id, "missing-credentials", 120.0
    )
    await harness.repo.set_investigation_run_state(
        incident_id, run.epoch, RUN_ESCALATED, last_error="model_unavailable"
    )

    response = await harness.client.get(f"/incidents/{incident_id}")
    detail = response.json()
    assert detail["investigation"]["run"]["adapter"] == "missing-credentials"
    assert detail["investigation"]["run"]["state"] == "escalated"
    assert detail["investigation"]["run"]["last_error"] == "model_unavailable"


async def test_incident_detail_without_investigation_is_null(harness) -> None:
    created = await harness.client.post(
        "/alerts",
        json={
            "dedupe_key": f"console-plain-{uuid.uuid4()}",
            "service_id": "demo-api",
            "summary": "no investigation yet",
        },
        headers=harness.auth(harness.origin),
    )
    incident_id = uuid.UUID(created.json()["id"])
    response = await harness.client.get(f"/incidents/{incident_id}")
    detail = response.json()
    assert detail["investigation"] is None or detail["investigation"]["run"] is None
