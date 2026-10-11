"""Real-PostgreSQL integration tests for the durable event stream.

Covers monotonic event IDs, Last-Event-ID ordered backfill, and the guarantee
that a reconnect cannot lose events between backfill and subscription because
the stream polls the persisted event table.
"""

from __future__ import annotations

import asyncio
import json
import uuid

import httpx

from incident_recovery.models import EventKind
from incident_recovery.repository import IncidentRepository

from .conftest import ApiApp, ApiHarness


def _key(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4()}"


async def _incident(repo: IncidentRepository) -> uuid.UUID:
    incident, _ = await repo.ingest_alert(_key("events"), "demo-api", None, {})
    return incident.id


async def test_event_ids_are_monotonic(repo: IncidentRepository) -> None:
    incident_id = await _incident(repo)
    ids = []
    for index in range(5):
        event = await repo.append_event(incident_id, EventKind.STATE_CHANGED, {"i": index})
        ids.append(event.id)
    assert ids == sorted(ids)
    assert len(set(ids)) == len(ids)


async def test_backfill_after_last_event_id_is_ordered(repo: IncidentRepository) -> None:
    incident_id = await _incident(repo)
    first = (await repo.list_events(incident_id))[0]
    e2 = await repo.append_event(incident_id, EventKind.STATE_CHANGED, {"to": "investigating"})
    e3 = await repo.append_event(incident_id, EventKind.EVIDENCE_RECORDED, {"evidence": "e1"})

    after = await repo.list_events(incident_id, after_id=first.id)
    assert [event.id for event in after] == [e2.id, e3.id]
    assert after[0].kind == EventKind.STATE_CHANGED
    assert after[1].kind == EventKind.EVIDENCE_RECORDED


async def test_stream_does_not_lose_events_added_after_subscription(
    repo: IncidentRepository,
) -> None:
    incident_id = await _incident(repo)
    received: list[int] = []

    async def consume() -> None:
        async for event in repo.iter_events(incident_id, after_id=0, poll_interval=0.05):
            received.append(event.id)
            if len(received) >= 3:
                return

    async def produce() -> None:
        await asyncio.sleep(0.05)
        await repo.append_event(incident_id, EventKind.STATE_CHANGED, {"n": 2})
        await repo.append_event(incident_id, EventKind.STATE_CHANGED, {"n": 3})

    await asyncio.wait_for(asyncio.gather(consume(), produce()), timeout=10)
    assert len(received) == 3
    assert received == sorted(received)
    assert len(set(received)) == 3


async def test_sse_endpoint_backfills_from_last_event_id(
    api_app: ApiApp, sse_server: str
) -> None:
    incident_id = await _incident(api_app.repo)
    events = await api_app.repo.list_events(incident_id)
    first = events[0]
    second = await api_app.repo.append_event(
        incident_id, EventKind.STATE_CHANGED, {"to": "investigating"}
    )

    collected: list[dict] = []

    async def read() -> None:
        async with httpx.AsyncClient(base_url=sse_server, timeout=10.0) as client:
            async with client.stream(
                "GET",
                f"/incidents/{incident_id}/events",
                headers={"Last-Event-ID": str(first.id)},
            ) as response:
                assert response.status_code == 200
                assert response.headers["content-type"].startswith("text/event-stream")
                async for line in response.aiter_lines():
                    if line.startswith("data:"):
                        collected.append(json.loads(line[len("data:") :].strip()))
                        return

    await asyncio.wait_for(read(), timeout=10)
    assert collected
    assert collected[0]["id"] == second.id
    assert collected[0]["kind"] == "state_changed"


async def test_sse_endpoint_unknown_incident_is_404(harness: ApiHarness) -> None:
    response = await harness.client.get(
        f"/incidents/{uuid.uuid4()}/events",
        headers={"Last-Event-ID": "0"},
    )
    assert response.status_code == 404
