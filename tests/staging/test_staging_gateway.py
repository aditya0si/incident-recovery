"""Stable staging traffic routing and authoritative identity headers.

The proxy is exercised with a fake upstream transport so no container is needed;
the assertions are about routing to the *fixed* revision destinations and the
identity headers, not about fabricated upstream content.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest

from incident_recovery.contracts import DeploymentSnapshot
from incident_recovery.gateway import evaluate_switch
from incident_recovery.service_profile import STAGING_PROFILE
from incident_recovery.staging.gateway import (
    StagingTrafficGateway,
    proxy_request,
)
from incident_recovery.staging.contracts import StagingSwitchRequest
from uuid import uuid4

NOW = datetime(2026, 10, 12, 0, 0, 0, tzinfo=timezone.utc)
HEALTHY = STAGING_PROFILE.healthy_revision
FAULTY = STAGING_PROFILE.faulty_revision


class FakeStore:
    def __init__(self, revision: str, generation: int = 1) -> None:
        self.profile = STAGING_PROFILE
        self._snapshot = DeploymentSnapshot(
            service_id=STAGING_PROFILE.service_id,
            revision=revision,
            generation=generation,
            activated_at=NOW,
            predecessor=None,
        )

    async def get_snapshot(self) -> DeploymentSnapshot:
        return self._snapshot


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_proxy_routes_to_the_active_fixed_revision() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        return httpx.Response(200, json={"data": []})

    gateway = StagingTrafficGateway()
    response = await proxy_request(
        FakeStore(HEALTHY, 3),
        gateway,
        method="GET",
        path="/v1/tenants/x/projects",
        query="limit=1",
        body=None,
        content_type=None,
        client=_client(handler),
    )
    assert seen == ["api"]
    assert response.status_code == 200
    assert response.headers["x-deployment-revision"] == HEALTHY
    assert response.headers["x-deployment-generation"] == "3"
    assert gateway.counters["requests_total"] == 1


@pytest.mark.asyncio
async def test_proxy_routes_to_the_faulty_binary_after_switch() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        return httpx.Response(500, json={"error": "injected_fault"})

    gateway = StagingTrafficGateway()
    response = await proxy_request(
        FakeStore(FAULTY, 2),
        gateway,
        method="GET",
        path="/v1/tenants/x/projects",
        query="",
        body=None,
        content_type=None,
        client=_client(handler),
    )
    assert seen == ["tenant-api-faulty"]
    assert response.status_code == 500
    assert response.headers["x-deployment-revision"] == FAULTY
    assert gateway.counters["requests_failed"] == 1


@pytest.mark.asyncio
async def test_proxy_refuses_an_unknown_revision() -> None:
    response = await proxy_request(
        FakeStore("evil-v9"),
        StagingTrafficGateway(),
        method="GET",
        path="/v1/health",
        query="",
        body=None,
        content_type=None,
        client=_client(lambda request: httpx.Response(200, json={})),
    )
    assert response.status_code == 503


def test_evaluate_switch_refuses_a_revision_outside_the_profile_set() -> None:

    current = DeploymentSnapshot(
        service_id=STAGING_PROFILE.service_id,
        revision=HEALTHY,
        generation=1,
        activated_at=NOW,
    )
    request = StagingSwitchRequest(
        operation_id=uuid4(), expected_generation=1, target_revision=FAULTY, scope="fault"
    )
    # A revision that is not in the closed set is refused even if the pydantic
    # contract is bypassed (defence in depth at the switch decision).
    decision = evaluate_switch(
        current,
        request,
        None,
        NOW,
        service_id=STAGING_PROFILE.service_id,
        revisions=("only-this-one",),
    )
    assert decision.status == "unauthorized"
