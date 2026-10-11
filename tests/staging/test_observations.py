"""Observation shapes, authenticated real business request, and secret exclusion.

These use a fake HTTP transport and a fake dependency connector: no Docker and
no real network.  The fake returns *shaped* provider responses and the test
asserts the adapter's handling, never fabricated telemetry.
"""

from __future__ import annotations

import json

import httpx
import pytest

from incident_recovery.service_profile import STAGING_PROFILE
from incident_recovery.staging.observations import (
    DependencyStatus,
    ObservationError,
    StagingDependencyProbe,
    StagingFunctionalProbe,
    StagingObserver,
)

TENANT_TOKEN = "secret-tenant-token-abc123"
TENANT_ID = "11111111-2222-3333-4444-555555555555"
REV = STAGING_PROFILE.healthy_revision


def _snapshot_body(revision: str = REV, generation: int = 1) -> dict:
    return {
        "service_id": STAGING_PROFILE.service_id,
        "revision": revision,
        "generation": generation,
        "activated_at": "2026-10-12T00:00:00Z",
        "predecessor": None,
    }


class FakeDependencies:
    def __init__(self, ok: bool = True) -> None:
        self.ok = ok
        self.calls = 0

    async def check(self) -> DependencyStatus:
        self.calls += 1
        return DependencyStatus(postgres_ok=self.ok, redis_ok=self.ok)


def _observer(handler, dependencies=None) -> tuple[StagingObserver, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(wrapped), base_url="http://gw.test")
    observer = StagingObserver(
        STAGING_PROFILE,
        "http://gw.test",
        tenant_id=TENANT_ID,
        tenant_token=TENANT_TOKEN,
        client=client,
        dependency_probe=dependencies,
    )
    return observer, seen


def _business_ok(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/snapshot":
        return httpx.Response(200, json=_snapshot_body())
    return httpx.Response(
        200,
        json={"data": []},
        headers={
            "X-Deployment-Revision": REV,
            "X-Deployment-Generation": "1",
        },
    )


@pytest.mark.asyncio
async def test_health_is_an_authenticated_business_request() -> None:
    deps = FakeDependencies(ok=True)
    observer, seen = _observer(_business_ok, deps)
    observation = await observer.observe_health()
    assert observation.functional_ok is True
    assert observation.dependencies_ok is True
    assert observation.revision == REV
    assert observation.generation == 1
    assert observation.evidence_fields["http_status"] == 200
    # The business request carried the tenant token.
    business = [r for r in seen if r.url.path.endswith("/projects")]
    assert business and business[0].headers.get("authorization") == f"Bearer {TENANT_TOKEN}"
    assert deps.calls == 1
    await observer.aclose()


@pytest.mark.asyncio
async def test_health_reports_actual_failure_not_liveness() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/snapshot":
            return httpx.Response(200, json=_snapshot_body())
        return httpx.Response(500, json={"error": "injected_fault"})

    observer, _ = _observer(handler, FakeDependencies(ok=True))
    observation = await observer.observe_health()
    assert observation.functional_ok is False
    assert observation.dependencies_ok is True
    assert observation.evidence_fields["http_status"] == 500
    await observer.aclose()


@pytest.mark.asyncio
async def test_dependency_health_is_independent_of_api_behaviour() -> None:
    # The business request succeeds, but the dependency is independently down.
    observer, _ = _observer(_business_ok, FakeDependencies(ok=False))
    observation = await observer.observe_health()
    assert observation.functional_ok is True
    assert observation.dependencies_ok is False
    assert observation.evidence_fields["dependencies"] == {
        "postgres_ok": False,
        "redis_ok": False,
    }
    await observer.aclose()


@pytest.mark.asyncio
async def test_health_without_dependency_probe_reports_unhealthy() -> None:
    observer, _ = _observer(_business_ok, dependencies=None)
    observation = await observer.observe_health()
    assert observation.dependencies_ok is False
    await observer.aclose()


@pytest.mark.asyncio
async def test_credentials_are_excluded_from_evidence() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/snapshot":
            return httpx.Response(200, json=_snapshot_body())
        # A hostile/leaky upstream echoes the token; it must not survive.
        return httpx.Response(
            200,
            json={"data": [], "access_token": TENANT_TOKEN, "Authorization": f"Bearer {TENANT_TOKEN}"},
            headers={"X-Deployment-Revision": REV, "X-Deployment-Generation": "1"},
        )

    observer, _ = _observer(handler, FakeDependencies(ok=True))
    observation = await observer.observe_health()
    serialized = json.dumps(observation.evidence_fields)
    assert TENANT_TOKEN not in serialized
    await observer.aclose()


@pytest.mark.asyncio
async def test_observation_error_never_contains_the_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    observer, _ = _observer(handler, FakeDependencies(ok=True))
    with pytest.raises(ObservationError) as exc:
        await observer.observe_health()
    assert TENANT_TOKEN not in str(exc.value)
    await observer.aclose()


@pytest.mark.asyncio
async def test_functional_probe_requires_revision_and_identity() -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(_business_ok), base_url="http://gw.test")
    observer = StagingObserver(
        STAGING_PROFILE, "http://gw.test", tenant_id=TENANT_ID, tenant_token=TENANT_TOKEN, client=client
    )
    probe = StagingFunctionalProbe(
        STAGING_PROFILE, "http://gw.test", tenant_id=TENANT_ID, tenant_token=TENANT_TOKEN, observer=observer
    )
    check = await probe.check(REV)
    assert check.ok is True
    assert check.revision == REV

    mismatch = await probe.check(STAGING_PROFILE.faulty_revision)
    assert mismatch.ok is False
    assert mismatch.detail == "revision_mismatch"
    await observer.aclose()


@pytest.mark.asyncio
async def test_functional_probe_rejects_wrong_identity_headers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/snapshot":
            return httpx.Response(200, json=_snapshot_body())
        return httpx.Response(
            200,
            json={"data": []},
            headers={"X-Deployment-Revision": REV, "X-Deployment-Generation": "99"},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://gw.test")
    observer = StagingObserver(
        STAGING_PROFILE, "http://gw.test", tenant_id=TENANT_ID, tenant_token=TENANT_TOKEN, client=client
    )
    probe = StagingFunctionalProbe(
        STAGING_PROFILE, "http://gw.test", tenant_id=TENANT_ID, tenant_token=TENANT_TOKEN, observer=observer
    )
    check = await probe.check(REV)
    assert check.ok is False
    assert check.detail == "business_identity_generation_mismatch"
    await observer.aclose()


@pytest.mark.asyncio
async def test_dependency_probe_uses_isolated_endpoints() -> None:
    seen: list[tuple[str, int]] = []

    async def connector(host: str, port: int) -> bool:
        seen.append((host, port))
        return host == "postgres"

    probe = StagingDependencyProbe(
        postgres=("postgres", 5432), redis=("redis", 6379), connector=connector
    )
    status = await probe.check()
    assert status.postgres_ok is True
    assert status.redis_ok is False
    assert seen == [("postgres", 5432), ("redis", 6379)]
