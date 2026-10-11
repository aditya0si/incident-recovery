"""Fixtures for real-PostgreSQL integration tests.

Every test receives a uniquely named, isolated PostgreSQL *schema* created
inside the project database and dropped afterwards.  Tests never create, drop,
truncate, or otherwise touch the shared ``public`` schema or any row created by
another test/project, so unrelated data is never destroyed.

Prerequisites are asserted loudly: a missing password or unreachable PostgreSQL
raises, it never skips.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import asyncpg
import httpx
import pytest_asyncio

from incident_recovery import db as db_module
from incident_recovery.api import create_app
from incident_recovery.contracts import DeploymentSnapshot, SwitchDecision
from incident_recovery.repository import IncidentRepository

OPERATOR_TOKEN = "test-operator-token-9f3a4c"
ALLOWED_ORIGIN = "http://127.0.0.1:5173"


def _host_dsn() -> str:
    user = os.environ.get("POSTGRES_USER")
    password = os.environ.get("POSTGRES_PASSWORD")
    name = os.environ.get("POSTGRES_DB")
    port = os.environ.get("POSTGRES_PORT", "5432")
    if not (user and password and name):
        raise RuntimeError(
            "Integration tests require POSTGRES_USER/POSTGRES_PASSWORD/POSTGRES_DB "
            "(loaded from .env); none are set."
        )
    return f"postgresql://{user}:{password}@127.0.0.1:{port}/{name}"


@dataclass
class TestDB:
    pool: asyncpg.Pool
    dsn: str
    schema: str


@pytest_asyncio.fixture
async def test_db() -> TestDB:
    dsn = _host_dsn()
    try:
        admin = await asyncpg.connect(dsn)
    except Exception as exc:  # noqa: BLE001 - surfaced as an explicit failure
        raise RuntimeError(
            f"PostgreSQL is not reachable at {dsn} for integration tests: {exc!r}. "
            "Start the stack (docker compose -p incident-recovery up -d --wait) first."
        ) from exc

    schema = f"it_{uuid.uuid4().hex[:12]}"
    try:
        await admin.execute(f'CREATE SCHEMA "{schema}"')
    finally:
        await admin.close()

    pool = await db_module.create_pool(dsn, schema=schema)
    await db_module.bootstrap_schema(pool)
    db = TestDB(pool=pool, dsn=dsn, schema=schema)
    try:
        yield db
    finally:
        await pool.close()
        admin = await asyncpg.connect(dsn)
        try:
            await admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
        finally:
            await admin.close()


@pytest_asyncio.fixture
async def repo(test_db: TestDB) -> IncidentRepository:
    return IncidentRepository(test_db.pool)


class FakeStore:
    """Read-only deployment snapshot reader for in-process API tests."""

    def __init__(self, revision: str = "healthy-v1", generation: int = 1) -> None:
        self._snapshot = DeploymentSnapshot(
            service_id="demo-api",
            revision=revision,
            generation=generation,
            activated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            predecessor=None,
        )

    async def get_snapshot(self) -> DeploymentSnapshot:
        return self._snapshot


class FakeSwitchClient:
    """Deterministic stand-in for the internal gateway switch over the network."""

    def __init__(self, store: FakeStore) -> None:
        self._store = store
        self.calls: list[dict] = []
        self.unreachable = False

    async def switch(self, *, operation_id, expected_generation, target_revision):
        from incident_recovery.api import SwitchUnreachable

        self.calls.append(
            {
                "operation_id": operation_id,
                "expected_generation": expected_generation,
                "target_revision": target_revision,
            }
        )
        if self.unreachable:
            raise SwitchUnreachable("simulated ambiguity")
        current = await self._store.get_snapshot()
        applied = DeploymentSnapshot(
            service_id="demo-api",
            revision=target_revision,
            generation=current.generation + 1,
            activated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            predecessor=current.revision,
        )
        return SwitchDecision(status="applied", snapshot=applied)


@dataclass
class ApiApp:
    app: object
    repo: IncidentRepository
    store: FakeStore
    switch: FakeSwitchClient


@dataclass
class ApiHarness:
    client: httpx.AsyncClient
    repo: IncidentRepository
    store: FakeStore
    switch: FakeSwitchClient
    token: str = OPERATOR_TOKEN
    origin: str = ALLOWED_ORIGIN

    def auth(self, origin: Optional[str] = None) -> dict:
        headers = {"Authorization": f"Bearer {self.token}"}
        if origin is not None:
            headers["Origin"] = origin
        return headers


@pytest_asyncio.fixture
async def api_app(test_db: TestDB) -> ApiApp:
    repo = IncidentRepository(test_db.pool)
    store = FakeStore()
    switch = FakeSwitchClient(store)
    app = create_app(
        repo,
        store=store,
        switch_client=switch,
        operator_token=OPERATOR_TOKEN,
        allowed_origins=[ALLOWED_ORIGIN],
    )
    return ApiApp(app=app, repo=repo, store=store, switch=switch)


@pytest_asyncio.fixture
async def harness(api_app: ApiApp) -> ApiHarness:
    transport = httpx.ASGITransport(app=api_app.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://api.test") as client:
        yield ApiHarness(
            client=client, repo=api_app.repo, store=api_app.store, switch=api_app.switch
        )


@pytest_asyncio.fixture
async def sse_server(api_app: ApiApp) -> str:
    """Run the app on a real loopback uvicorn server so SSE can stream for real.

    httpx's in-process ASGITransport buffers the entire body, which is unusable
    for an open-ended event stream, so a real server is used here.
    """

    import asyncio
    import socket

    import uvicorn

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    config = uvicorn.Config(api_app.app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    for _ in range(250):
        if server.started:
            break
        await asyncio.sleep(0.02)
    else:
        server.should_exit = True
        raise RuntimeError("uvicorn test server did not start")

    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, timeout=10)
        except asyncio.TimeoutError:  # pragma: no cover - defensive
            task.cancel()
