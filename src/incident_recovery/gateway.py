"""Stable public traffic gateway and authenticated internal revision switch.

Two logical roles share this module and are run as separate Compose services:

* ``proxy``  - public listener. Routes fixed functional paths to the active
  demo deployment (chosen from PostgreSQL) and exposes a read-only snapshot.
  It has no switch route at all.
* ``control`` - internal listener. Owns the authenticated compare-and-set
  switch. It is on the internal network only and requires the internal token.

The active revision and generation live in PostgreSQL (source of truth). The
proxy re-reads the active revision for every proxied request, so a completed
switch is immediately visible through real traffic.
"""

from __future__ import annotations

import asyncio
import hmac
import os
from datetime import datetime, timezone
from typing import Optional

import asyncpg
import httpx
import uvicorn
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, Response

from .contracts import (
    SERVICE_ID,
    DeploymentSnapshot,
    OperationRecord,
    SwitchDecision,
    SwitchRequest,
)

TARGETS: dict[str, str] = {
    "healthy-v1": "http://demo-healthy-v1:8000",
    "broken-v2": "http://demo-broken-v2:8000",
}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS deployment_state (
    service_id     TEXT PRIMARY KEY,
    revision       TEXT NOT NULL,
    generation     INTEGER NOT NULL,
    activated_at   TIMESTAMPTZ NOT NULL,
    predecessor    TEXT
);

CREATE TABLE IF NOT EXISTS deployment_operations (
    operation_id         UUID PRIMARY KEY,
    service_id           TEXT NOT NULL,
    expected_generation  INTEGER NOT NULL,
    target_revision      TEXT NOT NULL,
    result_revision      TEXT NOT NULL,
    result_generation    INTEGER NOT NULL,
    result_activated_at  TIMESTAMPTZ NOT NULL,
    result_predecessor   TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS deployment_history (
    id            BIGSERIAL PRIMARY KEY,
    service_id    TEXT NOT NULL,
    from_revision TEXT,
    to_revision   TEXT NOT NULL,
    generation    INTEGER NOT NULL,
    operation_id  UUID NOT NULL,
    activated_at  TIMESTAMPTZ NOT NULL
);

INSERT INTO deployment_state (service_id, revision, generation, activated_at, predecessor)
VALUES ('demo-api', 'healthy-v1', 1, now(), NULL)
ON CONFLICT (service_id) DO NOTHING;
"""

_STATE_COLUMNS = "service_id, revision, generation, activated_at, predecessor"


def target_for_revision(revision: str) -> Optional[str]:
    """Fixed revision -> Compose DNS destination. Unknown revisions return None."""

    return TARGETS.get(revision)


def evaluate_switch(
    current: DeploymentSnapshot,
    request: SwitchRequest,
    prior: Optional[OperationRecord],
    now: datetime,
) -> SwitchDecision:
    """Pure compare-and-set / idempotency decision.

    * exact replay of a recorded operation returns the recorded result
    * a conflicting replay (same operation id, different request) is refused
    * a stale ``expected_generation`` is refused
    * otherwise the switch is applied and the generation increments
    """

    if prior is not None:
        if (
            prior.service_id != SERVICE_ID
            or prior.expected_generation != request.expected_generation
            or prior.target_revision != request.target_revision
        ):
            return SwitchDecision(status="conflict", snapshot=current)
        return SwitchDecision(status="replayed", snapshot=prior.snapshot)

    if request.expected_generation != current.generation:
        return SwitchDecision(status="stale", snapshot=current)

    applied = DeploymentSnapshot(
        service_id=SERVICE_ID,
        revision=request.target_revision,
        generation=current.generation + 1,
        activated_at=now,
        predecessor=current.revision,
    )
    return SwitchDecision(status="applied", snapshot=applied)


def _row_to_snapshot(row: asyncpg.Record) -> DeploymentSnapshot:
    return DeploymentSnapshot(
        service_id=row["service_id"],
        revision=row["revision"],
        generation=row["generation"],
        activated_at=row["activated_at"],
        predecessor=row["predecessor"],
    )


class DeploymentStore:
    """PostgreSQL-backed authoritative deployment state and operation records."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def ensure_schema(self) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(SCHEMA_SQL)

    async def get_snapshot(self) -> DeploymentSnapshot:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                f"SELECT {_STATE_COLUMNS} FROM deployment_state WHERE service_id = $1",
                SERVICE_ID,
            )
        if row is None:
            raise RuntimeError("deployment_state is not initialised")
        return _row_to_snapshot(row)

    async def switch(self, request: SwitchRequest) -> SwitchDecision:
        now = datetime.now(timezone.utc)
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                # Row lock serialises all switches, including exact replays.
                state_row = await conn.fetchrow(
                    f"SELECT {_STATE_COLUMNS} FROM deployment_state "
                    "WHERE service_id = $1 FOR UPDATE",
                    SERVICE_ID,
                )
                if state_row is None:
                    raise RuntimeError("deployment_state is not initialised")
                current = _row_to_snapshot(state_row)

                prior_row = await conn.fetchrow(
                    "SELECT operation_id, service_id, expected_generation, "
                    "target_revision, result_revision, result_generation, "
                    "result_activated_at, result_predecessor "
                    "FROM deployment_operations WHERE operation_id = $1",
                    request.operation_id,
                )
                prior = self._row_to_operation(prior_row) if prior_row else None

                decision = evaluate_switch(current, request, prior, now)

                if decision.status == "applied":
                    snap = decision.snapshot
                    await conn.execute(
                        "UPDATE deployment_state SET revision = $1, generation = $2, "
                        "activated_at = $3, predecessor = $4 WHERE service_id = $5",
                        snap.revision,
                        snap.generation,
                        snap.activated_at,
                        snap.predecessor,
                        SERVICE_ID,
                    )
                    await conn.execute(
                        "INSERT INTO deployment_operations (operation_id, service_id, "
                        "expected_generation, target_revision, result_revision, "
                        "result_generation, result_activated_at, result_predecessor) "
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                        request.operation_id,
                        SERVICE_ID,
                        request.expected_generation,
                        request.target_revision,
                        snap.revision,
                        snap.generation,
                        snap.activated_at,
                        snap.predecessor,
                    )
                    await conn.execute(
                        "INSERT INTO deployment_history (service_id, from_revision, "
                        "to_revision, generation, operation_id, activated_at) "
                        "VALUES ($1, $2, $3, $4, $5, $6)",
                        SERVICE_ID,
                        current.revision,
                        snap.revision,
                        snap.generation,
                        request.operation_id,
                        snap.activated_at,
                    )
                return decision

    @staticmethod
    def _row_to_operation(row: asyncpg.Record) -> OperationRecord:
        snapshot = DeploymentSnapshot(
            service_id=row["service_id"],
            revision=row["result_revision"],
            generation=row["result_generation"],
            activated_at=row["result_activated_at"],
            predecessor=row["result_predecessor"],
        )
        return OperationRecord(
            operation_id=row["operation_id"],
            service_id=row["service_id"],
            expected_generation=row["expected_generation"],
            target_revision=row["target_revision"],
            snapshot=snapshot,
        )


async def _proxy_request(store: DeploymentStore, path: str) -> Response:
    snapshot = await store.get_snapshot()
    destination = target_for_revision(snapshot.revision)
    if destination is None:
        return JSONResponse(
            status_code=503,
            content={"error": "unknown_active_revision", "revision": snapshot.revision},
        )
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            upstream = await client.get(f"{destination}{path}")
    except httpx.HTTPError as exc:
        return JSONResponse(
            status_code=502,
            content={"error": "upstream_unreachable", "reason": exc.__class__.__name__},
        )
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type", "application/json"),
        headers={
            "X-Deployment-Revision": snapshot.revision,
            "X-Deployment-Generation": str(snapshot.generation),
        },
    )


def create_proxy_app(store: DeploymentStore) -> FastAPI:
    app = FastAPI(title="incident-recovery-gateway", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "role": "proxy"}

    @app.get("/snapshot")
    async def snapshot() -> dict:
        return (await store.get_snapshot()).model_dump(mode="json")

    @app.get("/api/work")
    async def api_work() -> Response:
        return await _proxy_request(store, "/work")

    @app.get("/api/health")
    async def api_health() -> Response:
        return await _proxy_request(store, "/health")

    return app


def create_control_app(store: DeploymentStore, internal_token: str) -> FastAPI:
    app = FastAPI(title="incident-recovery-gateway-control", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "role": "control"}

    @app.post("/internal/switch")
    async def switch(
        request: SwitchRequest,
        x_internal_token: Optional[str] = Header(default=None),
    ) -> JSONResponse:
        supplied = x_internal_token or ""
        if not internal_token or not hmac.compare_digest(supplied, internal_token):
            return JSONResponse(status_code=401, content={"error": "unauthorized"})

        decision = await store.switch(request)
        body = {
            "operation_id": str(request.operation_id),
            "status": decision.status,
            "snapshot": decision.snapshot.model_dump(mode="json"),
            "replay": decision.status == "replayed",
        }
        status_code = 200 if decision.status in ("applied", "replayed") else 409
        return JSONResponse(status_code=status_code, content=body)

    return app


async def _build_store(dsn: str, attempts: int = 30, delay: float = 1.0) -> DeploymentStore:
    last_error: Optional[BaseException] = None
    for _ in range(attempts):
        try:
            pool = await asyncpg.create_pool(dsn=dsn, min_size=1, max_size=5)
            store = DeploymentStore(pool)
            await store.ensure_schema()
            return store
        except Exception as exc:  # noqa: BLE001 - retried, reported if exhausted
            last_error = exc
            await asyncio.sleep(delay)
    raise RuntimeError(f"PostgreSQL unavailable after {attempts} attempts: {last_error!r}")


async def _serve(role: str, dsn: str, port: int, internal_token: str) -> None:
    store = await _build_store(dsn)
    if role == "control":
        app = create_control_app(store, internal_token)
    elif role == "proxy":
        app = create_proxy_app(store)
    else:
        raise SystemExit(f"unknown GATEWAY_ROLE: {role!r}")
    server = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info"))
    await server.serve()


def main() -> None:
    role = os.environ.get("GATEWAY_ROLE", "proxy").strip().lower()
    port = int(os.environ.get("PORT", "8000"))
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise SystemExit("DATABASE_URL is required")
    internal_token = os.environ.get("INTERNAL_TOKEN", "")
    asyncio.run(_serve(role, dsn, port, internal_token))


if __name__ == "__main__":
    main()
