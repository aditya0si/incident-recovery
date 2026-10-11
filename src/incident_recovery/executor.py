"""Restricted internal recovery executor.

The executor accepts only a *persisted operation id* over an authenticated
internal channel; it accepts no arbitrary shell, container, image, mount, or
revision inputs.  For each operation it re-loads the authoritative operation,
approval, and reservation, re-validates the exact scope (fixed service, current
revision/generation, known-good target, five-minute TTL, single consumption),
and only then drives the fixed desired-state switch.

Least-privilege note (Milestone 3): gateway revision switching is a pure
PostgreSQL desired-state change and needs **no** Docker power, so the executor
is intentionally *not* mounted with the Docker socket.  Restart capability is
deferred to a later milestone.

Response ambiguity never triggers a blind repeat: after a network failure the
executor reconciles the operation id against the gateway's durable operation
record, so an unrelated deployment change can never manufacture success.
"""

from __future__ import annotations

import asyncio
import hmac
import os
from typing import Optional, Protocol
from uuid import UUID

import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from .contracts import (
    ExecuteRequest,
    ExecuteResponse,
    SwitchDecision,
    operation_view,
)
from .gateway import DeploymentStore
from .models import (
    OPERATION_EXECUTED,
    OPERATION_EXECUTING,
    OPERATION_FAILED,
    OPERATION_PENDING,
    NotFound,
    Operation,
    SwitchUnreachable,
    ensure_utc,
    utcnow,
)
from .repository import IncidentRepository


class RecoverySwitchClient(Protocol):
    async def switch(
        self,
        *,
        operation_id: UUID,
        expected_generation: int,
        target_revision: str,
        scope: str,
    ) -> SwitchDecision: ...


class RecoveryExecutor:
    def __init__(
        self,
        repo: IncidentRepository,
        switch_client: RecoverySwitchClient,
        store: DeploymentStore,
        *,
        clock=utcnow,
    ) -> None:
        self._repo = repo
        self._switch = switch_client
        self._store = store
        self._clock = clock

    async def execute(self, operation_id: UUID) -> Operation:
        operation = await self._repo.get_operation(operation_id)
        if operation is None:
            raise NotFound(f"operation {operation_id} not found")

        # Idempotent: an operation that already reached a terminal-or-executed
        # state is returned as-is; a consumed approval can never run again.
        if operation.status in (OPERATION_EXECUTED, "verified", OPERATION_FAILED):
            return operation

        # Crash-window reconciliation: if the durable switch already committed
        # for this exact operation (the process died after the gateway mutation
        # but before record_execution), record the execution now instead of
        # re-admitting it under a fresh approval.  An expired/consumed approval
        # must never block reconciliation of a mutation that actually happened.
        reconciled = await self._reconcile_exact(operation_id, operation)
        if reconciled is not None:
            return reconciled

        reservation = await self._repo.get_reservation(operation_id)
        if reservation is None or reservation.status != "active":
            return await self._fail(operation_id, "no_active_reservation")
        if operation.approval_id is None:
            return await self._fail(operation_id, "missing_approval")

        approval = await self._repo.get_approval(operation.approval_id)
        if approval is None:
            return await self._fail(operation_id, "missing_approval")

        now = ensure_utc(self._clock())
        if ensure_utc(approval.expires_at) <= now:
            return await self._fail(operation_id, "approval_expired")
        if approval.consumed_by_operation not in (None, operation_id):
            return await self._fail(operation_id, "approval_consumed")
        if approval.service_id != operation.service_id:
            return await self._fail(operation_id, "service_mismatch")
        if approval.target_revision != operation.target_revision:
            return await self._fail(operation_id, "target_mismatch")

        consumed = await self._repo.consume_approval(approval.id, operation_id)
        if not consumed:
            return await self._fail(operation_id, "approval_consumed")

        await self._repo.set_operation_status(
            operation_id, OPERATION_EXECUTING, bump_attempts=True
        )

        try:
            decision = await self._switch.switch(
                operation_id=operation_id,
                expected_generation=reservation.expected_generation,
                target_revision=operation.target_revision,
                scope="recovery",
            )
        except (SwitchUnreachable, httpx.HTTPError) as exc:
            return await self._reconcile_after_ambiguity(operation_id, exc)

        if decision.status in ("applied", "replayed"):
            return await self._repo.record_execution(
                operation_id,
                {
                    "status": decision.status,
                    "revision": decision.snapshot.revision,
                    "generation": decision.snapshot.generation,
                },
            )
        # The switch rejected the request.  If, despite that, the durable record
        # proves this exact operation already applied, reconcile it rather than
        # reporting a false failure (e.g. a lost response).
        reconciled = await self._reconcile_exact(operation_id)
        if reconciled is not None:
            return reconciled
        if decision.status == "stale":
            return await self._fail(operation_id, "stale_revision")
        return await self._fail(operation_id, f"switch_{decision.status}")

    async def _reconcile_exact(
        self, operation_id: UUID, operation: Optional[Operation] = None
    ) -> Optional[Operation]:
        """Reconcile only an exact durable operation/scope/request match.

        Returns the reconciled operation, or ``None`` when there is no durable
        record or it does not exactly match this operation (so a revision that
        merely happens to be active can never manufacture success).
        """
        record = await self._store.get_operation_record(operation_id)
        if record is None:
            return None
        if operation is None:
            operation = await self._repo.get_operation(operation_id)
        if operation is None:
            return None
        if (
            record.service_id != operation.service_id
            or record.expected_generation != operation.expected_generation
            or record.target_revision != operation.target_revision
            or record.scope != "recovery"
        ):
            return None
        return await self._repo.record_execution(
            operation_id,
            {
                "status": "reconciled",
                "revision": record.snapshot.revision,
                "generation": record.snapshot.generation,
            },
        )

    async def _reconcile_after_ambiguity(
        self, operation_id: UUID, exc: BaseException
    ) -> Operation:
        """Reconcile by the durable operation record; never blind-retry."""
        reconciled = await self._reconcile_exact(operation_id)
        if reconciled is not None:
            return reconciled
        # The mutation is not confirmed.  Leave the operation pending so a later
        # claim retries the idempotent switch under the same operation id.
        return await self._repo.set_operation_status(
            operation_id, OPERATION_PENDING, last_error=f"ambiguous:{exc.__class__.__name__}"
        )

    async def _fail(self, operation_id: UUID, error: str) -> Operation:
        return await self._repo.set_operation_status(
            operation_id, OPERATION_FAILED, last_error=error
        )


def create_executor_app(
    repo: IncidentRepository,
    switch_client: RecoverySwitchClient,
    store: DeploymentStore,
    *,
    internal_token: str,
) -> FastAPI:
    app = FastAPI(title="incident-recovery-executor", docs_url=None, redoc_url=None)
    executor = RecoveryExecutor(repo, switch_client, store)

    def authorize(token: Optional[str]) -> None:
        supplied = token or ""
        if not internal_token or not hmac.compare_digest(
            supplied.encode(), internal_token.encode()
        ):
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "role": "executor"}

    @app.post("/internal/execute")
    async def execute(
        body: ExecuteRequest, x_internal_token: Optional[str] = Header(default=None)
    ) -> JSONResponse:
        authorize(x_internal_token)
        try:
            operation = await executor.execute(body.operation_id)
        except NotFound:
            raise HTTPException(status_code=404, detail="operation_not_found")
        view = operation_view(operation)
        return JSONResponse(
            status_code=200,
            content=ExecuteResponse(operation=view).model_dump(mode="json"),
        )

    return app


async def _build_pool(dsn: str, attempts: int = 30, delay: float = 1.0):
    from .db import bootstrap_schema, create_pool

    last: Optional[BaseException] = None
    for _ in range(attempts):
        try:
            pool = await create_pool(dsn)
            await bootstrap_schema(pool)
            return pool
        except Exception as exc:  # noqa: BLE001 - retried, surfaced if exhausted
            last = exc
            await asyncio.sleep(delay)
    raise RuntimeError(f"PostgreSQL unavailable after {attempts} attempts: {last!r}")


async def _serve() -> None:
    import uvicorn

    from .api import HttpSwitchClient

    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise SystemExit("DATABASE_URL is required")
    internal_token = os.environ.get("INTERNAL_TOKEN", "")
    if not internal_token:
        raise SystemExit("INTERNAL_TOKEN is required")
    pool = await _build_pool(dsn)
    repo = IncidentRepository(pool)
    store = DeploymentStore(pool)
    switch_client = HttpSwitchClient(
        os.environ.get("GATEWAY_INTERNAL_URL", "http://gateway-control:8000"),
        internal_token,
    )
    app = create_executor_app(repo, switch_client, store, internal_token=internal_token)
    port = int(os.environ.get("PORT", "8000"))
    server = uvicorn.Server(
        uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")
    )
    await server.serve()


def main() -> None:
    asyncio.run(_serve())


if __name__ == "__main__":
    main()
