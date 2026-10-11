"""Durable recovery worker.

The worker claims incidents in ``recovering``/``verifying`` with a durable lease,
executes the persisted operation through the restricted executor, then runs
independent sustained functional verification.  All ownership and state changes
are conditional ``UPDATE ... WHERE lease_owner = ...`` commits, so a stale worker
that lost its lease can never resolve an incident.

Durability rules:

* An approval persists a recovering incident and operation.  If the worker dies
  before executing, a later claim resumes the same operation id.
* An operation that already executed is not switched again; the worker proceeds
  straight to verification (reconciling the persisted operation, not just the
  matching revision).
* Ambiguous execution is left pending and retried idempotently under the same
  operation id; it is never blind-repeated and never declared resolved.
* ``resolved`` requires three consecutive gateway functional checks two seconds
  apart within 30 seconds; an executor ``200`` alone never resolves.
"""

from __future__ import annotations

import asyncio
import os
from typing import Optional, Protocol
from uuid import UUID

import httpx

from .contracts import ExecuteResponse
from .models import (
    OPERATION_EXECUTED,
    OPERATION_PENDING,
    Incident,
    IncidentState,
    LeaseLost,
    SwitchUnreachable,
    utcnow,
)
from .repository import IncidentRepository
from .verification import (
    DEFAULT_DEADLINE_SECONDS,
    DEFAULT_INTERVAL_SECONDS,
    DEFAULT_REQUIRED_STREAK,
    GatewayFunctionalProbe,
    RecoveryVerifier,
)


class ExecutorClient(Protocol):
    async def execute(self, operation_id: UUID): ...


class Investigator(Protocol):
    async def investigate(self, incident: Incident): ...


class HttpExecutorClient:
    """Calls the authenticated internal executor over the internal network."""

    def __init__(self, base_url: str, token: str, *, timeout: float = 15.0) -> None:
        self._base = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout

    async def execute(self, operation_id: UUID):
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{self._base}/internal/execute",
                    json={"operation_id": str(operation_id)},
                    headers={"X-Internal-Token": self._token},
                )
        except httpx.HTTPError as exc:
            raise SwitchUnreachable(exc.__class__.__name__) from exc
        if response.status_code == 404:
            raise LookupError("operation_not_found")
        if response.status_code != 200:
            raise SwitchUnreachable(f"executor_status_{response.status_code}")
        return ExecuteResponse(**response.json()).operation


class RecoveryWorker:
    def __init__(
        self,
        repo: IncidentRepository,
        executor: ExecutorClient,
        verifier: RecoveryVerifier,
        worker_id: str,
        *,
        lease_seconds: int = 120,
        investigator: Optional[Investigator] = None,
        investigation_lease_seconds: int = 180,
        clock=utcnow,
        poll_interval: float = 1.0,
    ) -> None:
        self._repo = repo
        self._executor = executor
        self._verifier = verifier
        self._worker_id = worker_id
        self._lease_seconds = lease_seconds
        self._investigator = investigator
        self._investigation_lease_seconds = investigation_lease_seconds
        self._clock = clock
        self._poll_interval = poll_interval

    async def run_once(self) -> bool:
        incident = await self._repo.claim_next_recovery(
            self._worker_id, lease_seconds=self._lease_seconds, now=self._clock()
        )
        if incident is not None:
            try:
                await self._process(incident)
            except LeaseLost:
                # Another owner has taken over; leave the incident to them.
                return True
            return True

        if self._investigator is None:
            return False

        # The investigation stage runs only when no recovery is pending, so an
        # approved recovery always takes precedence over new investigations.
        detected = await self._repo.claim_next_investigation(
            self._worker_id,
            lease_seconds=self._investigation_lease_seconds,
            now=self._clock(),
        )
        if detected is None:
            return False
        try:
            await self._investigator.investigate(detected)
        except LeaseLost:
            return True
        return True

    async def run_forever(self) -> None:
        while True:
            try:
                worked = await self.run_once()
            except Exception as exc:  # noqa: BLE001 - the loop must survive
                print(f"worker {self._worker_id} iteration error: {exc!r}", flush=True)
                worked = False
            if not worked:
                await asyncio.sleep(self._poll_interval)

    async def _process(self, incident: Incident) -> None:
        operation = await self._repo.get_operation_for_incident(incident.id)
        if operation is None:
            await self._repo.fail_recovery(
                incident.id,
                self._worker_id,
                _synthetic_operation_id(incident),
                error="missing_operation",
                now=self._clock(),
            )
            return

        if incident.state is IncidentState.RECOVERING:
            executed = await self._executor.execute(operation.id)
            current = await self._repo.get_operation(operation.id)
            status = current.status if current is not None else executed.status
            if status == OPERATION_EXECUTED:
                await self._repo.commit_under_lease(
                    incident.id,
                    self._worker_id,
                    IncidentState.VERIFYING,
                    lease_seconds=self._lease_seconds,
                    event_payload={"operation_id": str(operation.id)},
                    now=self._clock(),
                )
            elif status == OPERATION_PENDING:
                # Ambiguous: release the lease so a later claim retries safely.
                await self._repo.release_lease(incident.id, self._worker_id)
                return
            else:
                await self._repo.fail_recovery(
                    incident.id,
                    self._worker_id,
                    operation.id,
                    error=(current.last_error if current else None) or "execution_failed",
                    now=self._clock(),
                )
                return

        await self._verify(incident.id, operation.target_revision)

    async def _verify(self, incident_id: UUID, target_revision: str) -> None:
        async def heartbeat() -> None:
            await self._repo.renew_lease(
                incident_id,
                self._worker_id,
                lease_seconds=self._lease_seconds,
                now=self._clock(),
            )

        verification = await self._verifier.verify(target_revision, heartbeat=heartbeat)
        operation = await self._repo.get_operation_for_incident(incident_id)
        if operation is None:
            return
        await self._repo.finalize_verification(
            incident_id,
            self._worker_id,
            operation.id,
            success=verification.success,
            verification=verification.as_payload(),
            now=self._clock(),
        )


def _synthetic_operation_id(incident: Incident) -> UUID:
    # Only reached when an operation row is unexpectedly missing; the value is
    # never used to mutate the deployment.
    from uuid import uuid5, NAMESPACE_URL

    return uuid5(NAMESPACE_URL, f"missing-operation:{incident.id}")


def build_verifier(
    gateway_url: str,
    *,
    interval: float = DEFAULT_INTERVAL_SECONDS,
    required_streak: int = DEFAULT_REQUIRED_STREAK,
    deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
) -> tuple[RecoveryVerifier, httpx.AsyncClient]:
    client = httpx.AsyncClient(base_url=gateway_url.rstrip("/"), timeout=5.0)
    probe = GatewayFunctionalProbe(client)
    verifier = RecoveryVerifier(
        probe,
        interval=interval,
        required_streak=required_streak,
        deadline_seconds=deadline_seconds,
    )
    return verifier, client


async def _serve() -> None:
    from .db import bootstrap_schema, create_pool

    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise SystemExit("DATABASE_URL is required")
    internal_token = os.environ.get("INTERNAL_TOKEN", "")
    if not internal_token:
        raise SystemExit("INTERNAL_TOKEN is required")

    pool: Optional[object] = None
    last: Optional[BaseException] = None
    for _ in range(30):
        try:
            pool = await create_pool(dsn)
            await bootstrap_schema(pool)
            break
        except Exception as exc:  # noqa: BLE001 - retried, surfaced if exhausted
            last = exc
            await asyncio.sleep(1.0)
    if pool is None:
        raise RuntimeError(f"PostgreSQL unavailable: {last!r}")

    repo = IncidentRepository(pool)
    executor = HttpExecutorClient(
        os.environ.get("EXECUTOR_URL", "http://executor:8000"), internal_token
    )
    gateway_url = os.environ.get("GATEWAY_URL", "http://gateway:8000")
    verifier, client = build_verifier(gateway_url)

    from .agent import InvestigationAgent
    from .model_adapter import build_adapter_from_env
    from .tools import ToolRunner

    tools = ToolRunner(repo, gateway_url)
    adapter = build_adapter_from_env()
    investigator = InvestigationAgent(
        repo,
        tools,
        adapter,
        os.environ.get("WORKER_ID", "worker-1"),
        max_tool_calls=int(os.environ.get("INVESTIGATION_MAX_TOOL_CALLS", "12")),
        max_seconds=float(os.environ.get("INVESTIGATION_MAX_SECONDS", "120")),
        provider_timeout=float(os.environ.get("MODEL_TIMEOUT", "20")),
        lease_seconds=int(os.environ.get("INVESTIGATION_LEASE_SECONDS", "180")),
    )
    print(
        f"worker investigation adapter identity: {adapter.identity}",
        flush=True,
    )
    worker = RecoveryWorker(
        repo,
        executor,
        verifier,
        os.environ.get("WORKER_ID", "worker-1"),
        lease_seconds=int(os.environ.get("RECOVERY_LEASE_SECONDS", "120")),
        investigator=investigator,
        investigation_lease_seconds=int(
            os.environ.get("INVESTIGATION_LEASE_SECONDS", "180")
        ),
        poll_interval=float(os.environ.get("WORKER_POLL_INTERVAL", "1.0")),
    )
    try:
        await worker.run_forever()
    finally:
        await client.aclose()
        await investigator.aclose()


def main() -> None:
    asyncio.run(_serve())


if __name__ == "__main__":
    main()
