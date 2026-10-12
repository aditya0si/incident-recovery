"""Isolated staging control plane: operator API and durable recovery worker.

Both entry points reuse the *reviewed* control-plane classes
(:class:`~incident_recovery.repository.IncidentRepository`,
:class:`~incident_recovery.gateway.DeploymentStore`,
:class:`~incident_recovery.worker.RecoveryWorker`,
:class:`~incident_recovery.agent.InvestigationAgent`,
:class:`~incident_recovery.executor.RecoveryExecutor`) but bind them to the fixed
staging service profile and the staging observation/verification adapter.

Nothing here is a broad new design: the operator API exposes the same reviewed
workflow (alerts, approvals, rejection, deployment state, SSE), and the worker
runs the same investigation -> approval -> execution -> sustained-verification
pipeline.  The only differences are the bound service identity, the fixed
revision set, and the staging observation source.
"""

from __future__ import annotations

import asyncio
import hmac
import os
from typing import Optional, Protocol
from uuid import UUID, uuid4

import httpx
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse

from ..api import (
    HttpSwitchClient,
    StoreReader,
    SwitchClient,
    _event_view,
    _evidence_view,
    _incident_summary,
    _investigation_view,
    _sse_frame,
    _verification_view,
)
from ..contracts import (
    ApprovalRequest,
    ApprovalResult,
    IncidentDetail,
    RejectionRequest,
    RejectionResult,
    approval_view,
    operation_view,
    proposal_view,
)
from ..db import bootstrap_schema, create_pool
from ..gateway import DeploymentStore
from ..models import (
    ApprovalStale,
    IllegalStateTransition,
    NotFound,
    ProposalNotFound,
    ReservationConflict,
    SwitchUnreachable,
)
from ..repository import IncidentRepository
from ..service_profile import STAGING_SERVICE_ID, load_service_profile
from .contracts import StagingAlertCreate, StagingFaultRequest


def create_staging_api_app(
    repo: IncidentRepository,
    *,
    store: StoreReader,
    switch_client: SwitchClient,
    operator_token: str,
    allowed_origins: list[str],
) -> FastAPI:
    """Operator API bound to the fixed staging service.

    Every write that creates or approves a recovery binds the staging service id
    explicitly, so a demo record or a foreign service can never be mutated.
    """

    allowed = frozenset(origin.strip() for origin in allowed_origins if origin.strip())
    app = FastAPI(title="incident-recovery-staging-api", docs_url=None, redoc_url=None)

    def require_operator(
        request: Request, authorization: Optional[str] = Header(default=None)
    ) -> bool:
        origin = request.headers.get("origin")
        if origin is not None and origin not in allowed:
            raise HTTPException(status_code=403, detail="origin_not_allowed")
        if not operator_token:
            raise HTTPException(status_code=401, detail="unauthorized")
        supplied = ""
        if authorization and authorization.startswith("Bearer "):
            supplied = authorization[len("Bearer ") :]
        if not hmac.compare_digest(supplied.encode(), operator_token.encode()):
            raise HTTPException(status_code=401, detail="unauthorized")
        return True

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "role": "staging-api"}

    @app.post("/alerts")
    async def create_alert(alert: StagingAlertCreate, _: bool = Depends(require_operator)):
        incident, created = await repo.ingest_alert(
            alert.dedupe_key, alert.service_id, alert.summary, alert.payload
        )
        return JSONResponse(
            status_code=201 if created else 200,
            content={
                "id": str(incident.id),
                "state": incident.state.value,
                "service_id": incident.service_id,
                "deduplicated": not created,
            },
        )

    @app.get("/deployment")
    async def get_deployment() -> dict:
        return (await store.get_snapshot()).model_dump(mode="json")

    @app.get("/incidents")
    async def list_incidents(
        limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0)
    ) -> list[dict]:
        incidents = await repo.list_incidents(limit=limit, offset=offset)
        return [_incident_summary(i).model_dump(mode="json") for i in incidents]

    @app.get("/incidents/{incident_id}")
    async def get_incident(incident_id: UUID) -> dict:
        incident = await repo.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident_not_found")
        evidence = await repo.list_evidence(incident_id)
        events = await repo.list_events(incident_id, limit=200)
        proposal = await repo.get_proposal_for_incident(incident_id)
        approval = await repo.get_approval_for_incident(incident_id)
        operation = await repo.get_operation_for_incident(incident_id)
        run = await repo.get_latest_investigation_run(incident_id)
        steps = await repo.list_investigation_steps(incident_id, run.epoch) if run else []
        detail = IncidentDetail(
            **_incident_summary(incident).model_dump(),
            evidence=[_evidence_view(e) for e in evidence],
            events=[_event_view(e) for e in events],
            proposal=proposal_view(proposal) if proposal else None,
            approval=approval_view(approval) if approval else None,
            operation=operation_view(operation) if operation else None,
            verification=_verification_view(operation) if operation else None,
            investigation=_investigation_view(run, steps[-200:]) if run else None,
        )
        return detail.model_dump(mode="json")

    @app.post("/incidents/{incident_id}/approve")
    async def approve_incident(
        incident_id: UUID, body: ApprovalRequest, _: bool = Depends(require_operator)
    ) -> dict:
        try:
            approval, operation, created = await repo.approve_incident(
                incident_id,
                body.proposal_digest,
                body.actor,
                service_id=STAGING_SERVICE_ID,
            )
        except NotFound:
            raise HTTPException(status_code=404, detail="incident_not_found")
        except ProposalNotFound:
            raise HTTPException(status_code=404, detail="proposal_not_found")
        except ApprovalStale:
            raise HTTPException(status_code=409, detail="stale_approval")
        except ReservationConflict:
            raise HTTPException(status_code=409, detail="deployment_reserved")
        except IllegalStateTransition:
            raise HTTPException(status_code=409, detail="invalid_state")
        return ApprovalResult(
            approval=approval_view(approval),
            operation=operation_view(operation),
            created=created,
        ).model_dump(mode="json")

    @app.post("/incidents/{incident_id}/reject")
    async def reject_incident(
        incident_id: UUID, body: RejectionRequest, _: bool = Depends(require_operator)
    ) -> dict:
        try:
            incident = await repo.reject_incident(
                incident_id,
                body.actor,
                reason=body.reason,
                proposal_digest=body.proposal_digest,
                service_id=STAGING_SERVICE_ID,
            )
        except NotFound:
            raise HTTPException(status_code=404, detail="incident_not_found")
        except IllegalStateTransition:
            raise HTTPException(status_code=409, detail="invalid_state")
        return RejectionResult(
            incident_id=incident.id, state=incident.state.value, actor=body.actor
        ).model_dump(mode="json")

    @app.get("/incidents/{incident_id}/events")
    async def incident_events(
        incident_id: UUID,
        request: Request,
        last_event_id: Optional[int] = Query(default=None, ge=0),
    ) -> StreamingResponse:
        incident = await repo.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident_not_found")
        start = last_event_id or 0

        async def stream():
            async for event in repo.iter_events(incident_id, after_id=start):
                yield _sse_frame(event)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # The path matches the existing console's fault action, so the reviewed UI is
    # reused unchanged against the isolated staging API (same-origin config).
    @app.post("/demo/faults")
    async def inject_fault(body: StagingFaultRequest, _: bool = Depends(require_operator)):
        if await repo.has_pending_recovery():
            raise HTTPException(status_code=409, detail="pending_recovery")
        snapshot = await store.get_snapshot()
        if snapshot.revision == body.target_revision:
            return {"status": "already_active", "snapshot": snapshot.model_dump(mode="json")}
        operation_id = uuid4()
        try:
            await repo.reserve(
                operation_id,
                scope="fault",
                expected_generation=snapshot.generation,
                target_revision=body.target_revision,
                service_id=STAGING_SERVICE_ID,
            )
        except ReservationConflict:
            raise HTTPException(status_code=409, detail="deployment_reserved")
        try:
            try:
                decision = await switch_client.switch(
                    operation_id=operation_id,
                    expected_generation=snapshot.generation,
                    target_revision=body.target_revision,
                    scope="fault",
                )
            except SwitchUnreachable:
                record = await store.get_operation_record(operation_id)
                if record is not None:
                    return {
                        "status": "reconciled",
                        "snapshot": record.snapshot.model_dump(mode="json"),
                    }
                raise HTTPException(status_code=502, detail="switch_unreachable")
        finally:
            await repo.release_reservation(operation_id)
        if decision.status in ("applied", "replayed"):
            return {"status": decision.status, "snapshot": decision.snapshot.model_dump(mode="json")}
        actual = await store.get_snapshot()
        raise HTTPException(
            status_code=409,
            detail={
                "error": f"switch_{decision.status}",
                "revision": actual.revision,
                "generation": actual.generation,
            },
        )

    return app


async def _build_pool(dsn: str, attempts: int = 30, delay: float = 1.0):
    last: Optional[BaseException] = None
    for _ in range(attempts):
        try:
            pool = await create_pool(dsn)
            await bootstrap_schema(pool, profile=load_service_profile())
            return pool
        except Exception as exc:  # noqa: BLE001 - retried, surfaced if exhausted
            last = exc
            await asyncio.sleep(delay)
    raise RuntimeError(f"PostgreSQL unavailable after {attempts} attempts: {last!r}")


async def _serve_api() -> None:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise SystemExit("DATABASE_URL is required")
    pool = await _build_pool(dsn)
    repo = IncidentRepository(pool)
    store = DeploymentStore(pool, profile=load_service_profile())
    switch_client = HttpSwitchClient(
        os.environ.get("GATEWAY_INTERNAL_URL", "http://staging-gateway-control:8081"),
        os.environ.get("INTERNAL_TOKEN", ""),
    )
    allowed_origins = os.environ.get("ALLOWED_ORIGINS", "").split(",")
    app = create_staging_api_app(
        repo,
        store=store,
        switch_client=switch_client,
        operator_token=os.environ.get("OPERATOR_TOKEN", ""),
        allowed_origins=allowed_origins,
    )
    port = int(os.environ.get("PORT", "8000"))
    server = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info"))
    await server.serve()


def build_staging_worker(repo, pool, env: dict):
    """Construct the evaluated staging recovery worker (investigation + recovery)."""

    from ..agent import InvestigationAgent
    from ..executor import RecoveryExecutor
    from ..verification import DEFAULT_INTERVAL_SECONDS, DEFAULT_REQUIRED_STREAK, RecoveryVerifier
    from ..worker import RecoveryWorker
    from .observations import StagingDependencyProbe, StagingFunctionalProbe, StagingObserver
    from .workload import StagingScriptedAdapter, StagingToolRunner

    profile = load_service_profile(env)
    gateway_url = env.get("GATEWAY_URL", "http://staging-gateway:8081")
    tenant_id = env["STAGING_TENANT_ID"]
    tenant_token = env["STAGING_TENANT_TOKEN"]

    observer = StagingObserver(
        profile,
        gateway_url,
        tenant_id=tenant_id,
        tenant_token=tenant_token,
        dependency_probe=StagingDependencyProbe.from_env(env),
    )
    probe = StagingFunctionalProbe(
        profile, gateway_url, tenant_id=tenant_id, tenant_token=tenant_token, observer=observer
    )
    verifier = RecoveryVerifier(probe)
    tools = StagingToolRunner(repo, observer)
    adapter = StagingScriptedAdapter()
    agent = InvestigationAgent(
        repo,
        tools,
        adapter,
        env.get("WORKER_ID", "staging-worker-1"),
        service_id=profile.service_id,
        known_good_revision=profile.known_good_revision(),
        broken_revision=profile.broken_revision(),
        require_dependency_health=True,
        max_tool_calls=int(env.get("INVESTIGATION_MAX_TOOL_CALLS", "12")),
        max_seconds=float(env.get("INVESTIGATION_MAX_SECONDS", "120")),
    )
    from ..worker import HttpExecutorClient

    executor = HttpExecutorClient(
        env.get("EXECUTOR_URL", "http://staging-executor:8000"),
        env.get("INTERNAL_TOKEN", ""),
    )
    store = DeploymentStore(pool, profile=profile)
    worker = RecoveryWorker(
        repo,
        executor,
        verifier,
        env.get("WORKER_ID", "staging-worker-1"),
        investigator=agent,
        poll_interval=float(env.get("WORKER_POLL_INTERVAL", "1.0")),
    )
    return worker, (observer, agent)


async def _serve_worker() -> None:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise SystemExit("DATABASE_URL is required")
    env = dict(os.environ)
    if not env.get("STAGING_TENANT_ID") or not env.get("STAGING_TENANT_TOKEN"):
        raise SystemExit("STAGING_TENANT_ID and STAGING_TENANT_TOKEN are required")
    pool = await _build_pool(dsn)
    repo = IncidentRepository(pool)
    worker, closables = build_staging_worker(repo, pool, env)
    print(f"staging worker adapter identity: {worker._investigator._adapter.identity}", flush=True)
    try:
        await worker.run_forever()
    finally:
        for component in closables:
            closer = getattr(component, "aclose", None)
            if closer is not None:
                await closer()


def main_api() -> None:
    asyncio.run(_serve_api())


def main_worker() -> None:
    asyncio.run(_serve_worker())


if __name__ == "__main__":
    main_api()
