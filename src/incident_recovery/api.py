"""Operator control API: durable incidents, SSE event stream, demo fault injection.

Security model (Task 2):

* All writes require an ``Authorization: Bearer <OPERATOR_TOKEN>`` header with a
  constant-time comparison. Authentication never relies on cookies.
* Any request carrying an ``Origin`` header not on the explicit localhost
  allowlist is rejected (HTTP 403) even when a valid credential is supplied.
* The operator token is never echoed in errors, events, or logs.
* Reads (``GET /incidents`` and ``GET /incidents/{id}``) are read-only.

Fault injection only ever drives the fixed ``demo-api`` / ``broken-v2`` pair and
is refused while a recovery is pending.  The write itself goes through the
authenticated internal switch over the internal network, so it serialises on the
same authoritative ``deployment_state`` row lock as any other switch.  The API
never holds a database transaction across that network call, so it cannot
self-deadlock with the gateway control transaction; an ambiguous response is
reconciled against persisted state instead of being reported as false success.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
from typing import Optional, Protocol
from uuid import UUID, uuid4

import httpx
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .contracts import (
    AlertAccepted,
    AlertCreate,
    ApprovalRequest,
    ApprovalResult,
    ApprovalView,
    DeploymentSnapshot,
    EventView,
    EvidenceView,
    FaultRequest,
    FaultResult,
    IncidentDetail,
    IncidentSummary,
    InvestigationRunView,
    InvestigationStepView,
    InvestigationView,
    OperationView,
    ProposalView,
    RejectionRequest,
    RejectionResult,
    SwitchDecision,
    VerificationView,
    approval_view,
    operation_view,
    proposal_view,
)
from .db import bootstrap_schema, create_pool
from .gateway import DeploymentStore
from .models import (
    SERVICE_ID,
    ApprovalStale,
    Event,
    Evidence,
    IllegalStateTransition,
    Incident,
    NotFound,
    Operation,
    ProposalNotFound,
    ReservationConflict,
    SwitchUnreachable,
)
from .repository import IncidentRepository


class SwitchClient(Protocol):
    async def switch(
        self,
        *,
        operation_id: UUID,
        expected_generation: int,
        target_revision: str,
        scope: str,
    ) -> SwitchDecision: ...


class StoreReader(Protocol):
    async def get_snapshot(self) -> DeploymentSnapshot: ...

    async def get_operation_record(self, operation_id: UUID): ...


class HttpSwitchClient:
    """Calls the authenticated internal gateway-control switch over the network."""

    def __init__(self, base_url: str, token: str, *, timeout: float = 5.0) -> None:
        self._base = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout

    async def switch(
        self,
        *,
        operation_id: UUID,
        expected_generation: int,
        target_revision: str,
        scope: str,
    ) -> SwitchDecision:
        body = {
            "operation_id": str(operation_id),
            "expected_generation": expected_generation,
            "target_revision": target_revision,
            "scope": scope,
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{self._base}/internal/switch",
                    json=body,
                    headers={"X-Internal-Token": self._token},
                )
        except httpx.HTTPError as exc:
            # Never include request data (which carries the internal token).
            raise SwitchUnreachable(exc.__class__.__name__) from exc
        if response.status_code not in (200, 409):
            raise SwitchUnreachable(f"unexpected switch status {response.status_code}")
        data = response.json()
        return SwitchDecision(
            status=data["status"], snapshot=DeploymentSnapshot(**data["snapshot"])
        )


def _incident_summary(incident: Incident) -> IncidentSummary:
    return IncidentSummary(
        id=incident.id,
        service_id=incident.service_id,
        state=incident.state.value,
        summary=incident.summary,
        detected_at=incident.detected_at,
        updated_at=incident.updated_at,
        version=incident.version,
    )


def _evidence_view(evidence: Evidence) -> EvidenceView:
    return EvidenceView(
        id=evidence.id,
        incident_id=evidence.incident_id,
        source=evidence.source,
        evidence_type=evidence.evidence_type.value,
        observed_at=evidence.observed_at,
        payload=evidence.payload,
    )


def _event_view(event: Event) -> EventView:
    return EventView(
        id=event.id,
        incident_id=event.incident_id,
        kind=event.kind.value,
        payload=event.payload,
        created_at=event.created_at,
    )


def _verification_view(operation: Optional[Operation]) -> Optional[VerificationView]:
    if operation is None or not operation.result:
        return None
    payload = operation.result
    if "checks" not in payload or "consecutive_successes" not in payload:
        return None
    return VerificationView(
        status=str(payload.get("status", operation.status)),
        target_revision=operation.target_revision,
        checks=int(payload.get("checks", 0)),
        consecutive_successes=int(payload.get("consecutive_successes", 0)),
        required_streak=int(payload.get("required_streak", 3)),
        started_at=payload.get("started_at"),
        finished_at=payload.get("finished_at"),
        detail=payload.get("detail"),
    )


def _investigation_view(run, steps) -> InvestigationView:
    """Read-only investigation identity + bounded tool trace for the console."""

    return InvestigationView(
        run=InvestigationRunView(
            incident_id=run.incident_id,
            epoch=run.epoch,
            adapter=run.adapter,
            state=run.state,
            tool_calls=run.tool_calls,
            started_at=run.started_at,
            deadline_at=run.deadline_at,
            updated_at=run.updated_at,
            last_error=run.last_error,
        ),
        steps=[
            InvestigationStepView(
                id=step.id,
                epoch=step.epoch,
                step_index=step.step_index,
                kind=step.kind,
                payload=step.payload,
                created_at=step.created_at,
            )
            for step in steps
        ],
    )


def _sse_frame(event: Event) -> str:
    data = _event_view(event).model_dump(mode="json")
    return f"id: {event.id}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"


def create_app(
    repo: IncidentRepository,
    *,
    store: StoreReader,
    switch_client: SwitchClient,
    operator_token: str,
    allowed_origins: list[str],
) -> FastAPI:
    allowed = frozenset(origin.strip() for origin in allowed_origins if origin.strip())
    app = FastAPI(title="incident-recovery-api", docs_url=None, redoc_url=None)

    def require_operator(
        request: Request, authorization: Optional[str] = Header(default=None)
    ) -> bool:
        origin = request.headers.get("origin")
        # Reject an untrusted Origin even if a valid credential is supplied.
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
        return {"status": "ok", "role": "api"}

    @app.post("/alerts")
    async def create_alert(alert: AlertCreate, _: bool = Depends(require_operator)):
        incident, created = await repo.ingest_alert(
            alert.dedupe_key, alert.service_id, alert.summary, alert.payload
        )
        body = AlertAccepted(
            id=incident.id,
            state=incident.state.value,
            service_id=incident.service_id,
            deduplicated=not created,
        )
        return JSONResponse(
            status_code=201 if created else 200,
            content=body.model_dump(mode="json"),
        )

    @app.get("/deployment")
    async def get_deployment() -> dict:
        # Authoritative active deployment state (read-only) for the console.
        snapshot = await store.get_snapshot()
        return snapshot.model_dump(mode="json")

    @app.get("/incidents")
    async def list_incidents(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
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
        steps = (
            await repo.list_investigation_steps(incident_id, run.epoch) if run else []
        )
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
        incident_id: UUID,
        body: ApprovalRequest,
        _: bool = Depends(require_operator),
    ) -> dict:
        try:
            approval, operation, created = await repo.approve_incident(
                incident_id, body.proposal_digest, body.actor
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
        result = ApprovalResult(
            approval=approval_view(approval),
            operation=operation_view(operation),
            created=created,
        )
        return result.model_dump(mode="json")

    @app.post("/incidents/{incident_id}/reject")
    async def reject_incident(
        incident_id: UUID,
        body: RejectionRequest,
        _: bool = Depends(require_operator),
    ) -> dict:
        try:
            incident = await repo.reject_incident(
                incident_id,
                body.actor,
                reason=body.reason,
                proposal_digest=body.proposal_digest,
                service_id=SERVICE_ID,
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

        start = last_event_id
        if start is None:
            header = request.headers.get("last-event-id")
            if header:
                try:
                    start = int(header)
                except ValueError:
                    raise HTTPException(status_code=400, detail="invalid_last_event_id")
        start = start or 0

        async def stream():
            # Starlette cancels this generator when the client disconnects, so no
            # explicit is_disconnected() poll is needed (and polling would block
            # under in-process ASGI transports).
            async for event in repo.iter_events(incident_id, after_id=start):
                yield _sse_frame(event)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.post("/demo/faults")
    async def inject_fault(body: FaultRequest, _: bool = Depends(require_operator)):
        # A pending recovery owns the deployment; competing fault changes are refused.
        if await repo.has_pending_recovery():
            raise HTTPException(status_code=409, detail="pending_recovery")

        snapshot = await store.get_snapshot()
        if snapshot.revision == body.target_revision:
            return FaultResult(
                status="already_active", snapshot=snapshot, reconciled=True
            ).model_dump(mode="json")

        # The persisted reservation is the authoritative mutation token.  It is
        # created atomically before the switch and validated inside the gateway
        # switch transaction, closing the check-then-act race with a recovery
        # that may claim the deployment concurrently.
        operation_id = uuid4()
        try:
            await repo.reserve(
                operation_id,
                scope="fault",
                expected_generation=snapshot.generation,
                target_revision=body.target_revision,
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
                    return FaultResult(
                        status="reconciled", snapshot=record.snapshot, reconciled=True
                    ).model_dump(mode="json")
                raise HTTPException(status_code=502, detail="switch_unreachable")
        finally:
            await repo.release_reservation(operation_id)

        if decision.status in ("applied", "replayed"):
            return FaultResult(
                status=decision.status, snapshot=decision.snapshot, reconciled=False
            ).model_dump(mode="json")

        # Stale/conflict/unauthorized: report the authoritative state, never a
        # false success.
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


async def _build_pool_with_retry(dsn: str, attempts: int = 30, delay: float = 1.0):
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
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise SystemExit("DATABASE_URL is required")
    pool = await _build_pool_with_retry(dsn)
    repo = IncidentRepository(pool)
    store = DeploymentStore(pool)
    switch_client = HttpSwitchClient(
        os.environ.get("GATEWAY_INTERNAL_URL", "http://gateway-control:8000"),
        os.environ.get("INTERNAL_TOKEN", ""),
    )
    allowed_origins = os.environ.get(
        "ALLOWED_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173"
    ).split(",")
    app = create_app(
        repo,
        store=store,
        switch_client=switch_client,
        operator_token=os.environ.get("OPERATOR_TOKEN", ""),
        allowed_origins=allowed_origins,
    )
    port = int(os.environ.get("PORT", "8000"))
    server = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info"))
    await server.serve()


def main() -> None:
    asyncio.run(_serve())


if __name__ == "__main__":
    main()
