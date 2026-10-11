"""Stable staging traffic gateway and staging control switch.

Two roles share this module, run as separate Compose services on the isolated
staging network:

* ``proxy``   - the stable traffic gateway.  It routes the fixed ``/v1`` business
  surface to the *active* tenant API binary (chosen from PostgreSQL) and stamps
  the authoritative ``X-Deployment-Revision`` / ``X-Deployment-Generation``
  headers on every proxied response.  It also captures real request events for
  the ``/api/logs`` and ``/api/metrics`` observation sources.  It holds no
  tenant credential: the observation adapter supplies it.
* ``control`` - the internal compare-and-set switch.  It accepts only the fixed
  :class:`~incident_recovery.staging.contracts.StagingSwitchRequest` and is on
  the internal network only.

The active revision and generation live in the isolated incident PostgreSQL
(source of truth); the proxy re-reads them for every request, so a completed
rollback is immediately visible through real traffic.
"""

from __future__ import annotations

import asyncio
import hmac
import os
from collections import deque
from datetime import datetime, timezone
from typing import Mapping, Optional

import asyncpg
import httpx
import uvicorn
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, Response

from ..service_profile import ServiceProfile, load_service_profile
from .contracts import StagingSwitchRequest

DEFAULT_STORE_TIMEOUT = 5.0
_MAX_LOGS = 200
_PROXY_METHODS = ("GET", "POST")
# Only these request headers are forwarded upstream; everything else is dropped
# so a caller cannot inject arbitrary headers into the tenant API request.
_ALLOWED_FORWARD_HEADERS = ("authorization", "content-type", "idempotency-key", "accept")


class StagingTrafficGateway:
    """Capture real request events for the gateway observation sources."""

    def __init__(self, max_logs: int = _MAX_LOGS) -> None:
        self._logs: deque[dict] = deque(maxlen=max_logs)
        self.counters = {
            "requests_total": 0,
            "requests_failed": 0,
            "by_revision": {},
        }

    def record(self, *, method: str, path: str, status: int, revision: Optional[str]) -> None:
        self.counters["requests_total"] += 1
        if status >= 500:
            self.counters["requests_failed"] += 1
        key = revision or "unknown"
        self.counters["by_revision"][key] = self.counters["by_revision"].get(key, 0) + 1
        self._logs.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "level": "error" if status >= 500 else "info",
                "method": method,
                "path": path,
                "status": status,
                "revision": revision,
                "message": f"{method} {path} -> {status}",
            }
        )

    def logs(self, lines: int) -> list[dict]:
        return list(self._logs)[-lines:]

    def metrics(self, *, service_id: str, revision: Optional[str], generation: Optional[int]) -> dict:
        return {
            "service_id": service_id,
            "revision": revision,
            "generation": generation,
            **self.counters,
            "by_revision": dict(self.counters["by_revision"]),
        }


async def proxy_request(
    store,
    gateway: StagingTrafficGateway,
    *,
    method: str,
    path: str,
    query: str,
    body: Optional[bytes],
    content_type: Optional[str],
    timeout: float = DEFAULT_STORE_TIMEOUT,
    client: Optional[httpx.AsyncClient] = None,
    forward_headers: Optional[Mapping[str, str]] = None,
) -> Response:
    snapshot = await store.get_snapshot()
    destination = store.profile.target_for(snapshot.revision)
    if destination is None:
        return JSONResponse(
            status_code=503,
            content={"error": "unknown_active_revision", "revision": snapshot.revision},
        )
    url = f"{destination}{path}"
    if query:
        url = f"{url}?{query}"
    headers: dict[str, str] = {}
    if forward_headers:
        for name, value in forward_headers.items():
            if name.lower() in _ALLOWED_FORWARD_HEADERS:
                headers[name] = value
    if content_type and not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = content_type
    owns = client is None
    if owns:
        client = httpx.AsyncClient(timeout=timeout)
    try:
        upstream = await client.request(method, url, content=body, headers=headers)
    except httpx.HTTPError as exc:
        gateway.record(method=method, path=path, status=502, revision=snapshot.revision)
        return JSONResponse(
            status_code=502,
            content={"error": "upstream_unreachable", "reason": exc.__class__.__name__},
        )
    finally:
        if owns:
            await client.aclose()
    gateway.record(
        method=method, path=path, status=upstream.status_code, revision=snapshot.revision
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


def create_proxy_app(
    store,
    gateway: Optional[StagingTrafficGateway] = None,
    *,
    client: Optional[httpx.AsyncClient] = None,
) -> FastAPI:
    app = FastAPI(title="staging-gateway", docs_url=None, redoc_url=None)
    traffic = gateway or StagingTrafficGateway()

    @app.get("/livez")
    async def livez() -> dict:
        return {"live": True, "role": "proxy"}

    @app.get("/snapshot")
    async def snapshot() -> dict:
        return (await store.get_snapshot()).model_dump(mode="json")

    @app.get("/api/logs")
    async def api_logs(lines: int = 50) -> dict:
        bounded = max(1, min(int(lines), _MAX_LOGS))
        return {"count": bounded, "lines": traffic.logs(bounded)}

    @app.get("/api/metrics")
    async def api_metrics() -> dict:
        snap = await store.get_snapshot()
        return traffic.metrics(
            service_id=snap.service_id, revision=snap.revision, generation=snap.generation
        )

    @app.api_route("/v1/{path:path}", methods=list(_PROXY_METHODS))
    async def proxy_v1(path: str, request: Request) -> Response:
        return await proxy_request(
            store,
            traffic,
            method=request.method,
            path="/v1/" + path,
            query=request.url.query,
            body=await request.body(),
            content_type=request.headers.get("content-type"),
            client=client,
            forward_headers=dict(request.headers),
        )

    return app


def create_control_app(store, internal_token: str) -> FastAPI:
    app = FastAPI(title="staging-gateway-control", docs_url=None, redoc_url=None)

    @app.get("/livez")
    async def livez() -> dict:
        return {"live": True, "role": "control"}

    @app.post("/internal/switch")
    async def switch(
        request: StagingSwitchRequest,
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


async def build_store(
    dsn: str, profile: ServiceProfile, *, attempts: int = 30, delay: float = 1.0
):
    from ..db import bootstrap_schema
    from ..gateway import DeploymentStore

    last: Optional[BaseException] = None
    for _ in range(attempts):
        try:
            pool = await asyncpg.create_pool(dsn=dsn, min_size=1, max_size=5)
            await bootstrap_schema(pool, profile=profile)
            return DeploymentStore(pool, profile=profile)
        except Exception as exc:  # noqa: BLE001 - retried, surfaced if exhausted
            last = exc
            await asyncio.sleep(delay)
    raise RuntimeError(f"PostgreSQL unavailable after {attempts} attempts: {last!r}")


async def _serve() -> None:
    role = os.environ.get("STAGING_GATEWAY_ROLE", "proxy").strip().lower()
    port = int(os.environ.get("PORT", "8081"))
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise SystemExit("DATABASE_URL is required")
    profile = load_service_profile()
    store = await build_store(dsn, profile)
    if role == "control":
        app = create_control_app(store, os.environ.get("INTERNAL_TOKEN", ""))
    elif role == "proxy":
        app = create_proxy_app(store)
    else:
        raise SystemExit(f"unknown STAGING_GATEWAY_ROLE: {role!r}")
    server = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info"))
    await server.serve()


def main() -> None:
    asyncio.run(_serve())


if __name__ == "__main__":
    main()
