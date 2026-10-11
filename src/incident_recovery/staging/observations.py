"""Allowlisted observations of the real staging tenant workload.

Every observation is derived from a *real* source:

* **health** - an authenticated, tenant-scoped business request made through the
  stable staging gateway (never a liveness probe), plus a *direct* dependency
  check that does not depend on the API's own behaviour.  Functional health and
  dependency health are reported separately, so a dependency outage is never
  mistaken for a functional regression.
* **logs** - structured request events captured at the gateway from real
  proxied requests, already sanitized at the source.
* **metrics** - actual request counters derived from real proxied traffic.
* **deployments** - the authoritative revision/generation/predecessor history.

The adapter holds the tenant token internally; it is used only as an
``Authorization`` header and is never placed in a returned payload, an evidence
field, or an error.  Every payload is redacted through the shared helpers before
it leaves this module.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Awaitable, Callable, Mapping, Optional

import httpx

from ..models import utcnow
from ..service_profile import ServiceProfile
from ..tools import redact_structure
from ..verification import FunctionalCheck
from .contracts import STAGING_SERVICE, StagingObservation

MAX_RESPONSE_BYTES = 8192
DEFAULT_MAX_LINES = 200

# The documented, fixed business path the functional probe exercises.  It is a
# tenant-scoped, read-only listing, so probing it repeatedly neither writes nor
# needs an idempotency key.
BUSINESS_PATH = "/v1/tenants/{tenant_id}/projects"


class ObservationError(RuntimeError):
    """A bounded observation could not be collected; the caller escalates."""


@dataclass(frozen=True)
class DependencyStatus:
    postgres_ok: bool
    redis_ok: bool

    @property
    def ok(self) -> bool:
        return self.postgres_ok and self.redis_ok


Connector = Callable[[str, int], Awaitable[bool]]


async def _tcp_connect(host: str, port: int) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=2.0
        )
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:  # noqa: BLE001 - closing best effort
        pass
    return True


class StagingDependencyProbe:
    """Independent TCP reachability of the isolated PostgreSQL and Redis.

    It deliberately does **not** go through the tenant API: a healthy binary
    cannot repair a failed dependency, so dependency health must be observed
    independently of the active revision's behaviour.
    """

    def __init__(
        self,
        *,
        postgres: tuple[str, int],
        redis: tuple[str, int],
        connector: Optional[Connector] = None,
    ) -> None:
        self._postgres = postgres
        self._redis = redis
        self._connect = connector or _tcp_connect

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "StagingDependencyProbe":
        source = dict(os.environ if env is None else env)
        return cls(
            postgres=(
                source.get("STAGING_PG_HOST", "postgres"),
                int(source.get("STAGING_PG_PORT", "5432")),
            ),
            redis=(
                source.get("STAGING_REDIS_HOST", "redis"),
                int(source.get("STAGING_REDIS_PORT", "6379")),
            ),
        )

    async def check(self) -> DependencyStatus:
        pg, red = await asyncio.gather(
            self._connect(*self._postgres),
            self._connect(*self._redis),
        )
        return DependencyStatus(postgres_ok=pg, redis_ok=red)


class StagingObserver:
    """Bounded, allowlisted observations against the staging gateway."""

    def __init__(
        self,
        profile: ServiceProfile,
        gateway_url: str,
        *,
        tenant_id: str,
        tenant_token: str,
        client: Optional[httpx.AsyncClient] = None,
        dependency_probe: Optional[StagingDependencyProbe] = None,
        timeout: float = 5.0,
        max_bytes: int = MAX_RESPONSE_BYTES,
        max_lines: int = DEFAULT_MAX_LINES,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._profile = profile
        self._gateway = gateway_url.rstrip("/")
        self._tenant_id = tenant_id
        self._tenant_token = tenant_token
        self._client = client
        self._owns_client = client is None
        self._dependencies = dependency_probe
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._max_lines = max_lines
        self._clock = clock

    @property
    def service_id(self) -> str:
        return self._profile.service_id

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    # --- primitives --------------------------------------------------------

    def _bind(self, payload: dict) -> dict:
        """Redact and bound a payload before it leaves the adapter."""

        cleaned = redact_structure(payload, extra=(self._tenant_token,))
        encoded = json.dumps(cleaned, separators=(",", ":"), default=str).encode("utf-8")
        if len(encoded) > self._max_bytes:
            # Keep the structured proof of identity but drop the bulky detail.
            cleaned = {
                key: cleaned[key]
                for key in (
                    "tool",
                    "service_id",
                    "revision",
                    "generation",
                    "predecessor",
                    "http_status",
                    "functional_ok",
                    "dependencies_ok",
                )
                if key in cleaned
            }
            cleaned["truncated"] = True
        return cleaned

    async def _get_json(
        self, path: str, params: Optional[dict] = None, *, auth: bool = False
    ) -> tuple[int, Any, dict]:
        client = self._client
        owns = False
        if client is None:
            client = httpx.AsyncClient(base_url=self._gateway, timeout=self._timeout)
            owns = True
        headers = {"Authorization": f"Bearer {self._tenant_token}"} if auth else {}
        try:
            response = await client.get(
                path, params=params, headers=headers, timeout=self._timeout
            )
        except httpx.HTTPError as exc:
            if owns:
                await client.aclose()
            raise ObservationError(f"gateway_unreachable:{exc.__class__.__name__}") from exc
        finally:
            if owns and client is not None:
                await client.aclose()
        try:
            body = response.json()
        except ValueError:
            body = {}
        # Return the httpx.Headers object (case-insensitive) so callers can read
        # the authoritative identity headers without case-normalisation bugs.
        return response.status_code, response.headers, body if isinstance(body, dict) else {}

    async def _snapshot(self) -> dict:
        status, _, body = await self._get_json("/snapshot")
        if status != 200:
            raise ObservationError(f"snapshot_status:{status}")
        return body

    async def _business(self) -> tuple[int, dict, dict]:
        path = BUSINESS_PATH.format(tenant_id=self._tenant_id)
        return await self._get_json(path, {"limit": 1}, auth=True)

    async def _dependency_status(self) -> DependencyStatus:
        if self._dependencies is None:
            return DependencyStatus(postgres_ok=False, redis_ok=False)
        return await self._dependencies.check()

    # --- public API --------------------------------------------------------

    async def observe(self, kind: str, *, lines: Optional[int] = None) -> StagingObservation:
        if kind == "health":
            return await self.observe_health()
        if kind == "logs":
            return await self.observe_logs(lines or 50)
        if kind == "metrics":
            return await self.observe_metrics()
        if kind == "deployments":
            return await self.observe_deployments()
        raise ObservationError(f"unsupported_observation:{kind}")

    async def observe_health(self) -> StagingObservation:
        snapshot = await self._snapshot()
        status, _, body = await self._business()
        deps = await self._dependency_status()
        functional_ok = 200 <= status < 300
        fields = self._bind(
            {
                "tool": "health",
                "service_id": snapshot.get("service_id") or STAGING_SERVICE,
                "revision": snapshot.get("revision"),
                "generation": snapshot.get("generation"),
                "predecessor": snapshot.get("predecessor"),
                "http_status": status,
                "functional_ok": functional_ok,
                "dependencies_ok": deps.ok,
                "dependencies": {
                    "postgres_ok": deps.postgres_ok,
                    "redis_ok": deps.redis_ok,
                },
                "detail": "functional_pass" if functional_ok else f"functional_fail:{status}",
            }
        )
        return StagingObservation(
            service_id=self.service_id,
            kind="health",
            revision=snapshot.get("revision"),
            generation=snapshot.get("generation"),
            observed_at=self._clock(),
            functional_ok=functional_ok,
            dependencies_ok=deps.ok,
            evidence_fields=fields,
        )

    async def observe_logs(self, lines: int) -> StagingObservation:
        bounded = max(1, min(int(lines), self._max_lines))
        status, _, body = await self._get_json("/api/logs", {"lines": bounded})
        raw = body.get("lines", []) if isinstance(body, dict) else []
        rendered = [dict(entry) if isinstance(entry, dict) else {"message": str(entry)} for entry in raw[:bounded]]
        fields = self._bind(
            {
                "tool": "logs",
                "http_status": status,
                "count": len(rendered),
                "lines": rendered,
            }
        )
        return StagingObservation(
            service_id=self.service_id,
            kind="logs",
            observed_at=self._clock(),
            functional_ok=True,
            dependencies_ok=True,
            evidence_fields=fields,
        )

    async def observe_metrics(self) -> StagingObservation:
        status, _, body = await self._get_json("/api/metrics")
        cleaned = {str(k): body[k] for k in body} if isinstance(body, dict) else {}
        cleaned["http_status"] = status
        cleaned["tool"] = "metrics"
        fields = self._bind(cleaned)
        return StagingObservation(
            service_id=self.service_id,
            kind="metrics",
            observed_at=self._clock(),
            functional_ok=True,
            dependencies_ok=True,
            evidence_fields=fields,
        )

    async def observe_deployments(self, snapshot: Optional[dict] = None) -> StagingObservation:
        body = snapshot if snapshot is not None else await self._snapshot()
        fields = self._bind(
            {
                "tool": "deployments",
                "service_id": body.get("service_id") or self.service_id,
                "current_revision": body.get("revision"),
                "generation": body.get("generation"),
                "predecessor": body.get("predecessor"),
            }
        )
        return StagingObservation(
            service_id=self.service_id,
            kind="deployments",
            revision=body.get("revision"),
            generation=body.get("generation"),
            observed_at=self._clock(),
            functional_ok=True,
            dependencies_ok=True,
            evidence_fields=fields,
        )


class StagingFunctionalProbe:
    """A faithful :class:`FunctionalProbe` for the staging workload.

    It requires the authoritative revision to match the intended one and the
    *authenticated business request* to succeed, and it requires the response's
    own deployment identity headers to match the snapshot's revision and
    generation.  It therefore plugs straight into the shared
    :class:`~incident_recovery.verification.RecoveryVerifier`.
    """

    def __init__(
        self,
        profile: ServiceProfile,
        gateway_url: str,
        *,
        tenant_id: str,
        tenant_token: str,
        observer: Optional[StagingObserver] = None,
        client: Optional[httpx.AsyncClient] = None,
        timeout: float = 5.0,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._observer = observer or StagingObserver(
            profile,
            gateway_url,
            tenant_id=tenant_id,
            tenant_token=tenant_token,
            client=client,
            timeout=timeout,
            clock=clock,
        )
        self._owns_observer = observer is None

    async def aclose(self) -> None:
        if self._owns_observer:
            await self._observer.aclose()

    async def check(self, target_revision: str) -> FunctionalCheck:
        now = self._observer._clock()
        try:
            snapshot = await self._observer._snapshot()
        except ObservationError as exc:
            return FunctionalCheck(False, None, f"snapshot_unreachable:{exc}", now)
        revision = snapshot.get("revision")
        generation = snapshot.get("generation")
        if revision != target_revision:
            return FunctionalCheck(False, revision, "revision_mismatch", now)
        try:
            status, headers, body = await self._observer._business()
        except ObservationError as exc:
            return FunctionalCheck(False, revision, f"business_unreachable:{exc}", now)

        header_revision = headers.get("X-Deployment-Revision")
        header_generation = headers.get("X-Deployment-Generation")
        if header_revision != target_revision:
            return FunctionalCheck(False, revision, "business_identity_revision_mismatch", now)
        if header_generation is None or not str(header_generation).strip().isdigit():
            return FunctionalCheck(False, revision, "business_identity_generation_invalid", now)
        try:
            generation_matches = generation is not None and int(header_generation) == int(generation)
        except (TypeError, ValueError):
            generation_matches = False
        if not generation_matches:
            return FunctionalCheck(False, revision, "business_identity_generation_mismatch", now)

        healthy = 200 <= status < 300
        detail = "functional_pass" if healthy else f"functional_fail:{status}"
        return FunctionalCheck(healthy, revision, detail, now)


def build_staging_probe(
    profile: ServiceProfile,
    gateway_url: str,
    *,
    tenant_id: str,
    tenant_token: str,
    timeout: float = 5.0,
) -> StagingFunctionalProbe:
    return StagingFunctionalProbe(
        profile,
        gateway_url,
        tenant_id=tenant_id,
        tenant_token=tenant_token,
        timeout=timeout,
    )
