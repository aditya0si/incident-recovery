"""Independent, sustained functional verification of a recovery.

Verification is the authority that decides a recovery succeeded: it never trusts
an executor's success response.  Through the *public* stable gateway it requires
the active revision to match the intended known-good predecessor and the
functional health endpoint to succeed three consecutive times, two seconds
apart, within a 30-second deadline.  Any failure resets the streak, and an
expired deadline yields an explicit failure (never ``resolved``).

Timing is injected so unit tests are deterministic and do not sleep in real
time; the Docker E2E suite uses the real defaults.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Awaitable, Callable, Optional, Protocol, Sequence

import httpx

from .models import utcnow

DEFAULT_INTERVAL_SECONDS = 2.0
DEFAULT_REQUIRED_STREAK = 3
DEFAULT_DEADLINE_SECONDS = 30.0


@dataclass(frozen=True)
class FunctionalCheck:
    ok: bool
    revision: Optional[str]
    detail: str
    at: datetime


@dataclass(frozen=True)
class VerificationResult:
    success: bool
    target_revision: str
    checks: tuple[FunctionalCheck, ...]
    consecutive_successes: int
    required_streak: int
    started_at: datetime
    finished_at: datetime
    reason: str

    def as_payload(self) -> dict:
        return {
            "status": "verified" if self.success else "failed",
            "target_revision": self.target_revision,
            "checks": len(self.checks),
            "consecutive_successes": self.consecutive_successes,
            "required_streak": self.required_streak,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "detail": self.reason,
        }


class FunctionalProbe(Protocol):
    async def check(self, target_revision: str) -> FunctionalCheck: ...


class GatewayFunctionalProbe:
    """Checks revision match and functional health through the public gateway."""

    def __init__(self, client: httpx.AsyncClient, *, timeout: float = 5.0) -> None:
        self._client = client
        self._timeout = timeout

    async def check(self, target_revision: str) -> FunctionalCheck:
        now = utcnow()
        try:
            snapshot_response = await self._client.get("/snapshot", timeout=self._timeout)
        except httpx.HTTPError as exc:
            return FunctionalCheck(False, None, f"snapshot_unreachable:{exc.__class__.__name__}", now)
        if snapshot_response.status_code != 200:
            return FunctionalCheck(False, None, f"snapshot_status:{snapshot_response.status_code}", now)
        revision = snapshot_response.json().get("revision")
        if revision != target_revision:
            return FunctionalCheck(False, revision, "revision_mismatch", now)

        try:
            health_response = await self._client.get("/api/health", timeout=self._timeout)
        except httpx.HTTPError as exc:
            return FunctionalCheck(False, revision, f"health_unreachable:{exc.__class__.__name__}", now)
        try:
            body = health_response.json()
        except ValueError:
            body = {}
        healthy = health_response.status_code == 200 and body.get("status") == "pass"
        detail = "functional_pass" if healthy else f"functional_fail:{health_response.status_code}"
        return FunctionalCheck(healthy, revision, detail, now)


class RecoveryVerifier:
    def __init__(
        self,
        probe: FunctionalProbe,
        *,
        interval: float = DEFAULT_INTERVAL_SECONDS,
        required_streak: int = DEFAULT_REQUIRED_STREAK,
        deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
        sleep: Optional[Callable[[float], Awaitable[None]]] = None,
        clock: Optional[Callable[[], datetime]] = None,
    ) -> None:
        if required_streak < 1:
            raise ValueError("required_streak must be >= 1")
        self._probe = probe
        self._interval = interval
        self._required_streak = required_streak
        self._deadline_seconds = deadline_seconds
        self._sleep = sleep or asyncio.sleep
        self._clock = clock or utcnow

    async def verify(
        self,
        target_revision: str,
        *,
        heartbeat: Optional[Callable[[], Awaitable[None]]] = None,
    ) -> VerificationResult:
        started = self._clock()
        checks: list[FunctionalCheck] = []
        streak = 0
        success = False
        reason = "deadline_exceeded"

        while True:
            if heartbeat is not None:
                await heartbeat()
            check = await self._probe.check(target_revision)
            checks.append(check)
            streak = streak + 1 if check.ok else 0
            if streak >= self._required_streak:
                success = True
                reason = "verified"
                break
            if self._elapsed(started) >= self._deadline_seconds:
                break
            await self._sleep(self._interval)
            if self._elapsed(started) >= self._deadline_seconds:
                break

        finished = self._clock()
        return VerificationResult(
            success=success,
            target_revision=target_revision,
            checks=tuple(checks),
            consecutive_successes=streak,
            required_streak=self._required_streak,
            started_at=started,
            finished_at=finished,
            reason=reason,
        )

    def _elapsed(self, started: datetime) -> float:
        return (self._clock() - started).total_seconds()


def build_gateway_probe(gateway_url: str, *, timeout: float = 5.0) -> tuple[GatewayFunctionalProbe, httpx.AsyncClient]:
    """Create a probe plus the HTTP client that owns its lifecycle."""
    client = httpx.AsyncClient(base_url=gateway_url.rstrip("/"), timeout=timeout)
    return GatewayFunctionalProbe(client, timeout=timeout), client
