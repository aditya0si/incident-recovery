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
from typing import Awaitable, Callable, Optional, Protocol

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
        try:
            snapshot = snapshot_response.json()
        except ValueError:
            snapshot = {}
        if not isinstance(snapshot, dict):
            snapshot = {}
        revision = snapshot.get("revision")
        generation = snapshot.get("generation")
        if revision != target_revision:
            return FunctionalCheck(False, revision, "revision_mismatch", now)

        try:
            health_response = await self._client.get("/api/health", timeout=self._timeout)
        except httpx.HTTPError as exc:
            return FunctionalCheck(False, revision, f"health_unreachable:{exc.__class__.__name__}", now)

        # The gateway stamps the authoritative deployment identity on every
        # proxied response.  Require the health response's own identity headers
        # to match the intended revision and the snapshot generation, so an
        # independent snapshot or an unrelated success can never be blessed.
        # Missing or malformed identity fails closed.
        header_revision = health_response.headers.get("X-Deployment-Revision")
        header_generation = health_response.headers.get("X-Deployment-Generation")
        if header_revision != target_revision:
            return FunctionalCheck(False, revision, "health_identity_revision_mismatch", now)
        if header_generation is None or not str(header_generation).strip().isdigit():
            return FunctionalCheck(False, revision, "health_identity_generation_invalid", now)
        try:
            generation_matches = generation is not None and int(header_generation) == int(generation)
        except (TypeError, ValueError):
            generation_matches = False
        if not generation_matches:
            return FunctionalCheck(False, revision, "health_identity_generation_mismatch", now)

        try:
            body = health_response.json()
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            return FunctionalCheck(False, revision, "health_body_not_object", now)
        body_revision = body.get("revision")
        if body_revision is not None and body_revision != target_revision:
            return FunctionalCheck(False, revision, "health_body_revision_mismatch", now)
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
            # Never start a probe once the deadline has passed.
            if self._elapsed(started) >= self._deadline_seconds:
                reason = "deadline_exceeded"
                break
            if heartbeat is not None:
                await heartbeat()
            # Bound the probe by the remaining deadline: a slow probe can never
            # run past the deadline and then report a late success.
            remaining = self._deadline_seconds - self._elapsed(started)
            if remaining <= 0:
                reason = "deadline_exceeded"
                break
            try:
                check = await asyncio.wait_for(
                    self._probe.check(target_revision), timeout=remaining
                )
            except asyncio.TimeoutError:
                checks.append(
                    FunctionalCheck(
                        ok=False, revision=None, detail="deadline_exceeded", at=self._clock()
                    )
                )
                reason = "deadline_exceeded"
                break
            checks.append(check)
            # Strict elapsed semantics: a probe that completed *after* the
            # deadline can never contribute to a successful streak.
            if self._elapsed(started) > self._deadline_seconds:
                success = False
                reason = "deadline_exceeded"
                break
            streak = streak + 1 if check.ok else 0
            if streak >= self._required_streak:
                success = True
                reason = "verified"
                break
            await self._sleep(self._interval)
            if self._elapsed(started) >= self._deadline_seconds:
                reason = "deadline_exceeded"
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
