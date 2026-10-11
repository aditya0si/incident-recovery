"""Unit tests for sustained functional verification.

The verifier is the *independent* judge of recovery: it never trusts an executor
"success" response.  It requires the public gateway to report the matching active
revision and to return functional health three consecutive times, two seconds
apart, within a 30-second deadline.  A single failure resets the streak and the
deadline produces a failed (never resolved) result.

Time is injected so the tests are deterministic and do not sleep in real time.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import pytest

from incident_recovery.verification import (
    FunctionalCheck,
    GatewayFunctionalProbe,
    RecoveryVerifier,
)

_AUTO = object()

START = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)
TARGET = "healthy-v1"


class FakeTime:
    """Controllable monotonic clock whose ``sleep`` advances the clock."""

    def __init__(self, start: datetime = START) -> None:
        self.current = start

    def now(self) -> datetime:
        return self.current

    async def sleep(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)


class ScriptedProbe:
    """Returns a scripted sequence of check results (last value repeats)."""

    def __init__(self, script: list[bool]) -> None:
        self.script = script
        self.calls = 0

    async def check(self, target_revision: str) -> FunctionalCheck:
        index = min(self.calls, len(self.script) - 1)
        ok = self.script[index]
        self.calls += 1
        return FunctionalCheck(
            ok=ok,
            revision=target_revision if ok else "broken-v2",
            detail="scripted",
            at=START,
        )


def _verifier(probe: ScriptedProbe, time: FakeTime) -> RecoveryVerifier:
    return RecoveryVerifier(
        probe,
        interval=2.0,
        required_streak=3,
        deadline_seconds=30.0,
        sleep=time.sleep,
        clock=time.now,
    )


async def test_three_consecutive_successes_resolve() -> None:
    time = FakeTime()
    result = await _verifier(ScriptedProbe([True]), time).verify(TARGET)
    assert result.success is True
    assert result.consecutive_successes == 3
    assert len(result.checks) == 3
    assert result.reason == "verified"


async def test_failure_resets_streak_before_success() -> None:
    time = FakeTime()
    probe = ScriptedProbe([True, True, False, True, True, True])
    result = await _verifier(probe, time).verify(TARGET)
    assert result.success is True
    # Two successes, one failure, then three consecutive successes.
    assert probe.calls == 6
    assert result.consecutive_successes == 3
    assert result.checks[-1].ok is True


async def test_deadline_exceeded_is_recovery_failure() -> None:
    time = FakeTime()
    result = await _verifier(ScriptedProbe([False]), time).verify(TARGET)
    assert result.success is False
    assert result.consecutive_successes == 0
    assert result.reason == "deadline_exceeded"
    # The final check is at t=30s; no successful streak can form.
    assert time.current <= START + timedelta(seconds=30)


async def test_heartbeat_called_between_checks() -> None:
    time = FakeTime()
    beats = 0

    async def heartbeat() -> None:
        nonlocal beats
        beats += 1

    await _verifier(ScriptedProbe([True]), time).verify(TARGET, heartbeat=heartbeat)
    assert beats >= 3


# --- functional probe: revision match plus functional health ----------------


def _probe(handler) -> GatewayFunctionalProbe:
    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport, base_url="http://gateway.test")
    return GatewayFunctionalProbe(client)


def _handler(
    *,
    revision: str,
    health_status: int,
    body: Optional[dict] = None,
    snapshot_generation: int = 3,
    header_revision=_AUTO,
    header_generation=_AUTO,
):
    """Gateway double.

    ``header_revision``/``header_generation`` default to the consistent values;
    pass ``None`` to omit a header or an explicit value to forge/mismatch it.
    """

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/snapshot":
            return httpx.Response(
                200,
                json={"service_id": "demo-api", "revision": revision, "generation": snapshot_generation},
            )
        if request.url.path == "/api/health":
            headers: dict = {}
            effective_revision = revision if header_revision is _AUTO else header_revision
            effective_generation = (
                snapshot_generation if header_generation is _AUTO else header_generation
            )
            if effective_revision is not None:
                headers["X-Deployment-Revision"] = str(effective_revision)
            if effective_generation is not None:
                headers["X-Deployment-Generation"] = str(effective_generation)
            return httpx.Response(
                health_status,
                json=body or {"status": "pass", "revision": revision},
                headers=headers,
            )
        return httpx.Response(404)

    return handle


async def test_probe_requires_matching_revision_and_functional_health() -> None:
    good = _probe(_handler(revision=TARGET, health_status=200))
    check = await good.check(TARGET)
    assert check.ok is True
    assert check.revision == TARGET


async def test_probe_rejects_revision_mismatch() -> None:
    stale = _probe(_handler(revision="broken-v2", health_status=200))
    check = await stale.check(TARGET)
    assert check.ok is False


async def test_probe_rejects_functional_failure() -> None:
    failing = _probe(_handler(revision=TARGET, health_status=503, body={"status": "fail"}))
    check = await failing.check(TARGET)
    assert check.ok is False


async def test_probe_rejects_unknown_revision_in_snapshot() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/snapshot":
            return httpx.Response(200, json={"service_id": "demo-api", "revision": None, "generation": 3})
        return httpx.Response(200, json={"status": "pass"})

    check = await _probe(handle).check(TARGET)
    assert check.ok is False


# --- Finding 6: health identity must be authoritative and consistent ----------


async def test_probe_rejects_health_identity_revision_mismatch() -> None:
    """Snapshot says healthy-v1 but the health response is from broken-v2."""

    probe = _probe(
        _handler(
            revision=TARGET,
            health_status=200,
            header_revision="broken-v2",
            header_generation=4,
            body={"status": "pass", "revision": "broken-v2"},
        )
    )
    check = await probe.check(TARGET)
    assert check.ok is False
    assert check.detail == "health_identity_revision_mismatch"


async def test_probe_rejects_missing_health_identity_headers() -> None:
    probe = _probe(
        _handler(revision=TARGET, health_status=200, header_revision=None, header_generation=None)
    )
    check = await probe.check(TARGET)
    assert check.ok is False


async def test_probe_rejects_malformed_generation_header() -> None:
    probe = _probe(
        _handler(revision=TARGET, health_status=200, header_generation="not-a-number")
    )
    check = await probe.check(TARGET)
    assert check.ok is False
    assert check.detail == "health_identity_generation_invalid"


async def test_probe_rejects_generation_inconsistent_with_snapshot() -> None:
    probe = _probe(
        _handler(revision=TARGET, health_status=200, snapshot_generation=3, header_generation=4)
    )
    check = await probe.check(TARGET)
    assert check.ok is False
    assert check.detail == "health_identity_generation_mismatch"


async def test_probe_rejects_body_revision_mismatch() -> None:
    probe = _probe(
        _handler(
            revision=TARGET,
            health_status=200,
            body={"status": "pass", "revision": "broken-v2"},
        )
    )
    check = await probe.check(TARGET)
    assert check.ok is False
    assert check.detail == "health_body_revision_mismatch"


# --- Finding 5: strict elapsed deadline --------------------------------------


class SlowProbe:
    """A probe whose check advances the injected clock by ``per_check`` seconds."""

    def __init__(self, time: FakeTime, *, per_check: float = 9.0, ok: bool = True) -> None:
        self._time = time
        self._per = per_check
        self._ok = ok
        self.calls = 0

    async def check(self, target_revision: str) -> FunctionalCheck:
        self.calls += 1
        self._time.current += timedelta(seconds=self._per)
        return FunctionalCheck(ok=self._ok, revision=target_revision, detail="slow", at=self._time.current)


async def test_slow_probe_cannot_resolve_after_deadline() -> None:
    """Three 9s checks plus two 2s waits (31s) must not verify within 30s."""

    time = FakeTime()
    probe = SlowProbe(time, per_check=9.0, ok=True)
    verifier = RecoveryVerifier(
        probe,
        interval=2.0,
        required_streak=3,
        deadline_seconds=30.0,
        sleep=time.sleep,
        clock=time.now,
    )
    result = await verifier.verify(TARGET)
    assert result.success is False
    assert result.reason == "deadline_exceeded"
    # The late third success never contributes to the streak.
    assert result.consecutive_successes < result.required_streak


async def test_slow_probe_within_deadline_can_still_verify() -> None:
    """A genuinely fast-enough sustained recovery still verifies."""

    time = FakeTime()
    probe = SlowProbe(time, per_check=1.0, ok=True)
    verifier = RecoveryVerifier(
        probe,
        interval=2.0,
        required_streak=3,
        deadline_seconds=30.0,
        sleep=time.sleep,
        clock=time.now,
    )
    result = await verifier.verify(TARGET)
    assert result.success is True
    assert result.reason == "verified"


async def test_slow_real_client_never_resolves_beyond_deadline() -> None:
    """Real slow client control: a probe slower than the deadline fails closed."""

    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.5)
        if request.url.path == "/snapshot":
            return httpx.Response(200, json={"service_id": "demo-api", "revision": TARGET, "generation": 1})
        return httpx.Response(
            200,
            json={"status": "pass", "revision": TARGET},
            headers={"X-Deployment-Revision": TARGET, "X-Deployment-Generation": "1"},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://gateway.test")
    probe = GatewayFunctionalProbe(client)
    verifier = RecoveryVerifier(probe, interval=2.0, required_streak=3, deadline_seconds=0.3)
    started = time.monotonic()
    try:
        result = await verifier.verify(TARGET)
    finally:
        await client.aclose()
    elapsed = time.monotonic() - started
    assert result.success is False
    assert result.reason == "deadline_exceeded"
    assert elapsed < 2.0
