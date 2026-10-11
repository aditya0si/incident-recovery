"""Unit tests for sustained functional verification.

The verifier is the *independent* judge of recovery: it never trusts an executor
"success" response.  It requires the public gateway to report the matching active
revision and to return functional health three consecutive times, two seconds
apart, within a 30-second deadline.  A single failure resets the streak and the
deadline produces a failed (never resolved) result.

Time is injected so the tests are deterministic and do not sleep in real time.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import pytest

from incident_recovery.verification import (
    FunctionalCheck,
    GatewayFunctionalProbe,
    RecoveryVerifier,
)

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


def _handler(*, revision: str, health_status: int, body: Optional[dict] = None):
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/snapshot":
            return httpx.Response(200, json={"service_id": "demo-api", "revision": revision, "generation": 3})
        if request.url.path == "/api/health":
            return httpx.Response(health_status, json=body or {"status": "pass", "revision": revision})
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
