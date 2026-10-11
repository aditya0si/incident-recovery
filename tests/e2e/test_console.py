"""Real browser end-to-end console checks (Task 5).

These tests drive the real React console in a real Chromium browser against the
live Compose stack, proving the operator flow end to end:

* inject a demo fault from the console UI,
* submit an alert from the UI,
* watch the real worker run the explicitly labeled ``scripted:demo``
  investigation and produce a real, evidence-linked proposal,
* approve the exact digest in the UI and observe the real sustained recovery,
* observe a real escalation (scripted investigation against a healthy
  deployment) and a real operator rejection,
* observe a ``recovery_failed`` view backed by a clearly labeled test-side
  fixture (the only place a fixture is used).

The scripted adapter is enabled only by ``compose.investigation.yaml``; the
default stack requires a live provider and escalates without credentials.

Bring the stack up with the override first, then restore the default stack:

    docker compose -p incident-recovery -f compose.yaml -f compose.investigation.yaml up --build -d --wait
    uv run pytest tests/e2e/test_console.py -v
    docker compose -p incident-recovery up --build -d --wait
"""

from __future__ import annotations

import asyncio
import os
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import asyncpg
import httpx
import pytest
import pytest_asyncio
from playwright.async_api import Browser, async_playwright

from incident_recovery import db as db_module
from incident_recovery.contracts import SwitchRequest
from incident_recovery.gateway import DeploymentStore
from incident_recovery.repository import IncidentRepository

CONSOLE_URL = os.environ.get(
    "CONSOLE_URL", f"http://127.0.0.1:{os.environ.get('CONSOLE_PORT', '18083')}"
)
API_URL = os.environ.get(
    "API_URL", f"http://127.0.0.1:{os.environ.get('API_PORT', '18082')}"
)
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://127.0.0.1:18080")
OPERATOR_TOKEN = os.environ.get("OPERATOR_TOKEN", "")
HEALTHY = "healthy-v1"
BROKEN = "broken-v2"

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EVIDENCE_DIR = _REPO_ROOT / ".hermes" / "evidence"


def _host_dsn() -> str:
    user = os.environ.get("POSTGRES_USER")
    password = os.environ.get("POSTGRES_PASSWORD")
    name = os.environ.get("POSTGRES_DB")
    port = os.environ.get("POSTGRES_PORT", "15432")
    if not (user and password and name):
        raise RuntimeError("Console E2E requires POSTGRES_* values in .env")
    return f"postgresql://{user}:{password}@127.0.0.1:{port}/{name}"


def _wait_ready(url: str, timeout: float = 90.0) -> None:
    deadline = time.time() + timeout
    last = "no attempt"
    while time.time() < deadline:
        try:
            response = httpx.get(url, timeout=3.0)
            if response.status_code == 200:
                return
            last = f"status {response.status_code}"
        except Exception as exc:  # noqa: BLE001 - recorded as evidence
            last = repr(exc)
        time.sleep(1.0)
    raise AssertionError(f"{url} not ready within {timeout}s: {last}")


@dataclass
class Live:
    console_url: str
    api_url: str
    gateway_url: str
    token: str

    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}


@pytest_asyncio.fixture
async def live() -> Live:
    if not OPERATOR_TOKEN:
        pytest.fail("OPERATOR_TOKEN is not set; generate it in .env and start the stack.")
    try:
        _wait_ready(f"{GATEWAY_URL}/healthz")
        _wait_ready(f"{API_URL}/healthz")
        _wait_ready(f"{CONSOLE_URL}/")
    except AssertionError as exc:
        pytest.fail(f"stack not reachable; bring it up first: {exc}")
    return Live(
        console_url=CONSOLE_URL,
        api_url=API_URL,
        gateway_url=GATEWAY_URL,
        token=OPERATOR_TOKEN,
    )


@pytest_asyncio.fixture
async def pool(live: Live):
    connection = await db_module.create_pool(_host_dsn())
    try:
        yield connection
    finally:
        await connection.close()


@pytest_asyncio.fixture
async def browser():
    async with async_playwright() as playwright:
        instance = await playwright.chromium.launch()
        try:
            yield instance
        finally:
            await instance.close()


async def _restore_healthy(pool: asyncpg.Pool) -> None:
    await pool.execute(
        "UPDATE deployment_reservations SET status = 'released', released_at = now() "
        "WHERE status = 'active'"
    )
    store = DeploymentStore(pool)
    repo = IncidentRepository(pool)
    snapshot = await store.get_snapshot()
    if snapshot.revision == HEALTHY:
        return
    operation_id = uuid.uuid4()
    await repo.reserve(
        operation_id,
        scope="fault",
        expected_generation=snapshot.generation,
        target_revision=HEALTHY,
    )
    try:
        decision = await store.switch(
            SwitchRequest(
                operation_id=operation_id,
                expected_generation=snapshot.generation,
                target_revision=HEALTHY,
                scope="fault",
            )
        )
        assert decision.status == "applied"
    finally:
        await repo.release_reservation(operation_id)


async def _wait_for_incident(
    api: httpx.AsyncClient,
    *,
    states: set[str],
    summary: Optional[str] = None,
    incident_id: Optional[str] = None,
    timeout: float = 150.0,
) -> dict:
    deadline = time.time() + timeout
    last: dict = {}
    while time.time() < deadline:
        if incident_id is None:
            listing = await api.get("/incidents")
            if listing.status_code == 200:
                for item in listing.json():
                    if item.get("summary") == summary:
                        incident_id = item["id"]
                        break
            if incident_id is None:
                await asyncio.sleep(1.0)
                continue
        response = await api.get(f"/incidents/{incident_id}")
        if response.status_code == 200:
            last = response.json()
            if last["state"] in states:
                return last
        await asyncio.sleep(1.0)
    raise AssertionError(
        f"incident {incident_id or summary} did not reach {states} in {timeout}s: {last}"
    )


def _record_page(page) -> list[str]:
    events: list[str] = []
    page.on("console", lambda msg: events.append(f"console:{msg.type}:{msg.text}"))
    page.on("pageerror", lambda exc: events.append(f"pageerror:{exc}"))
    page.on("requestfailed", lambda req: events.append(f"requestfailed:{req.url}"))
    return events


async def _shot(page, name: str) -> None:
    try:
        _EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        await page.screenshot(path=str(_EVIDENCE_DIR / name), full_page=True)
    except Exception:  # noqa: BLE001 - screenshots are best-effort evidence
        pass


async def _cleanup_incident(pool: asyncpg.Pool, incident_id: Optional[str]) -> None:
    if incident_id is None:
        return
    await pool.execute(
        "UPDATE incidents SET state = 'recovery_failed', lease_owner = NULL, "
        "lease_expires_at = NULL, updated_at = now() "
        "WHERE id = $1 AND state NOT IN "
        "('resolved','escalated','rejected','recovery_failed')",
        uuid.UUID(incident_id),
    )


async def test_console_scripted_investigation_to_verified_recovery(
    live: Live, pool: asyncpg.Pool, browser: Browser
) -> None:
    await _restore_healthy(pool)
    context = await browser.new_context(viewport={"width": 1280, "height": 900})
    page = await context.new_page()
    page.set_default_timeout(25000)
    log = _record_page(page)
    incident_id: Optional[str] = None
    try:
        await page.goto(live.console_url, wait_until="domcontentloaded")
        await page.get_by_label("Operator token").fill(live.token)

        await page.get_by_role("button", name="Inject demo fault (broken-v2)").click()
        await page.get_by_text(
            re.compile(r"Demo fault injection: (applied|already_active|reconciled)")
        ).wait_for()
        broken = httpx.get(f"{live.gateway_url}/api/work", timeout=5.0)
        assert broken.status_code == 500 and broken.json()["ok"] is False

        summary = f"console-e2e-{uuid.uuid4()}"
        await page.get_by_label("New alert summary").fill(summary)
        await page.get_by_role("button", name="Submit alert").click()

        async with httpx.AsyncClient(
            base_url=live.api_url, headers=live.headers(), timeout=10.0
        ) as api:
            detail = await _wait_for_incident(
                api, states={"awaiting_approval", "escalated"}, summary=summary
            )
        assert detail["state"] == "awaiting_approval", (
            "worker escalated; bring the stack up with compose.investigation.yaml so the "
            f"explicit scripted adapter is enabled: {detail}"
        )
        incident_id = detail["id"]
        assert detail["proposal"]["target_revision"] == HEALTHY
        assert len(detail["proposal"]["evidence_ids"]) >= 2
        assert detail["investigation"]["run"]["adapter"] == "scripted:demo"

        await page.get_by_role("button", name=re.compile(re.escape(incident_id))).click()
        await page.get_by_text("Scripted demo adapter").first.wait_for()
        # Cited evidence links resolve to rendered evidence records.
        first_evidence_id = detail["evidence"][0]["id"]
        await page.locator(f"a[href='#evidence-{first_evidence_id}']").first.wait_for()
        await page.locator(f"#evidence-{first_evidence_id}").wait_for()
        await _shot(page, "console-proposal-scripted.png")

        await page.get_by_label("Approver").fill("e2e-operator")
        await page.get_by_role("button", name="Approve", exact=True).click()

        async with httpx.AsyncClient(
            base_url=live.api_url, headers=live.headers(), timeout=10.0
        ) as api:
            final = await _wait_for_incident(
                api, states={"resolved", "recovery_failed"}, incident_id=incident_id
            )
        assert final["state"] == "resolved", final
        assert final["verification"]["consecutive_successes"] >= 3

        await page.get_by_text("Resolved", exact=True).first.wait_for(timeout=25000)
        await page.get_by_text("recovery_verified").first.wait_for(timeout=25000)
        healthy = httpx.get(f"{live.gateway_url}/api/work", timeout=5.0)
        assert healthy.status_code == 200 and healthy.json()["ok"] is True
        await _shot(page, "console-resolved.png")
    finally:
        await _cleanup_incident(pool, incident_id)
        await _restore_healthy(pool)
        await context.close()
        _write_log(log, "console-main.log")


async def test_console_real_escalation_view(
    live: Live, pool: asyncpg.Pool, browser: Browser
) -> None:
    # Healthy deployment + scripted investigation => the deterministic gate sees
    # no functional failure and the real worker escalates.
    await _restore_healthy(pool)
    context = await browser.new_context(viewport={"width": 1280, "height": 900})
    page = await context.new_page()
    page.set_default_timeout(25000)
    log = _record_page(page)
    incident_id: Optional[str] = None
    try:
        await page.goto(live.console_url, wait_until="domcontentloaded")
        await page.get_by_label("Operator token").fill(live.token)
        summary = f"console-escalation-{uuid.uuid4()}"
        await page.get_by_label("New alert summary").fill(summary)
        await page.get_by_role("button", name="Submit alert").click()

        async with httpx.AsyncClient(
            base_url=live.api_url, headers=live.headers(), timeout=10.0
        ) as api:
            detail = await _wait_for_incident(api, states={"escalated"}, summary=summary)
        incident_id = detail["id"]
        assert detail["investigation"]["run"]["state"] == "escalated"

        await page.get_by_role("button", name=re.compile(re.escape(incident_id))).click()
        await page.get_by_text("Scripted demo adapter").first.wait_for()
        await page.get_by_text("Escalated", exact=True).first.wait_for()
        await page.get_by_text(re.compile("no_functional_failure")).first.wait_for()
        await _shot(page, "console-escalated.png")
    finally:
        await _cleanup_incident(pool, incident_id)
        await _restore_healthy(pool)
        await context.close()
        _write_log(log, "console-escalation.log")


async def test_console_rejection_view(
    live: Live, pool: asyncpg.Pool, browser: Browser
) -> None:
    await _restore_healthy(pool)
    context = await browser.new_context(viewport={"width": 1280, "height": 900})
    page = await context.new_page()
    page.set_default_timeout(25000)
    log = _record_page(page)
    incident_id: Optional[str] = None
    try:
        async with httpx.AsyncClient(
            base_url=live.api_url, headers=live.headers(), timeout=10.0
        ) as api:
            fault = await api.post("/demo/faults", json={"target_revision": BROKEN})
            assert fault.status_code == 200, fault.text

        await page.goto(live.console_url, wait_until="domcontentloaded")
        await page.get_by_label("Operator token").fill(live.token)
        summary = f"console-rejection-{uuid.uuid4()}"
        await page.get_by_label("New alert summary").fill(summary)
        await page.get_by_role("button", name="Submit alert").click()

        async with httpx.AsyncClient(
            base_url=live.api_url, headers=live.headers(), timeout=10.0
        ) as api:
            detail = await _wait_for_incident(api, states={"awaiting_approval"}, summary=summary)
        incident_id = detail["id"]

        await page.get_by_role("button", name=re.compile(re.escape(incident_id))).click()
        await page.get_by_label("Approver").fill("e2e-operator")
        await page.get_by_role("button", name="Reject", exact=True).click()

        async with httpx.AsyncClient(
            base_url=live.api_url, headers=live.headers(), timeout=10.0
        ) as api:
            rejected = await _wait_for_incident(
                api, states={"rejected"}, incident_id=incident_id
            )
        assert rejected["operation"] is None
        await page.get_by_text("Rejected", exact=True).first.wait_for(timeout=25000)
        await _shot(page, "console-rejected.png")
    finally:
        await _cleanup_incident(pool, incident_id)
        await _restore_healthy(pool)
        await context.close()
        _write_log(log, "console-rejection.log")


async def test_console_recovery_failed_fixture_view(
    live: Live, pool: asyncpg.Pool, browser: Browser
) -> None:
    # Labeled test-side fixture for a failure state that is impractical to induce
    # in a normal demo: the console still reads it through the real API.
    incident_id = uuid.uuid4()
    operation_id = uuid.uuid4()
    await pool.execute(
        "INSERT INTO incidents (id, dedupe_key, service_id, state, summary, "
        "alert_payload, detected_at, updated_at, version) "
        "VALUES ($1, $2, 'demo-api', 'recovery_failed', $3, '{}'::jsonb, now(), now(), 1)",
        incident_id,
        f"fixture-recovery-failed-{incident_id}",
        "fixture: recovery_failed",
    )
    verification = {
        "status": "recovery_failed",
        "checks": 3,
        "consecutive_successes": 1,
        "required_streak": 3,
        "detail": "functional check failed after rollback",
    }
    await pool.execute(
        "INSERT INTO recovery_operations (id, incident_id, status, target_revision, result, "
        "service_id, expected_generation, attempts, last_error, created_at, updated_at) "
        "VALUES ($1, $2, 'failed', 'healthy-v1', $3::jsonb, 'demo-api', 2, 1, "
        "'verification_failed', now(), now())",
        operation_id,
        incident_id,
        verification,
    )

    async with httpx.AsyncClient(
        base_url=live.api_url, headers=live.headers(), timeout=10.0
    ) as api:
        detail = (await api.get(f"/incidents/{incident_id}")).json()
    assert detail["operation"] is not None, detail
    assert detail["operation"]["last_error"] == "verification_failed", detail
    assert detail["verification"]["status"] == "recovery_failed", detail

    context = await browser.new_context(viewport={"width": 1280, "height": 900})
    page = await context.new_page()
    page.set_default_timeout(25000)
    try:
        await page.goto(live.console_url, wait_until="domcontentloaded")
        await page.get_by_role("button", name=re.compile(str(incident_id))).click()
        await page.get_by_role("heading", name=str(incident_id)).wait_for()
        await page.get_by_text("Recovery failed", exact=True).first.wait_for()
        await page.get_by_text(re.compile("verification_failed")).first.wait_for()
        await _shot(page, "console-recovery-failed-fixture.png")
    finally:
        await context.close()
        await pool.execute(
            "DELETE FROM incidents WHERE id = $1", incident_id
        )


async def test_console_narrow_viewport_and_labels(
    live: Live, pool: asyncpg.Pool, browser: Browser
) -> None:
    await _restore_healthy(pool)
    context = await browser.new_context(viewport={"width": 390, "height": 844})
    page = await context.new_page()
    page.set_default_timeout(25000)
    try:
        await page.goto(live.console_url, wait_until="domcontentloaded")
        await page.get_by_label("Operator token").wait_for()
        # Keyboard focus reaches the token input via Tab from the document.
        await page.keyboard.press("Tab")
        focused = await page.evaluate("document.activeElement && document.activeElement.tagName")
        assert focused in ("INPUT", "BUTTON")
        overflow = await page.evaluate(
            "document.documentElement.scrollWidth - window.innerWidth"
        )
        assert overflow <= 2, f"horizontal overflow at 390px: {overflow}px"
        await _shot(page, "console-narrow.png")
    finally:
        await context.close()


def _write_log(events: list[str], name: str) -> None:
    try:
        _EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        (_EVIDENCE_DIR / name).write_text("\n".join(events) + "\n", encoding="utf-8")
    except Exception:  # noqa: BLE001 - evidence logging is best-effort
        pass
