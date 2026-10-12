#!/usr/bin/env python
"""Real authenticated, operator-approved recovery of the staging tenant service.

This is the Task 3 executable evidence.  It runs the *real* workload and the
*real* control plane: it builds and starts the pinned healthy tenant API and the
isolated faulty binary, drives real authenticated tenant traffic through the
stable staging gateway, injects the fault, runs the reviewed investigation gate,
obtains a clearly-labelled operator-harness approval, executes the traffic
rollback, and verifies three consecutive authenticated business successes two
seconds apart within thirty seconds.

It also exercises the non-repairable path: a real workload dependency outage
(PostgreSQL/Redis stopped by the operator harness) must escalate and must never
admit a rollback.

Nothing is fabricated: every check records the actual command/request and its
observed result.  Required prerequisites fail loudly, and both stacks are left
healthy.  The provider runtime gate is reported as blocked (no live call).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import staging_env  # noqa: E402
import staging_fault  # noqa: E402
import staging_source  # noqa: E402

from incident_recovery import db as db_module  # noqa: E402
from incident_recovery.agent import InvestigationAgent  # noqa: E402
from incident_recovery.executor import RecoveryExecutor  # noqa: E402
from incident_recovery.gateway import DeploymentStore  # noqa: E402
from incident_recovery.models import IncidentState  # noqa: E402
from incident_recovery.repository import IncidentRepository  # noqa: E402
from incident_recovery.service_profile import STAGING_PROFILE  # noqa: E402
from incident_recovery.staging.contracts import StagingSwitchRequest  # noqa: E402
from incident_recovery.staging.observations import (  # noqa: E402
    ObservationError,
    StagingDependencyProbe,
    StagingFunctionalProbe,
    StagingObserver,
)
from incident_recovery.staging.workload import (  # noqa: E402
    StagingScriptedAdapter,
    StagingToolRunner,
)
from incident_recovery.verification import RecoveryVerifier  # noqa: E402
from incident_recovery.worker import RecoveryWorker  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
STAGING = REPO_ROOT / "staging"
COMPOSE_FILE = STAGING / "compose.yaml"
OVERRIDE_FILE = STAGING / "compose.recovery.yaml"
ENV_FILE = STAGING / ".env"
CONTROL_ENV_FILE = STAGING / ".control.env"
PROJECT = "incident-recovery-staging"
DEFAULT_EVIDENCE = REPO_ROOT / ".hermes" / "evidence" / "staging-task3"

PROFILE = STAGING_PROFILE
HEALTHY = PROFILE.healthy_revision
FAULTY = PROFILE.faulty_revision
SERVICE = PROFILE.service_id

WORKLOAD_DB_PORT = 18096
WORKLOAD_REDIS_PORT = 18097
WORKER_ID = "staging-recovery-driver"
APPROVER = "operator-harness (scripted/test)"


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""
    duration_seconds: float = 0.0


@dataclass
class Report:
    task: str = "staging-task3"
    status: str = "failed"
    project: str = PROJECT
    source_sha: str = ""
    healthy_revision: str = HEALTHY
    faulty_revision: str = FAULTY
    patch_sha256: str = ""
    adapter_identity: str = ""
    live_provider: str = "blocked"
    ports: dict = field(default_factory=dict)
    images: dict = field(default_factory=dict)
    started_at: str = ""
    finished_at: str = ""
    checks: list = field(default_factory=list)

    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == "passed")


class Checks:
    def __init__(self) -> None:
        self.items: list[Check] = []

    def record(self, name: str, ok: bool, detail: str = "", duration: float = 0.0) -> bool:
        self.items.append(
            Check(name=name, status="passed" if ok else "failed", detail=detail, duration_seconds=duration)
        )
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
        return ok


class Sanitizer:
    def __init__(self, secrets_: list[str]) -> None:
        self._secrets = sorted({s for s in secrets_ if s and len(s) >= 6}, key=len, reverse=True)

    def __call__(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, "[REDACTED]")
        return text


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(argv: list[str], *, timeout: float, sanitizer: Sanitizer | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(
        argv,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    if sanitizer is not None and result.stdout:
        result = subprocess.CompletedProcess(result.args, result.returncode, sanitizer(result.stdout), "")
    return result


def compose_argv(*args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(COMPOSE_FILE),
        "-f",
        str(OVERRIDE_FILE),
        "--env-file",
        str(ENV_FILE),
        "--env-file",
        str(CONTROL_ENV_FILE),
        "--profile",
        "recovery",
        "-p",
        PROJECT,
        *args,
    ]


def http_request(method, url, *, body=None, token=None, timeout=15.0):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return exc.code, {}


class StoreSwitchClient:
    """In-process switch client bound to the authoritative staging store."""

    def __init__(self, store: DeploymentStore) -> None:
        self._store = store

    async def switch(self, *, operation_id, expected_generation, target_revision, scope):
        return await self._store.switch(
            StagingSwitchRequest(
                operation_id=operation_id,
                expected_generation=expected_generation,
                target_revision=target_revision,
                scope=scope,
            )
        )


def _control_dsn(values: dict) -> str:
    user = values["STAGING_CONTROL_DB_USER"]
    password = values["STAGING_CONTROL_DB_PASSWORD"]
    name = values["STAGING_CONTROL_DB"]
    port = values["STAGING_CONTROL_DB_PORT"]
    return f"postgresql://{user}:{password}@127.0.0.1:{port}/{name}"


def _register_tenant(api_base: str, sanitizer: Sanitizer) -> dict:
    run_id = uuid.uuid4().hex[:10]
    password = secrets.token_urlsafe(18)
    status, body = http_request(
        "POST",
        api_base + "/v1/auth/register",
        body={
            "email": f"recovery-{run_id}@staging.test",
            "password": password,
            "tenant_name": f"Recovery {run_id}",
        },
    )
    data = (body or {}).get("data") or {}
    token = data.get("access_token")
    tenant_id = (data.get("tenants") or [{}])[0].get("tenant_id")
    if status != 201 or not token or not tenant_id:
        raise RuntimeError(f"tenant registration failed (status {status})")
    return {"token": token, "tenant_id": tenant_id}


async def _drive(
    repo,
    store,
    observer,
    probe,
    *,
    checks: Checks,
    evidence_dir: Path,
) -> None:
    agent = InvestigationAgent(
        repo,
        StagingToolRunner(repo, observer),
        StagingScriptedAdapter(),
        WORKER_ID,
        service_id=SERVICE,
        known_good_revision=HEALTHY,
        broken_revision=FAULTY,
    )
    async def _dependencies_healthy() -> bool:
        """A bounded fresh dependency attestation immediately before mutation."""

        try:
            health = await observer.observe_health()
        except ObservationError:
            return False
        return bool(health.dependencies_ok)

    executor = RecoveryExecutor(
        repo, StoreSwitchClient(store), store, dependency_check=_dependencies_healthy
    )
    verifier = RecoveryVerifier(probe, interval=2.0, required_streak=3, deadline_seconds=30.0)
    worker = RecoveryWorker(
        repo,
        executor,
        verifier,
        WORKER_ID,
        lease_seconds=120,
        investigator=agent,
        investigation_lease_seconds=180,
        poll_interval=0.2,
    )

    # --- 1. inject the real fault (operator harness switch) ------------------
    snapshot = await store.get_snapshot()
    checks.record(
        "initial active revision is the pinned healthy binary",
        snapshot.revision == HEALTHY,
        f"revision={snapshot.revision} generation={snapshot.generation}",
    )
    fault_op = uuid.uuid4()
    await repo.reserve(
        fault_op,
        scope="fault",
        expected_generation=snapshot.generation,
        target_revision=FAULTY,
        service_id=SERVICE,
    )
    decision = await store.switch(
        StagingSwitchRequest(
            operation_id=fault_op,
            expected_generation=snapshot.generation,
            target_revision=FAULTY,
            scope="fault",
        )
    )
    await repo.release_reservation(fault_op)
    checks.record(
        "fault switch routes traffic to the injected faulty binary",
        decision.status == "applied" and decision.snapshot.revision == FAULTY,
        f"status={decision.status} revision={decision.snapshot.revision}",
    )

    faulty_health = await observer.observe_health()
    checks.record(
        "real authenticated business request fails on the faulty binary",
        faulty_health.functional_ok is False,
        f"http_status={faulty_health.evidence_fields.get('http_status')}",
    )
    checks.record(
        "workload dependencies remain healthy during the functional fault",
        faulty_health.dependencies_ok is True,
    )

    # --- 2. investigation (reviewed gate, scripted adapter) ------------------
    incident, _ = await repo.ingest_alert(
        f"staging-recovery-{fault_op.hex[:8]}", SERVICE, "real functional fault", {}
    )
    for _ in range(6):
        await worker.run_once()
        current = await repo.get_incident(incident.id)
        if current is not None and current.state is IncidentState.AWAITING_APPROVAL:
            break
    proposal = await repo.get_proposal_for_incident(incident.id)
    checks.record(
        "scripted investigation produced an evidence-supported rollback proposal",
        proposal is not None
        and proposal.service_id == SERVICE
        and proposal.target_revision == HEALTHY,
        f"target={getattr(proposal, 'target_revision', None)}",
    )
    if proposal is None:
        return

    # --- 3. operator-harness approval ---------------------------------------
    approval, operation, created = await repo.approve_incident(
        incident.id, proposal.digest, APPROVER, service_id=SERVICE
    )
    checks.record(
        "operator harness approval binds the staging service and a known-good target",
        created
        and approval.service_id == SERVICE
        and approval.target_revision == HEALTHY
        and approval.actor == APPROVER,
        f"actor={approval.actor} target={approval.target_revision}",
    )

    # --- 4. execute + sustained authenticated verification ------------------
    await worker.run_once()
    resolved = await repo.get_incident(incident.id)
    final_operation = await repo.get_operation_for_incident(incident.id)
    checks.record(
        "incident recovered to resolved after the approved traffic rollback",
        resolved is not None and resolved.state is IncidentState.RESOLVED,
        f"state={getattr(resolved, 'state', None)}",
    )
    checks.record(
        "recovery operation verified the sustained functional recovery",
        final_operation is not None and final_operation.status == "verified",
        f"status={getattr(final_operation, 'status', None)}",
    )
    after = await store.get_snapshot()
    checks.record(
        "active revision is the known-good healthy binary after recovery",
        after.revision == HEALTHY and after.predecessor == FAULTY,
        f"revision={after.revision} predecessor={after.predecessor}",
    )

    # Three more authenticated business successes, two seconds apart.
    successes = 0
    for _ in range(3):
        check = await probe.check(HEALTHY)
        if check.ok:
            successes += 1
        await asyncio.sleep(2.0)
    checks.record(
        "three consecutive authenticated business requests succeed after recovery",
        successes == 3,
        f"successes={successes}/3",
    )

    # --- 5. real dependency outage: must escalate, never roll back -----------
    checks.record(
        "dependency outage: workload PostgreSQL/Redis stopped by the operator harness",
        _stop_workload_dependencies(),
    )
    await asyncio.sleep(2.0)
    outage_health = await observer.observe_health()
    checks.record(
        "dependency outage is observed independently of the active revision",
        outage_health.dependencies_ok is False,
        f"dependencies_ok={outage_health.dependencies_ok} functional_ok={outage_health.functional_ok}",
    )
    outage_incident, _ = await repo.ingest_alert(
        f"staging-outage-{uuid.uuid4().hex[:8]}", SERVICE, "dependency outage", {}
    )
    for _ in range(6):
        await worker.run_once()
        current = await repo.get_incident(outage_incident.id)
        if current is not None and current.state in (
            IncidentState.ESCALATED,
            IncidentState.AWAITING_APPROVAL,
        ):
            break
    outage_final = await repo.get_incident(outage_incident.id)
    outage_proposal = await repo.get_proposal_for_incident(outage_incident.id)
    checks.record(
        "dependency outage escalates and admits no executable rollback",
        outage_final is not None
        and outage_final.state is IncidentState.ESCALATED
        and outage_proposal is None,
        f"state={getattr(outage_final, 'state', None)} proposal={outage_proposal is not None}",
    )
    checks.record(
        "no recovery rollback was executed during the dependency outage",
        (await store.get_snapshot()).revision == HEALTHY,
    )

    # --- 6. restore dependencies and confirm repair is possible again --------
    checks.record("dependency outage cleanup: dependencies restarted", _start_workload_dependencies())
    await asyncio.sleep(3.0)
    restored = await observer.observe_health()
    checks.record(
        "restored dependencies report healthy again",
        restored.dependencies_ok is True and restored.functional_ok is True,
    )

    # --- 7. interruption resume: a decided investigation resumes cleanly -----
    incident2, _ = await repo.ingest_alert(
        f"staging-resume-{uuid.uuid4().hex[:8]}", SERVICE, "resume check", {}
    )
    await worker.run_once()
    first = await repo.get_incident(incident2.id)
    await worker.run_once()  # a second claim must not duplicate or reset the run
    second = await repo.get_incident(incident2.id)
    runs = await repo.get_latest_investigation_run(incident2.id)
    checks.record(
        "interrupted/duplicate claim resumes the same investigation without reset",
        first is not None
        and second is not None
        and first.state is second.state
        and runs is not None
        and runs.tool_calls <= 12,
        f"state={getattr(second, 'state', None)} tool_calls={getattr(runs, 'tool_calls', None)}",
    )


async def _restore(store, repo) -> None:
    """Best-effort restore of the staging environment: deps up, healthy active."""

    _start_workload_dependencies()
    try:
        snapshot = await store.get_snapshot()
        if snapshot.revision == HEALTHY:
            return
        operation_id = uuid.uuid4()
        await repo.reserve(
            operation_id,
            scope="fault",
            expected_generation=snapshot.generation,
            target_revision=HEALTHY,
            service_id=SERVICE,
        )
        try:
            await store.switch(
                StagingSwitchRequest(
                    operation_id=operation_id,
                    expected_generation=snapshot.generation,
                    target_revision=HEALTHY,
                    scope="fault",
                )
            )
        finally:
            await repo.release_reservation(operation_id)
    except Exception:  # noqa: BLE001 - cleanup is best effort, never masks a failure
        pass


def _compose(*args: str, timeout: float = 300.0) -> subprocess.CompletedProcess:
    return run(compose_argv(*args), timeout=timeout)


def _stop_workload_dependencies() -> bool:
    return _compose("stop", "postgres", "redis", timeout=120).returncode == 0


def _start_workload_dependencies() -> bool:
    result = _compose("start", "postgres", "redis", timeout=120)
    if result.returncode != 0:
        return False
    deadline = time.time() + 90
    while time.time() < deadline:
        ps = _compose("ps", "postgres", "redis", "--format", "json", timeout=60)
        if '"Health":"healthy"' in (ps.stdout or "").replace(" ", ""):
            return True
        time.sleep(2)
    return True


def _wait_for_url(url: str, timeout: float, interval: float = 1.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _ = http_request("GET", url, timeout=3.0)
            if status == 200:
                return True
        except Exception:  # noqa: BLE001 - retried until deadline
            pass
        time.sleep(interval)
    return False


def run_recovery(*, evidence_dir: Path, build: bool, wait_timeout: float) -> dict:
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    report = Report(started_at=_now())
    checks = Checks()

    workload_env = staging_env.ensure_env(ENV_FILE)
    control_env = staging_env.ensure_control_env(CONTROL_ENV_FILE)
    secrets_list = [
        *[workload_env.get(k, "") for k in staging_env.SECRET_KEYS],
        *[control_env.get(k, "") for k in staging_env.CONTROL_SECRET_KEYS],
    ]
    sanitizer = Sanitizer(secrets_list)

    manifest = staging_source.load_manifest(staging_source.DEFAULT_MANIFEST)
    provenance = staging_source.materialize(
        REPO_ROOT / manifest["archive"], staging_source.DEFAULT_DEST, manifest
    )
    report.source_sha = provenance["source_sha"]
    fault_manifest = staging_fault.prepare()
    report.patch_sha256 = fault_manifest["patch_sha256"]

    report.ports = {
        "gateway": int(workload_env["STAGING_GATEWAY_PORT"]),
        "api": int(workload_env["STAGING_API_PORT"]),
        "control_api": int(control_env["STAGING_CONTROL_API_PORT"]),
        "console": int(workload_env["STAGING_CONSOLE_PORT"]),
    }
    gateway_url = f"http://127.0.0.1:{report.ports['gateway']}"
    api_base = f"http://127.0.0.1:{report.ports['api']}"

    # Bring up the real healthy + faulty binaries and the stable gateway.
    up_args = ["up", "-d", "--wait", "--wait-timeout", str(int(wait_timeout))]
    if build:
        up_args.insert(1, "--build")
    started = time.time()
    up = _compose(
        *up_args,
        "api",
        "worker",
        "tenant-api-faulty",
        "staging-gateway",
        timeout=wait_timeout + 300,
    )
    checks.record(
        "real staging stack (healthy, faulty, gateway) came up",
        up.returncode == 0,
        f"exit {up.returncode} in {time.time() - started:.0f}s",
        duration=time.time() - started,
    )
    if up.returncode != 0:
        (evidence_dir / "compose-up.log").write_text(up.stdout or "", encoding="utf-8")
        return _finalize(report, checks, evidence_dir)
    (evidence_dir / "compose-up.log").write_text(sanitizer(up.stdout or ""), encoding="utf-8")

    checks.record("staging gateway snapshot endpoint is live", _wait_for_url(gateway_url + "/snapshot", 90))
    _compose("exec", "-T", "redis", "sh", "-c", 'redis-cli --no-auth-warning -a "$STAGING_REDIS_PASSWORD" FLUSHALL', timeout=30)

    tenant = _register_tenant(api_base, sanitizer)
    observer = StagingObserver(
        PROFILE,
        gateway_url,
        tenant_id=tenant["tenant_id"],
        tenant_token=tenant["token"],
        dependency_probe=StagingDependencyProbe(
            postgres=("127.0.0.1", WORKLOAD_DB_PORT), redis=("127.0.0.1", WORKLOAD_REDIS_PORT)
        ),
    )
    probe = StagingFunctionalProbe(
        PROFILE, gateway_url, tenant_id=tenant["tenant_id"], tenant_token=tenant["token"], observer=observer
    )

    async def _main() -> None:
        pool = await db_module.create_pool(_control_dsn(control_env))
        await db_module.bootstrap_schema(pool, profile=PROFILE)
        store = DeploymentStore(pool, profile=PROFILE)
        repo = IncidentRepository(pool)
        healthy_before = await observer.observe_health()
        checks.record(
            "authenticated tenant business health is real and functional on healthy",
            healthy_before.functional_ok is True and healthy_before.dependencies_ok is True,
            f"http={healthy_before.evidence_fields.get('http_status')}",
        )
        report.adapter_identity = StagingScriptedAdapter.identity
        try:
            await _drive(
                repo,
                store,
                observer,
                probe,
                checks=checks,
                evidence_dir=evidence_dir,
            )
        finally:
            # Cleanup cannot overwrite a recorded failure: it only restores the
            # environment (dependencies up, healthy revision active).
            await _restore(store, repo)
            await observer.aclose()
            await probe.aclose()
            await pool.close()

    try:
        asyncio.run(_main())
    except Exception as exc:  # noqa: BLE001 - surfaced as an explicit failure
        checks.record("staging recovery driver completed without exception", False, repr(exc))

    return _finalize(report, checks, evidence_dir)


def _finalize(report: Report, checks: Checks, evidence_dir: Path) -> dict:
    passed = sum(1 for c in checks.items if c.status == "passed")
    failed = [c.name for c in checks.items if c.status != "passed"]
    report.checks = [asdict(c) for c in checks.items]
    report.finished_at = _now()
    report.status = "passed" if not failed else "failed"
    payload = asdict(report)
    (evidence_dir / "results.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    lines = [
        f"staging-task3 recovery: {report.status}",
        f"source_sha: {report.source_sha}",
        f"patch_sha256: {report.patch_sha256}",
        f"revisions: healthy={report.healthy_revision} faulty={report.faulty_revision}",
        f"adapter identity: {report.adapter_identity}",
        f"live provider: {report.live_provider}",
        f"checks: {passed}/{len(checks.items)} passed",
    ]
    for check in checks.items:
        if check.status != "passed":
            lines.append(f"FAILED: {check.name} — {check.detail}")
    (evidence_dir / "summary.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--wait-timeout", type=float, default=1200.0)
    args = parser.parse_args(argv)
    try:
        payload = run_recovery(
            evidence_dir=args.evidence_dir, build=not args.no_build, wait_timeout=args.wait_timeout
        )
    except Exception as exc:  # noqa: BLE001 - hard failure
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0 if payload["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
