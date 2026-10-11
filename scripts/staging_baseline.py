#!/usr/bin/env python
"""Real authenticated baseline for the isolated staging tenant API.

This driver proves the *real* tenant-api-platform workload runs in the isolated
Compose project and that authenticated tenant-scoped business operations work
against it.  It is the executable evidence behind Task 1, and it never fabricates
a result: every check records the actual command/request and response.

What it does, in order:

1. loads (or generates) the gitignored ``staging/.env`` and materializes the
   pinned source snapshot,
2. validates the Compose configuration without printing secrets,
3. brings the stack up with ``up --build -d --wait`` and waits for readiness,
4. clears the dedicated staging Redis (rate-limit counters only) so the seeded
   tenants are repeatable,
5. registers two synthetic tenants through the real API, performs authenticated
   business writes (idempotent project create), and asserts two-tenant isolation,
6. verifies worker and database readiness, then inspects the actual Docker
   resources (project labels, networks, volumes, published ports) for collisions,
7. writes a machine-readable report and sanitized logs under
   ``.hermes/evidence/staging-task1``.

Required prerequisites fail loudly.  The stack is intentionally left healthy.
"""

from __future__ import annotations

import argparse
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
import staging_source  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
STAGING = REPO_ROOT / "staging"
COMPOSE_FILE = STAGING / "compose.yaml"
ENV_FILE = STAGING / ".env"
PROJECT = "incident-recovery-staging"
DEFAULT_EVIDENCE = REPO_ROOT / ".hermes" / "evidence" / "staging-task1"
DEMO_PROJECT = "incident-recovery"

# Host ports the running demo owns; staging must never choose one.
DEMO_PORTS = {15432, 18080, 18081, 18082, 18083}


@dataclass
class Check:
    name: str
    status: str  # passed | failed | blocked
    detail: str = ""
    command: str | None = None
    exit_code: int | None = None
    duration_seconds: float = 0.0


@dataclass
class Report:
    task: str = "staging-task1"
    status: str = "failed"
    project: str = PROJECT
    source_sha: str = ""
    archive_sha256: str = ""
    image: dict = field(default_factory=dict)
    ports: dict = field(default_factory=dict)
    started_at: str = ""
    finished_at: str = ""
    checks: list = field(default_factory=list)
    resources: dict = field(default_factory=dict)
    failed_checks: list = field(default_factory=list)


class Sanitizer:
    def __init__(self, secrets_: list[str]) -> None:
        self._secrets = sorted({s for s in secrets_ if s and len(s) >= 6}, key=len, reverse=True)

    def __call__(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, "[REDACTED]")
        return text


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve(argv: list[str]) -> list[str]:
    import shutil

    resolved = shutil.which(argv[0]) or argv[0]
    return [resolved, *argv[1:]]


def run(
    argv: list[str],
    *,
    timeout: float,
    sanitizer: Sanitizer | None = None,
    log_path: Path | None = None,
) -> subprocess.CompletedProcess:
    result = subprocess.run(
        _resolve(argv),
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    output = result.stdout or ""
    if sanitizer is not None:
        output = sanitizer(output)
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(output, encoding="utf-8")
    return subprocess.CompletedProcess(result.args, result.returncode, output, "")


def compose_argv(*args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(COMPOSE_FILE),
        "--env-file",
        str(ENV_FILE),
        "-p",
        PROJECT,
        *args,
    ]


def http_request(
    method: str,
    url: str,
    *,
    body: dict | None = None,
    token: str | None = None,
    idempotency_key: str | None = None,
    timeout: float = 15.0,
) -> tuple[int, dict, dict]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    if idempotency_key:
        request.add_header("Idempotency-Key", idempotency_key)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            parsed = json.loads(raw) if raw else {}
            return response.status, dict(response.headers), parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {}
        return exc.code, dict(exc.headers), parsed


def wait_for_url(url: str, timeout: float, interval: float = 1.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _, _ = http_request("GET", url, timeout=3.0)
            if status == 200:
                return True
        except Exception:  # noqa: BLE001 - retried until the deadline
            pass
        time.sleep(interval)
    return False


class Checks:
    def __init__(self) -> None:
        self.items: list[Check] = []

    def record(self, name: str, ok: bool, detail: str = "", **kwargs) -> bool:
        self.items.append(Check(name=name, status="passed" if ok else "failed", detail=detail, **kwargs))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
        return ok


def _parse_json_list(raw: str) -> list[dict]:
    raw = raw.strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        items: list[dict] = []
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return items


def _flush_staging_redis(values: dict, sanitizer: Sanitizer) -> bool:
    script = 'redis-cli --no-auth-warning -a "$STAGING_REDIS_PASSWORD" FLUSHALL'
    result = run(compose_argv("exec", "-T", "redis", "sh", "-c", script), timeout=30, sanitizer=sanitizer)
    return result.returncode == 0 and "OK" in result.stdout


def _inspect_resources(values: dict, sanitizer: Sanitizer) -> dict:
    info: dict = {"containers": [], "volumes": [], "networks": [], "labels": {}}

    ps = run(compose_argv("ps", "-a", "--format", "json"), timeout=60, sanitizer=sanitizer)
    for entry in _parse_json_list(ps.stdout):
        info["containers"].append(
            {
                "service": entry.get("Service"),
                "name": entry.get("Name"),
                "state": entry.get("State"),
                "health": entry.get("Health"),
                "exit_code": entry.get("ExitCode"),
                "publishers": entry.get("Publishers"),
            }
        )

    vol = run(["docker", "volume", "ls", "--filter", f"name={PROJECT}", "--format", "{{.Name}}"], timeout=30)
    info["volumes"] = [line for line in vol.stdout.splitlines() if line.strip()]

    net = run(["docker", "network", "ls", "--filter", f"name={PROJECT}", "--format", "{{.Name}}"], timeout=30)
    info["networks"] = [line for line in net.stdout.splitlines() if line.strip()]

    api_id = run(compose_argv("ps", "-q", "api"), timeout=30, sanitizer=sanitizer).stdout.strip()
    if api_id:
        label = run(
            [
                "docker",
                "inspect",
                "--format",
                '{{ index .Config.Labels "com.docker.compose.project" }}',
                api_id,
            ],
            timeout=30,
        )
        info["labels"]["api_project"] = label.stdout.strip()
        nets = run(
            [
                "docker",
                "inspect",
                "--format",
                "{{ range $k, $v := .NetworkSettings.Networks }}{{$k}}\n{{end}}",
                api_id,
            ],
            timeout=30,
        )
        info["labels"]["api_networks"] = [n for n in nets.stdout.splitlines() if n.strip()]

    image = values.get("STAGING_SOURCE_SHORT_SHA", "a6f715a")
    image_name = f"incident-recovery-staging-tenant-api:{image}"
    image_id = run(["docker", "image", "inspect", "--format", "{{.Id}}", image_name], timeout=30)
    if image_id.returncode == 0:
        info["image"] = {"name": image_name, "id": image_id.stdout.strip()}

    demo = run(
        [
            "docker",
            "ps",
            "--filter",
            f"label=com.docker.compose.project={DEMO_PROJECT}",
            "--format",
            "{{.Names}}",
        ],
        timeout=30,
    )
    info["demo_containers"] = [line for line in demo.stdout.splitlines() if line.strip()]
    return info


def run_baseline(
    *,
    report_path: Path | None = None,
    evidence_dir: Path | None = None,
    build: bool = True,
    wait_timeout: float = 1200.0,
) -> dict:
    evidence_dir = Path(evidence_dir or DEFAULT_EVIDENCE)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    report_path = Path(report_path or (evidence_dir / "results.json"))

    report = Report(started_at=_now())
    checks = Checks()

    # 1. Configuration + pinned source.
    values = staging_env.ensure_env(ENV_FILE)
    secrets_list = [values[k] for k in staging_env.SECRET_KEYS if values.get(k)]
    sanitizer = Sanitizer(secrets_list)

    manifest = staging_source.load_manifest(staging_source.DEFAULT_MANIFEST)
    provenance = staging_source.materialize(
        REPO_ROOT / manifest["archive"],
        staging_source.DEFAULT_DEST,
        manifest,
    )
    report.source_sha = provenance["source_sha"]
    report.archive_sha256 = provenance["archive_sha256"]
    report.ports = {k: int(values[k]) for k in staging_env.PORT_KEYS}
    (evidence_dir / "provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
    )

    api_port = int(values["STAGING_API_PORT"])
    worker_port = int(values["STAGING_WORKER_PORT"])
    api_base = f"http://127.0.0.1:{api_port}"
    worker_base = f"http://127.0.0.1:{worker_port}"

    checks.record(
        "staging ports are clear of the running demo",
        api_port not in DEMO_PORTS and worker_port not in DEMO_PORTS,
        f"api={api_port} worker={worker_port} demo={sorted(DEMO_PORTS)}",
    )

    # 2. Compose configuration (quiet; never prints resolved secrets).
    config = run(
        compose_argv("config", "-q"),
        timeout=120,
        sanitizer=sanitizer,
        log_path=evidence_dir / "compose-config.log",
    )
    checks.record(
        "compose config validates",
        config.returncode == 0,
        f"exit {config.returncode}",
        command="docker compose -f staging/compose.yaml --env-file staging/.env -p incident-recovery-staging config -q",
        exit_code=config.returncode,
    )

    # 3. Bring the stack up.
    up_args = ["up"]
    if build:
        up_args.append("--build")
    up_args += ["-d", "--wait", "--wait-timeout", str(int(wait_timeout))]
    started = time.time()
    up = run(
        compose_argv(*up_args),
        timeout=wait_timeout + 120,
        sanitizer=sanitizer,
        log_path=evidence_dir / "compose-up.log",
    )
    checks.record(
        "stack up --build -d --wait",
        up.returncode == 0,
        f"exit {up.returncode} in {time.time() - started:.0f}s",
        command="docker compose -f staging/compose.yaml --env-file staging/.env -p incident-recovery-staging "
        + " ".join(up_args),
        exit_code=up.returncode,
        duration_seconds=time.time() - started,
    )
    if up.returncode != 0:
        report.checks = [asdict(c) for c in checks.items]
        return _finalize(report, checks, evidence_dir, report_path)

    # 4. Repeatable seeding: clear the isolated staging Redis (rate limits only).
    checks.record(
        "staging redis flushed for repeatable seeding",
        _flush_staging_redis(values, sanitizer),
        "isolated staging Redis; rate-limit counters only",
    )

    # 5. Readiness.
    checks.record("api /readyz reports ready", wait_for_url(api_base + "/readyz", 90))
    checks.record("worker /readyz reports ready", wait_for_url(worker_base + "/readyz", 90))

    worker_metrics = ""
    try:
        with urllib.request.urlopen(worker_base + "/metrics", timeout=10) as resp:
            worker_metrics = resp.read().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - reported as a failed readiness check
        worker_metrics = ""
    checks.record(
        "worker metrics expose outbox depth",
        "webhook_outbox_depth" in worker_metrics,
    )

    # 6. Authenticated tenant business operations.
    run_id = uuid.uuid4().hex[:10]
    password = secrets.token_urlsafe(18)
    tenants: dict[str, dict] = {}
    for label in ("a", "b"):
        email = f"baseline-{run_id}-{label}@staging.test"
        status, _, body = http_request(
            "POST",
            api_base + "/v1/auth/register",
            body={"email": email, "password": password, "tenant_name": f"Baseline {label.upper()}"},
        )
        data = (body or {}).get("data") or {}
        token = data.get("access_token")
        tenant_id = (data.get("tenants") or [{}])[0].get("tenant_id")
        tenants[label] = {"email": email, "token": token, "tenant_id": tenant_id}
        checks.record(
            f"register tenant {label.upper()} returns a session",
            status == 201 and bool(token) and bool(tenant_id),
            f"status {status}",
        )

    for label, tenant in tenants.items():
        status, _, body = http_request("GET", api_base + "/v1/me", token=tenant.get("token"))
        checks.record(
            f"tenant {label.upper()} /v1/me authenticated",
            status == 200 and (body.get("data") or {}).get("auth_method") == "jwt",
            f"status {status}",
        )

    # Idempotent business write in tenant A.
    a, b = tenants["a"], tenants["b"]
    project_payload = {"name": "Baseline project", "description": "staging task1"}
    key = f"baseline-{run_id}"
    status1, headers1, body1 = http_request(
        "POST",
        api_base + f"/v1/tenants/{a['tenant_id']}/projects",
        body=project_payload,
        token=a["token"],
        idempotency_key=key,
    )
    project_id = ((body1 or {}).get("data") or {}).get("id")
    checks.record(
        "tenant A creates a project (201)",
        status1 == 201 and bool(project_id),
        f"status {status1}",
    )

    status2, _, body2 = http_request(
        "POST",
        api_base + f"/v1/tenants/{a['tenant_id']}/projects",
        body=project_payload,
        token=a["token"],
        idempotency_key=key,
    )
    replayed_id = ((body2 or {}).get("data") or {}).get("id")
    checks.record(
        "project create is idempotent on retry",
        status2 == 201 and replayed_id == project_id,
        f"status {status2}",
    )

    _, _, list_a = http_request(
        "GET", api_base + f"/v1/tenants/{a['tenant_id']}/projects", token=a["token"]
    )
    a_ids = [p.get("id") for p in (list_a.get("data") or [])]
    checks.record(
        "exactly one project exists after the retry",
        a_ids.count(project_id) == 1,
        f"{len(a_ids)} project(s)",
    )

    # Two-tenant isolation.
    cross_status, _, _ = http_request(
        "GET", api_base + f"/v1/tenants/{b['tenant_id']}/projects", token=a["token"]
    )
    checks.record(
        "tenant A cannot read tenant B's tenant scope (404, never 403)",
        cross_status == 404,
        f"status {cross_status}",
    )

    _, _, list_b_before = http_request(
        "GET", api_base + f"/v1/tenants/{b['tenant_id']}/projects", token=b["token"]
    )
    b_ids_before = [p.get("id") for p in (list_b_before.get("data") or [])]
    checks.record(
        "tenant B does not observe tenant A's project",
        project_id not in b_ids_before,
        f"{len(b_ids_before)} project(s) in B",
    )

    status_b, _, body_b = http_request(
        "POST",
        api_base + f"/v1/tenants/{b['tenant_id']}/projects",
        body={"name": "B project", "description": "staging task1"},
        token=b["token"],
        idempotency_key=f"baseline-{run_id}-b",
    )
    b_project_id = ((body_b or {}).get("data") or {}).get("id")
    checks.record("tenant B creates its own project (201)", status_b == 201 and bool(b_project_id), f"status {status_b}")

    _, _, list_a_after = http_request(
        "GET", api_base + f"/v1/tenants/{a['tenant_id']}/projects", token=a["token"]
    )
    a_ids_after = [p.get("id") for p in (list_a_after.get("data") or [])]
    checks.record(
        "tenant A does not observe tenant B's project",
        b_project_id not in a_ids_after,
        f"{len(a_ids_after)} project(s) in A",
    )

    # 7. Actual Docker resource isolation.
    resources = _inspect_resources(values, sanitizer)
    report.resources = resources
    report.image = resources.get("image", {})
    (evidence_dir / "resource-inspection.log").write_text(
        json.dumps(resources, indent=2) + "\n", encoding="utf-8"
    )

    services = {c.get("service") for c in resources["containers"]}
    states = {c.get("service"): (c.get("state"), c.get("health"), c.get("exit_code")) for c in resources["containers"]}
    checks.record(
        "all staging services present",
        {"postgres", "redis", "migrate", "app-role-provision", "api", "worker"} <= services,
        f"services={sorted(filter(None, services))}",
    )
    checks.record(
        "one-shot migrate/provision completed successfully",
        states.get("migrate", ("", "", 1))[2] == 0 and states.get("app-role-provision", ("", "", 1))[2] == 0,
        f"migrate={states.get('migrate')} provision={states.get('app-role-provision')}",
    )
    checks.record(
        "api and worker running and healthy",
        states.get("api", ("", "", None))[0] == "running" and states.get("worker", ("", "", None))[0] == "running",
        f"api={states.get('api')} worker={states.get('worker')}",
    )
    checks.record(
        "container project label is the staging project",
        resources["labels"].get("api_project") == PROJECT,
        resources["labels"].get("api_project", ""),
    )
    checks.record(
        "staging volumes are project-scoped",
        bool(resources["volumes"]) and all(v.startswith(PROJECT) for v in resources["volumes"]),
        ",".join(resources["volumes"]),
    )
    checks.record(
        "staging networks are project-scoped",
        bool(resources["networks"]) and all(n.startswith(PROJECT) for n in resources["networks"]),
        ",".join(resources["networks"]),
    )
    checks.record(
        "existing incident-recovery demo containers still present",
        bool(resources.get("demo_containers")),
        f"{len(resources.get('demo_containers', []))} demo container(s)",
    )

    report.checks = [asdict(c) for c in checks.items]
    return _finalize(report, checks, evidence_dir, report_path)


def _finalize(report: Report, checks: Checks, evidence_dir: Path, report_path: Path) -> dict:
    report.finished_at = _now()
    report.failed_checks = [c.name for c in checks.items if c.status != "passed"]
    report.status = "passed" if not report.failed_checks else "failed"
    payload = asdict(report)
    report_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    lines = [
        f"staging-task1 baseline: {report.status}",
        f"source_sha: {report.source_sha}",
        f"archive_sha256: {report.archive_sha256}",
        f"image: {report.image}",
        f"ports: {report.ports}",
        f"checks: {sum(1 for c in checks.items if c.status == 'passed')}/{len(checks.items)} passed",
    ]
    for check in checks.items:
        if check.status != "passed":
            lines.append(f"FAILED: {check.name} — {check.detail}")
    (evidence_dir / "baseline-summary.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--evidence-dir", type=Path, default=None)
    parser.add_argument("--no-build", action="store_true", help="skip --build on up")
    parser.add_argument("--wait-timeout", type=float, default=1200.0)
    args = parser.parse_args(argv)

    try:
        payload = run_baseline(
            report_path=args.report,
            evidence_dir=args.evidence_dir,
            build=not args.no_build,
            wait_timeout=args.wait_timeout,
        )
    except Exception as exc:  # noqa: BLE001 - surfaced as a hard failure
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0 if payload["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
