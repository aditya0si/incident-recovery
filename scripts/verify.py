#!/usr/bin/env python
"""Reproducible whole-stack verification driver (Milestone 6).

This driver runs the real gates for the incident-recovery demo and writes a
machine-readable report plus durable, sanitized logs.  It never fabricates a
result: every status comes from an actually executed command's exit code and
captured output.

Checks are classified as:

* ``required`` - a failure or an unmet prerequisite fails the whole run
  (the process exits non-zero),
* ``optional`` - an explicitly optional check (the live-model investigation);
  an unconfigured live model is reported as ``blocked`` and never as a success.

Usage::

    uv run python scripts/verify.py --docker --ui          # full local gate
    uv run python scripts/verify.py                       # host-only checks
    uv run python scripts/verify.py --docker --live       # add live model check

Docker checks deliberately apply the test-only control override and the explicit
scripted-investigation override, then restore the default stack in a ``finally``
block even if a check fails.  No secrets are printed: command output is sanitized
against the values in the gitignored ``.env`` before it is logged, and Compose
configuration is only ever validated with ``config -q``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT = "incident-recovery"
COMPOSE_DEFAULT = ["-f", "compose.yaml"]
COMPOSE_OVERRIDES = ["-f", "compose.yaml", "-f", "compose.test.yaml", "-f", "compose.investigation.yaml"]
REPORT_DIR = REPO_ROOT / ".hermes" / "evidence" / "verify"
LOG_DIR = REPORT_DIR / "logs"

_SECRET_ENV_KEYS = (
    "INTERNAL_TOKEN",
    "OPERATOR_TOKEN",
    "POSTGRES_PASSWORD",
    "MODEL_API_KEY",
)

_HIGH_RISK_PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
)


@dataclass
class Result:
    returncode: int
    output: str
    duration: float
    timed_out: bool


@dataclass
class Check:
    name: str
    category: str
    status: str
    command: Optional[str] = None
    exit_code: Optional[int] = None
    duration_seconds: float = 0.0
    detail: str = ""
    adapter: Optional[str] = None
    counts: dict = field(default_factory=dict)
    log: Optional[str] = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


class Sanitizer:
    """Replaces known secret values with ``[REDACTED]`` before anything is logged."""

    def __init__(self, secrets: list[str]) -> None:
        self._secrets = sorted({s for s in secrets if s and len(s) >= 4}, key=len, reverse=True)

    def __call__(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, "[REDACTED]")
        return text


def _kill_tree(proc: subprocess.Popen) -> None:
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            capture_output=True,
            check=False,
        )
    else:  # pragma: no cover - POSIX path
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


def _resolve_argv(argv: list[str]) -> list[str]:
    """Resolve the executable and make Windows ``.cmd`` shims runnable.

    ``npm`` (and other tools) are ``.cmd`` shims on Windows which cannot be
    launched directly by ``CreateProcess``; they are invoked through ``cmd.exe /c``
    with an explicit argument array.  No shell string is ever built, so a failure
    cannot be masked by a pipeline.
    """

    resolved = shutil.which(argv[0]) or argv[0]
    if os.name == "nt" and resolved.lower().endswith((".cmd", ".bat")):
        return ["cmd.exe", "/c", resolved, *argv[1:]]
    return [resolved, *argv[1:]]


def run(
    argv: list[str],
    *,
    timeout: float,
    env: Optional[dict[str, str]] = None,
    sanitizer: Optional[Sanitizer] = None,
    log_name: Optional[str] = None,
) -> Result:
    """Run ``argv`` as an argument array with an explicit cwd and owned cleanup.

    No shell is used, so a failure can never be masked by a pipeline.  On timeout
    the whole child process tree is terminated.
    """

    started = time.time()
    resolved = _resolve_argv(argv)
    kwargs: dict = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:  # pragma: no cover - POSIX path
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(
        resolved,
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        **kwargs,
    )
    timed_out = False
    try:
        output, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        output, _ = proc.communicate()
    duration = time.time() - started
    clean = sanitizer(output or "") if sanitizer else (output or "")
    if log_name:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        (LOG_DIR / f"{log_name}.log").write_text(clean, encoding="utf-8")
    return Result(
        returncode=proc.returncode if proc.returncode is not None else -1,
        output=clean,
        duration=duration,
        timed_out=timed_out,
    )


def _command_string(argv: list[str]) -> str:
    return " ".join(argv)


def _pytest_counts(output: str) -> dict:
    counts: dict[str, int] = {}
    for label in (
        "passed",
        "failed",
        "error",
        "errors",
        "skipped",
        "deselected",
        "xfailed",
        "xpassed",
    ):
        match = re.search(rf"(\d+) {label}\b", output)
        if match:
            counts[label.rstrip("s") if label == "errors" else label] = int(match.group(1))
    if re.search(r"no tests ran", output, re.IGNORECASE):
        counts["no_tests_ran"] = 1
    return counts


def _pytest_gate(counts: dict) -> tuple[bool, str]:
    """Decide whether a pytest run actually executed passing tests.

    A zero-test run, a skipped-only run, a run with deselected/unexecuted tests, a
    collection error, or any failing test can never be reported as success.
    Required suites must execute at least one passing test and leave nothing
    skipped, deselected, or errored; a suite that did not run is a failure, not a
    pass.
    """

    passed = counts.get("passed", 0)
    failed = counts.get("failed", 0)
    errors = counts.get("error", 0)
    skipped = counts.get("skipped", 0)
    deselected = counts.get("deselected", 0)
    if failed or errors:
        return False, f"{failed + errors} failing/error test(s)"
    if skipped:
        return False, f"{skipped} skipped test(s)"
    if deselected:
        return False, f"{deselected} deselected/unexecuted test(s)"
    if counts.get("no_tests_ran") or passed == 0:
        return False, "no tests executed"
    return True, f"{passed} passed"


def _vitest_counts(output: str) -> dict:
    """Parse the vitest ``Tests`` summary line (not the ``Test Files`` line)."""

    counts: dict[str, int] = {}
    summary = re.search(r"^\s*Tests\s+(.+)$", output, re.MULTILINE)
    if summary is None:
        return counts
    line = summary.group(1)
    for label in ("passed", "failed", "skipped", "todo"):
        match = re.search(rf"(\d+)\s+{label}\b", line)
        if match:
            counts[label] = int(match.group(1))
    total = re.search(r"\((\d+)\)\s*$", line)
    if total:
        counts["total"] = int(total.group(1))
    return counts


def _test_gate(counts: dict) -> tuple[bool, str]:
    """Decide whether a JS/TS test run actually executed passing tests.

    Mirrors :func:`_pytest_gate`: zero tests, skips, todo/unexecuted tests, a
    total-count mismatch, or failures cannot pass.
    """

    passed = counts.get("passed", 0)
    failed = counts.get("failed", 0)
    skipped = counts.get("skipped", 0)
    todo = counts.get("todo", 0)
    if failed:
        return False, f"{failed} failing test(s)"
    if skipped:
        return False, f"{skipped} skipped test(s)"
    if todo:
        return False, f"{todo} todo/unexecuted test(s)"
    total = counts.get("total")
    if total is not None and passed + failed + skipped + todo < total:
        unexecuted = total - (passed + failed + skipped + todo)
        return False, f"{unexecuted} unexecuted test(s) of {total}"
    if passed == 0:
        return False, "no tests executed"
    return True, f"{passed} passed"


class Verifier:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.env_file = load_env_file(REPO_ROOT / ".env")
        secrets = [self.env_file.get(key, "") for key in _SECRET_ENV_KEYS]
        self.sanitizer = Sanitizer(secrets)
        self.env = dict(os.environ)
        for key, value in self.env_file.items():
            self.env.setdefault(key, value)
        self.checks: list[Check] = []

    # --- helpers ----------------------------------------------------------

    def record(self, check: Check) -> Check:
        self.checks.append(check)
        marker = {"passed": "PASS", "failed": "FAIL", "blocked": "BLOCK"}[check.status]
        print(f"[{marker}] {check.name}: {check.detail}".rstrip())
        return check

    def _run_check(
        self,
        name: str,
        argv: list[str],
        *,
        timeout: float,
        category: str = "required",
        expect_zero: bool = True,
        parse=None,
        adapter: Optional[str] = None,
        detail_ok: str = "ok",
        env: Optional[dict[str, str]] = None,
    ) -> Check:
        result = run(
            argv,
            timeout=timeout,
            env=env or self.env,
            sanitizer=self.sanitizer,
            log_name=name,
        )
        counts = parse(result.output) if parse else {}
        if result.timed_out:
            status, detail = "failed", f"timed out after {timeout:.0f}s"
        elif expect_zero and result.returncode != 0:
            status, detail = "failed", f"exit {result.returncode}"
        elif not expect_zero and result.returncode == 0:
            status, detail = "failed", "expected a non-zero exit"
        else:
            status, detail = "passed", detail_ok
        # A required test suite must have actually executed passing tests: an
        # empty, skipped-only, or collection-error run cannot pass silently.
        if category == "required" and parse in (_pytest_counts, _vitest_counts):
            gate = _pytest_gate if parse is _pytest_counts else _test_gate
            gate_ok, gate_detail = gate(counts)
            if status == "passed" and not gate_ok:
                status, detail = "failed", gate_detail
            elif status == "passed":
                detail = gate_detail
        return self.record(
            Check(
                name=name,
                category=category,
                status=status,
                command=_command_string(argv),
                exit_code=result.returncode,
                duration_seconds=round(result.duration, 3),
                detail=detail,
                adapter=adapter,
                counts=counts,
                log=str(LOG_DIR / f"{name}.log"),
            )
        )

    def _blocked(self, name: str, detail: str, *, category: str = "required", adapter=None) -> Check:
        return self.record(
            Check(name=name, category=category, status="blocked", detail=detail, adapter=adapter)
        )

    # --- checks -----------------------------------------------------------

    def source_metadata(self) -> dict:
        sha = run(["git", "rev-parse", "HEAD"], timeout=30, env=self.env).output.strip()
        branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], timeout=30, env=self.env).output.strip()
        status = run(["git", "status", "--porcelain"], timeout=30, env=self.env).output.strip()
        return {"sha": sha, "branch": branch, "dirty": bool(status)}

    def environment_metadata(self) -> dict:
        def first_line(argv: list[str]) -> str:
            result = run(argv, timeout=60, env=self.env)
            return (result.output.strip().splitlines() or ["unavailable"])[0]

        return {
            "python": sys.version.split()[0],
            "docker": first_line(["docker", "version", "--format", "{{.Server.Version}}"]),
            "compose": first_line(["docker", "compose", "version"]),
            "node": first_line(["node", "--version"]),
            "npm": first_line(["npm", "--version"]),
        }

    def preflight(self) -> None:
        required_keys = ("POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB", "INTERNAL_TOKEN", "OPERATOR_TOKEN")
        missing = [key for key in required_keys if not self.env_file.get(key)]
        placeholders = [
            key
            for key in ("POSTGRES_PASSWORD", "INTERNAL_TOKEN", "OPERATOR_TOKEN")
            if self.env_file.get(key, "").startswith("replace-with")
        ]
        if missing:
            self._blocked("env_configuration", f"missing .env keys: {', '.join(missing)}")
        elif placeholders:
            self._blocked("env_configuration", f"placeholder .env values: {', '.join(placeholders)}")
        else:
            self.record(Check(name="env_configuration", category="required", status="passed", detail=".env present with distinct required values"))

        ignored = run(
            ["git", "check-ignore", ".env", "frontend/dist", "frontend/node_modules", ".hermes"],
            timeout=30,
            env=self.env,
        )
        covered = {line.strip() for line in ignored.output.splitlines()}
        expected = {".env", "frontend/dist", "frontend/node_modules", ".hermes"}
        if expected <= covered:
            self.record(Check(name="gitignore_artifacts", category="required", status="passed", detail="env and build artifacts are ignored"))
        else:
            self._blocked(
                "gitignore_artifacts",
                f"not ignored: {', '.join(sorted(expected - covered))}",
            )

    def credential_scan(self) -> None:
        listing = run(["git", "ls-files"], timeout=60, env=self.env)
        tracked = [line.strip() for line in listing.output.splitlines() if line.strip()]
        findings: list[str] = []
        secret_values = {
            key: value
            for key, value in self.env_file.items()
            if key in _SECRET_ENV_KEYS and len(value) >= 8 and not value.startswith("replace-with")
        }
        for relative in tracked:
            path = REPO_ROOT / relative
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for label, pattern in _HIGH_RISK_PATTERNS:
                if pattern.search(text):
                    findings.append(f"{relative}:{label}")
            for key, value in secret_values.items():
                if value in text:
                    findings.append(f"{relative}:{key}_value")
        if findings:
            self._blocked(
                "tracked_secret_scan",
                f"potential credential material in {len(findings)} tracked location(s): "
                + ", ".join(findings[:10]),
            )
        else:
            self.record(
                Check(
                    name="tracked_secret_scan",
                    category="required",
                    status="passed",
                    detail=f"no secret material across {len(tracked)} tracked files",
                )
            )

    def host_checks(self) -> None:
        self._run_check(
            "backend_unit",
            ["uv", "run", "pytest", "tests/unit", "-q"],
            timeout=1200,
            parse=_pytest_counts,
        )
        self._run_check(
            "frontend_install",
            ["npm", "--prefix", "frontend", "ci"],
            timeout=1800,
            detail_ok="npm ci completed",
        )
        self._run_check(
            "frontend_unit",
            ["npm", "--prefix", "frontend", "test", "--", "--run"],
            timeout=900,
            parse=_vitest_counts,
        )
        self._run_check(
            "frontend_build",
            ["npm", "--prefix", "frontend", "run", "build"],
            timeout=900,
            detail_ok="typecheck + production build",
        )
        self._run_check(
            "frontend_audit",
            ["npm", "--prefix", "frontend", "audit", "--audit-level=high"],
            timeout=600,
            detail_ok="no high/critical advisories",
        )

    def docker_checks(self) -> None:
        self._run_check(
            "compose_config_default",
            ["docker", "compose", "-p", PROJECT, *COMPOSE_DEFAULT, "config", "-q"],
            timeout=120,
            detail_ok="default compose config valid",
        )
        self._run_check(
            "compose_config_overrides",
            ["docker", "compose", "-p", PROJECT, *COMPOSE_OVERRIDES, "config", "-q"],
            timeout=120,
            detail_ok="test/investigation override config valid",
        )
        self._run_check(
            "compose_up_default",
            ["docker", "compose", "-p", PROJECT, *COMPOSE_DEFAULT, "up", "--build", "-d", "--wait"],
            timeout=1800,
            detail_ok="default stack healthy",
        )
        self._run_check(
            "backend_integration",
            ["uv", "run", "pytest", "tests/integration", "-q"],
            timeout=1800,
            parse=_pytest_counts,
        )

        up_ok = self._run_check(
            "compose_up_overrides",
            ["docker", "compose", "-p", PROJECT, *COMPOSE_OVERRIDES, "up", "--build", "-d", "--wait"],
            timeout=1800,
            detail_ok="override stack healthy (control port + scripted adapter)",
        )
        try:
            if up_ok.status == "passed":
                for name, path in (
                    ("e2e_deployment", "tests/e2e/test_deployment.py"),
                    ("e2e_recovery", "tests/e2e/test_recovery.py"),
                    ("e2e_investigation", "tests/e2e/test_investigation.py"),
                    ("e2e_resilience", "tests/e2e/test_resilience.py"),
                ):
                    self._run_check(
                        name,
                        ["uv", "run", "pytest", path, "-q"],
                        timeout=1800,
                        parse=_pytest_counts,
                        adapter="scripted:demo",
                    )
                if self.args.ui:
                    self._run_check(
                        "e2e_console",
                        ["uv", "run", "pytest", "tests/e2e/test_console.py", "-q"],
                        timeout=1800,
                        parse=_pytest_counts,
                        adapter="scripted:demo",
                    )
            else:
                for name in ("e2e_deployment", "e2e_recovery", "e2e_investigation", "e2e_resilience"):
                    self._blocked(name, "override stack did not become healthy", adapter="scripted:demo")
                if self.args.ui:
                    self._blocked("e2e_console", "override stack did not become healthy", adapter="scripted:demo")
        finally:
            # Restore the default stack (no host control port, no scripted adapter)
            # even if an E2E check failed.
            self._run_check(
                "compose_restore_default",
                ["docker", "compose", "-p", PROJECT, *COMPOSE_DEFAULT, "up", "--build", "-d", "--wait"],
                timeout=1800,
                detail_ok="default stack restored",
            )

    def live_check(self) -> dict:
        configured = all(
            self.env.get(key, "").strip() for key in ("MODEL_BASE_URL", "MODEL_NAME", "MODEL_API_KEY")
        )
        if not self.args.live:
            return {"configured": configured, "status": "not_requested", "reason": "--live not passed"}
        if not configured:
            self._blocked(
                "live_model_investigation",
                "live model unconfigured (MODEL_BASE_URL/MODEL_NAME/MODEL_API_KEY absent); "
                "reported blocked, never as success",
                category="optional",
                adapter="missing-credentials",
            )
            return {"configured": False, "status": "blocked", "reason": "live_model_unconfigured"}
        live_env = dict(self.env)
        live_env["RUN_LIVE_MODEL"] = "1"
        check = self._run_check(
            "live_model_investigation",
            ["uv", "run", "pytest", "tests/live/test_live_model.py", "-q"],
            timeout=1800,
            category="optional",
            parse=_pytest_counts,
            adapter=f"openai-compatible:{self.env.get('MODEL_NAME', '').strip()}",
            env=live_env,
        )
        return {
            "configured": True,
            "status": check.status,
            "reason": "real provider call + incident E2E" if check.status == "passed" else check.detail,
        }

    # --- orchestration ----------------------------------------------------

    def run_all(self) -> int:
        started = _now()
        self.preflight()
        self.host_checks()
        if self.args.docker:
            self.docker_checks()
        else:
            self._blocked("compose_up_default", "not requested (pass --docker)", category="optional")
            self._blocked("backend_integration", "requires the PostgreSQL stack (pass --docker)", category="optional")
        self.credential_scan()
        live = self.live_check()
        finished = _now()

        totals = {"passed": 0, "failed": 0, "blocked": 0}
        for check in self.checks:
            totals[check.status] = totals.get(check.status, 0) + 1
        required_failures = [
            check.name
            for check in self.checks
            if check.category == "required" and check.status != "passed"
        ]
        report = {
            "schema": "incident-recovery/verify-report/v1",
            "source": self.source_metadata(),
            "environment": self.environment_metadata(),
            "options": {"docker": self.args.docker, "ui": self.args.ui, "live": self.args.live},
            "started_at": started,
            "finished_at": finished,
            "checks": [asdict(check) for check in self.checks],
            "totals": totals,
            "required_failures": required_failures,
            "required_ok": not required_failures,
            "live": live,
        }
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        report_path = REPORT_DIR / "report.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print("\n=== verification summary ===")
        print(f"source: {report['source']['sha']} ({report['source']['branch']})")
        print(f"passed={totals['passed']} failed={totals['failed']} blocked={totals['blocked']}")
        if required_failures:
            print(f"required failures/blockers: {', '.join(required_failures)}")
        print(f"live: {live['status']} ({live['reason']})")
        print(f"report: {report_path}")
        return 0 if report["required_ok"] else 1


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reproducible whole-stack verification driver")
    parser.add_argument("--docker", action="store_true", help="run Docker/Compose and E2E checks")
    parser.add_argument("--ui", action="store_true", help="run the real-browser console E2E (implies --docker)")
    parser.add_argument("--live", action="store_true", help="run the optional live-model investigation check")
    args = parser.parse_args(argv)
    if args.ui:
        args.docker = True
    return args


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    return Verifier(args).run_all()


if __name__ == "__main__":
    raise SystemExit(main())
