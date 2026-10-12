"""Staging env/port unit tests plus a gated real-container baseline test.

The pure tests always run.  The real test drives ``scripts/staging_baseline.py``
against the actual Docker engine and is gated behind ``STAGING_E2E=1`` so the
default test suite never silently requires a Docker daemon; it is an explicit
opt-in, and the required prerequisite (Docker) fails loudly rather than being
skipped by the driver itself.
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

import staging_baseline
import staging_env


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_probe_reports_a_free_port() -> None:
    port = staging_env.allocate_loopback_port(49152)
    assert staging_env.probe_loopback_port(port) is True


def test_allocate_skips_taken_and_out_of_range() -> None:
    held = socket.socket()
    held.bind(("127.0.0.1", 0))
    held.listen(1)
    busy = held.getsockname()[1]
    try:
        chosen = staging_env.allocate_loopback_port(busy, taken={busy})
        assert chosen != busy
        assert 1 <= chosen <= 65535
        assert staging_env.probe_loopback_port(chosen) is True
    finally:
        held.close()


def test_generate_values_are_valid_and_distinct() -> None:
    values = staging_env.generate_values()
    assert staging_env.validate_env_values(values) == []
    # Distinct from upstream development credentials.
    assert values["STAGING_OWNER_PASSWORD"] not in ("postgres", "app_rw")
    assert values["STAGING_APP_PASSWORD"] not in ("postgres", "app_rw")
    assert values["STAGING_DB"] != "tenant_platform"
    assert len(values["STAGING_JWT_SECRET"]) >= 32


def test_validate_rejects_missing_and_placeholder_values() -> None:
    assert staging_env.validate_env_values({})
    values = staging_env.generate_values()
    values["STAGING_OWNER_PASSWORD"] = "replace-with-generated-owner-password"
    assert any("STAGING_OWNER_PASSWORD" in p for p in staging_env.validate_env_values(values))


def test_validate_rejects_upstream_dev_secrets() -> None:
    values = staging_env.generate_values()
    values["STAGING_APP_PASSWORD"] = "app_rw"
    problems = staging_env.validate_env_values(values)
    assert any("STAGING_APP_PASSWORD" in p for p in problems)


def test_env_file_round_trip(tmp_path: Path) -> None:
    values = staging_env.generate_values()
    path = tmp_path / ".env"
    staging_env.write_env(path, values)
    assert staging_env.load_env_file(path) == values


def test_gateway_port_preference_is_probed() -> None:
    # The brief names 18090 as the preferred loopback.  Allocation must return a
    # usable port and never exceed the 16-bit range.
    chosen = staging_env.allocate_loopback_port(18090)
    assert 18090 <= chosen <= 65535


def test_container_id_extraction_ignores_compose_warnings() -> None:
    container_id = "eacbf87d779a1e0702d6cc7924677abe323a7b889d55bd852a5b36060c05c809"
    noisy = (
        'time="2026-10-12T05:02:00+05:30" level=warning '
        'msg="The \\"STAGING_CONTROL_DB_USER\\" variable is not set. Defaulting to a blank string."\n'
        f"{container_id}\n"
    )
    assert staging_baseline._container_id(noisy) == container_id
    assert staging_baseline._container_id("warning only\n") == ""


def test_compose_argv_supplies_the_control_env_when_present() -> None:
    argv = staging_baseline.compose_argv("config", "-q")
    assert "--env-file" in argv
    assert str(staging_baseline.ENV_FILE) in argv
    # The recovery-profile services interpolate STAGING_CONTROL_* variables, so the
    # control env must be supplied (when present) to keep the default stack quiet.
    if staging_baseline.CONTROL_ENV_FILE.exists():
        assert str(staging_baseline.CONTROL_ENV_FILE) in argv


def test_real_staging_baseline(tmp_path: Path) -> None:
    if os.environ.get("STAGING_E2E") != "1":
        pytest.skip("set STAGING_E2E=1 to run the real Docker staging baseline")
    evidence_dir = Path(os.environ.get("STAGING_EVIDENCE_DIR") or tmp_path)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    report_path = evidence_dir / "staging-baseline.json"
    report = staging_baseline.run_baseline(report_path=report_path, evidence_dir=evidence_dir)
    assert report_path.exists()
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["status"] == "passed", json.dumps(payload.get("failed_checks", []))
    assert report["status"] == "passed"
