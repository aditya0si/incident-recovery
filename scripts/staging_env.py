#!/usr/bin/env python
"""Generate and validate the gitignored staging runtime configuration.

Staging runs on its own Compose project with its own PostgreSQL, Redis and
credentials.  Every secret is freshly generated with :mod:`secrets`; nothing is
inherited from the upstream development defaults (``postgres``/``app_rw``) or
from the running demo.  Host ports for the services that are published are
probed on loopback before they are written, preferring the reviewed defaults
(18090 gateway, 18091 worker metrics, 18092 API, 18093 console) and falling
back to the next free port on conflict.

The file is written to ``staging/.env`` which is gitignored.  Values are never
printed.
"""

from __future__ import annotations

import argparse
import secrets
import socket
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV = REPO_ROOT / "staging" / ".env"
CONTROL_ENV = REPO_ROOT / "staging" / ".control.env"
EXAMPLE = REPO_ROOT / "staging" / ".env.example"

PINNED_SHORT_SHA = "a6f715a"

# --- Task 3: isolated recovery control-plane configuration -------------------
#
# These values live in their own gitignored file so the Task 1 workload
# credentials are never regenerated or disturbed.  The control plane runs on its
# own PostgreSQL server (control-postgres) so workload dependency outages do not
# take the incident store with them.

CONTROL_KEYS = (
    "STAGING_CONTROL_DB_USER",
    "STAGING_CONTROL_DB",
    "STAGING_CONTROL_DB_PASSWORD",
    "STAGING_OPERATOR_TOKEN",
    "STAGING_INTERNAL_TOKEN",
    "STAGING_CONTROL_DB_PORT",
    "STAGING_CONTROL_API_PORT",
)

CONTROL_SECRET_KEYS = (
    "STAGING_CONTROL_DB_PASSWORD",
    "STAGING_OPERATOR_TOKEN",
    "STAGING_INTERNAL_TOKEN",
)

CONTROL_PORT_KEYS = (
    "STAGING_CONTROL_DB_PORT",
    "STAGING_CONTROL_API_PORT",
)

PREFERRED_CONTROL_PORTS = {
    "STAGING_CONTROL_DB_PORT": 18094,
    "STAGING_CONTROL_API_PORT": 18095,
}

REQUIRED_KEYS = (
    "STAGING_OWNER_USER",
    "STAGING_OWNER_PASSWORD",
    "STAGING_DB",
    "STAGING_APP_USER",
    "STAGING_APP_PASSWORD",
    "STAGING_REDIS_PASSWORD",
    "STAGING_JWT_SECRET",
    "STAGING_SOURCE_SHORT_SHA",
    "STAGING_API_PORT",
    "STAGING_WORKER_PORT",
    "STAGING_GATEWAY_PORT",
    "STAGING_CONSOLE_PORT",
)

SECRET_KEYS = (
    "STAGING_OWNER_PASSWORD",
    "STAGING_APP_PASSWORD",
    "STAGING_REDIS_PASSWORD",
    "STAGING_JWT_SECRET",
)

PORT_KEYS = (
    "STAGING_GATEWAY_PORT",
    "STAGING_WORKER_PORT",
    "STAGING_API_PORT",
    "STAGING_CONSOLE_PORT",
)

# Preferred loopback ports, in probe order. 18090 is the reviewed preferred
# port and is probed first, as the brief requires.
PREFERRED_PORTS = {
    "STAGING_GATEWAY_PORT": 18090,
    "STAGING_WORKER_PORT": 18091,
    "STAGING_API_PORT": 18092,
    "STAGING_CONSOLE_PORT": 18093,
}

PLACEHOLDER_PREFIX = "replace-with"
FORBIDDEN_SECRETS = {"postgres", "app_rw", "password", "changeme", ""}


def probe_loopback_port(port: int) -> bool:
    """True when ``127.0.0.1:port`` can be bound right now."""

    if not 1 <= port <= 65535:
        return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def allocate_loopback_port(preferred: int, taken: set[int] | None = None) -> int:
    taken = taken or set()
    for candidate in range(preferred, min(preferred + 200, 65535) + 1):
        if candidate in taken:
            continue
        if probe_loopback_port(candidate):
            return candidate
    raise RuntimeError(f"no free loopback port found near {preferred}")


def generate_values(probe: bool = True, taken: set[int] | None = None) -> dict[str, str]:
    values: dict[str, str] = {
        "STAGING_OWNER_USER": "staging_owner",
        "STAGING_OWNER_PASSWORD": secrets.token_hex(24),
        "STAGING_DB": "tenant_platform_staging",
        "STAGING_APP_USER": "app_rw",
        "STAGING_APP_PASSWORD": secrets.token_hex(24),
        "STAGING_REDIS_PASSWORD": secrets.token_hex(24),
        "STAGING_JWT_SECRET": secrets.token_hex(48),
        "STAGING_SOURCE_SHORT_SHA": PINNED_SHORT_SHA,
    }
    used = set(taken or set())
    for key in PORT_KEYS:
        preferred = PREFERRED_PORTS[key]
        chosen = allocate_loopback_port(preferred, used) if probe else preferred
        values[key] = str(chosen)
        used.add(chosen)
    return values


def validate_env_values(values: dict[str, str]) -> list[str]:
    problems: list[str] = []
    for key in REQUIRED_KEYS:
        raw = (values.get(key) or "").strip()
        if not raw:
            problems.append(f"{key} is missing or empty")
            continue
        if raw.lower().startswith(PLACEHOLDER_PREFIX):
            problems.append(f"{key} is still a placeholder")
    for key in SECRET_KEYS:
        raw = (values.get(key) or "").strip()
        if raw in FORBIDDEN_SECRETS or raw.lower() in FORBIDDEN_SECRETS:
            problems.append(f"{key} is an upstream development credential")
    if (values.get("STAGING_DB") or "").strip() == "tenant_platform":
        problems.append("STAGING_DB must not reuse the upstream database name")
    if len((values.get("STAGING_JWT_SECRET") or "").strip()) < 32:
        problems.append("STAGING_JWT_SECRET must be at least 32 characters")
    for key in PORT_KEYS:
        raw = (values.get(key) or "").strip()
        if not raw.isdigit() or not 1 <= int(raw) <= 65535:
            problems.append(f"{key} must be a TCP port between 1 and 65535")
    return problems


def load_env_file(path: Path) -> dict[str, str]:
    path = Path(path)
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


def write_env(path: Path, values: dict[str, str]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Generated staging runtime configuration. GITIGNORED. Never commit.",
        "# Produced by scripts/staging_env.py; distinct from upstream dev creds.",
    ]
    for key in REQUIRED_KEYS:
        lines.append(f"{key}={values[key]}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def ensure_env(path: Path = DEFAULT_ENV, *, force: bool = False, probe: bool = True) -> dict[str, str]:
    """Return validated staging config, generating it when absent or forced."""

    existing = load_env_file(path)
    if existing and not force:
        problems = validate_env_values(existing)
        if problems:
            raise RuntimeError(
                f"{path} is present but invalid: " + "; ".join(problems)
            )
        return existing
    values = generate_values(probe=probe)
    problems = validate_env_values(values)
    if problems:
        raise RuntimeError("generated staging config is invalid: " + "; ".join(problems))
    write_env(path, values)
    return values


def generate_control_values(probe: bool = True, taken: set[int] | None = None) -> dict[str, str]:
    values: dict[str, str] = {
        "STAGING_CONTROL_DB_USER": "control_owner",
        "STAGING_CONTROL_DB": "incident_recovery_control",
        "STAGING_CONTROL_DB_PASSWORD": secrets.token_hex(24),
        "STAGING_OPERATOR_TOKEN": secrets.token_hex(24),
        "STAGING_INTERNAL_TOKEN": secrets.token_hex(24),
    }
    used = set(taken or set())
    for key in CONTROL_PORT_KEYS:
        preferred = PREFERRED_CONTROL_PORTS[key]
        chosen = allocate_loopback_port(preferred, used) if probe else preferred
        values[key] = str(chosen)
        used.add(chosen)
    return values


def validate_control_values(values: dict[str, str]) -> list[str]:
    problems: list[str] = []
    for key in CONTROL_KEYS:
        raw = (values.get(key) or "").strip()
        if not raw:
            problems.append(f"{key} is missing or empty")
        elif raw.lower().startswith(PLACEHOLDER_PREFIX):
            problems.append(f"{key} is still a placeholder")
    for key in CONTROL_SECRET_KEYS:
        raw = (values.get(key) or "").strip()
        if raw in FORBIDDEN_SECRETS or raw.lower() in FORBIDDEN_SECRETS:
            problems.append(f"{key} is a development credential")
    if (values.get("STAGING_CONTROL_DB") or "").strip() == "tenant_platform":
        problems.append("STAGING_CONTROL_DB must not reuse the workload database name")
    for key in CONTROL_PORT_KEYS:
        raw = (values.get(key) or "").strip()
        if not raw.isdigit() or not 1 <= int(raw) <= 65535:
            problems.append(f"{key} must be a TCP port between 1 and 65535")
    return problems


def write_control_env(path: Path, values: dict[str, str]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Generated staging recovery control-plane configuration. GITIGNORED.",
        "# Produced by scripts/staging_env.py --control; distinct from workload creds.",
    ]
    for key in CONTROL_KEYS:
        lines.append(f"{key}={values[key]}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def ensure_control_env(
    path: Path = CONTROL_ENV, *, force: bool = False, probe: bool = True
) -> dict[str, str]:
    existing = load_env_file(path)
    if existing and not force:
        problems = validate_control_values(existing)
        if problems:
            raise RuntimeError(f"{path} is present but invalid: " + "; ".join(problems))
        return existing
    values = generate_control_values(probe=probe)
    problems = validate_control_values(values)
    if problems:
        raise RuntimeError("generated control config is invalid: " + "; ".join(problems))
    write_control_env(path, values)
    return values


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV)
    parser.add_argument("--check", action="store_true", help="validate only, do not write")
    parser.add_argument("--force", action="store_true", help="regenerate over an existing file")
    parser.add_argument(
        "--control",
        action="store_true",
        help="generate/validate the recovery control-plane env (staging/.control.env)",
    )
    parser.add_argument(
        "--no-probe",
        action="store_true",
        help="do not probe loopback ports (used only for offline config tests)",
    )
    args = parser.parse_args(argv)

    if args.control:
        try:
            if args.check:
                values = load_env_file(CONTROL_ENV)
                if not values:
                    print(f"error: {CONTROL_ENV} does not exist", file=sys.stderr)
                    return 1
                problems = validate_control_values(values)
                if problems:
                    for problem in problems:
                        print(f"error: {problem}", file=sys.stderr)
                    return 1
            else:
                values = ensure_control_env(force=args.force, probe=not args.no_probe)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"config: {CONTROL_ENV}")
        for key in CONTROL_KEYS:
            shown = "[set]" if (values.get(key) or "").strip() else "[missing]"
            if key in CONTROL_SECRET_KEYS:
                print(f"  {key}: {shown}")
            else:
                print(f"  {key}: {values.get(key)}")
        return 0

    try:
        if args.check:
            values = load_env_file(args.env)
            if not values:
                print(f"error: {args.env} does not exist", file=sys.stderr)
                return 1
            problems = validate_env_values(values)
            if problems:
                for problem in problems:
                    print(f"error: {problem}", file=sys.stderr)
                return 1
        else:
            values = ensure_env(args.env, force=args.force, probe=not args.no_probe)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"config: {args.env}")
    for key in REQUIRED_KEYS:
        shown = "[set]" if (values.get(key) or "").strip() else "[missing]"
        if key in SECRET_KEYS:
            print(f"  {key}: {shown}")
        else:
            print(f"  {key}: {values.get(key)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
