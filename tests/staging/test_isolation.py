"""Isolation invariants for the staging Compose stack.

These assert properties of the reviewed ``staging/compose.yaml`` and
``staging/.env.example`` *statically* (no Docker required): that the stack
cannot accidentally reuse the upstream demo's fixed container names, publish
database or cache ports on the host, or inherit upstream development
credentials.  A real-resource check (labels, ports, volumes) is performed by
``scripts/staging_baseline.py`` against the running stack.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
STAGING = REPO_ROOT / "staging"
COMPOSE = STAGING / "compose.yaml"
ENV_EXAMPLE = STAGING / ".env.example"

PROJECT = "incident-recovery-staging"

# Ports the upstream demo/tenant development stacks publish on the host.  None
# of these may appear unqualified (public) in staging.
UPSTREAM_PUBLIC_PORTS = ("5432:5432", "6379:6379", "8080:8080", "9090:9090")

# Literal development credentials that must never be inherited.
UPSTREAM_DEV_SECRETS = (
    "postgres:postgres",
    "app_rw:app_rw",
    "dev-only-insecure-secret-change-me-32b-min",
)


@pytest.fixture(scope="module")
def compose() -> dict:
    assert COMPOSE.exists(), f"missing {COMPOSE}"
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def env_example() -> str:
    assert ENV_EXAMPLE.exists(), f"missing {ENV_EXAMPLE}"
    return ENV_EXAMPLE.read_text(encoding="utf-8")


def test_project_is_isolated(compose: dict) -> None:
    assert compose.get("name") == PROJECT


def test_expected_services_present(compose: dict) -> None:
    services = compose["services"]
    assert {
        "postgres",
        "redis",
        "migrate",
        "app-role-provision",
        "api",
        "worker",
    } <= set(services)


def test_no_upstream_fixed_container_names(compose: dict) -> None:
    for name, svc in compose["services"].items():
        assert "container_name" not in svc, (
            f"service {name!r} pins container_name; staging must use project-scoped "
            "names so it cannot collide with the running demo"
        )


def test_all_published_ports_bind_loopback(compose: dict) -> None:
    published = 0
    for name, svc in compose["services"].items():
        for entry in svc.get("ports", []):
            text = str(entry)
            assert text.startswith("127.0.0.1:"), (
                f"service {name!r} publishes {text!r}; staging ports must bind 127.0.0.1"
            )
            published += 1
    assert published > 0, "staging API must be reachable on a loopback port for verification"


def test_no_public_database_or_cache_ports(compose: dict) -> None:
    services = compose["services"]
    for db_service in ("postgres", "redis"):
        ports = services[db_service].get("ports", [])
        assert ports == [], (
            f"{db_service} must not publish a host port by default, got {ports!r}"
        )
        for bad in UPSTREAM_PUBLIC_PORTS:
            assert bad not in COMPOSE.read_text(encoding="utf-8")


def test_no_docker_socket_mounted(compose: dict) -> None:
    for name, svc in compose["services"].items():
        for vol in svc.get("volumes", []):
            assert "docker.sock" not in str(vol), (
                f"service {name!r} mounts the Docker socket; staging must not"
            )


def test_volumes_and_networks_are_project_scoped(compose: dict) -> None:
    for vol_name, spec in (compose.get("volumes") or {}).items():
        explicit = (spec or {}).get("name", "")
        assert explicit.startswith(PROJECT), (
            f"volume {vol_name!r} explicit name {explicit!r} is not project-scoped"
        )
    for net_name, spec in (compose.get("networks") or {}).items():
        explicit = (spec or {}).get("name", "")
        assert explicit.startswith(PROJECT), (
            f"network {net_name!r} explicit name {explicit!r} is not project-scoped"
        )


def test_build_context_is_pinned_vendor_snapshot(compose: dict) -> None:
    for name in ("migrate", "api", "worker"):
        build = compose["services"][name].get("build")
        assert build is not None, f"service {name!r} must build from the pinned snapshot"
        context = build["context"] if isinstance(build, dict) else build
        assert context == "./vendor/tenant-api-platform", (
            f"service {name!r} builds from {context!r}; expected the pinned snapshot"
        )


def test_api_connects_as_unprivileged_app_role(compose: dict) -> None:
    api_env = compose["services"]["api"]["environment"]
    dsn = str(api_env.get("DATABASE_URL", ""))
    assert "app_rw:" in dsn, f"api DATABASE_URL must use app_rw, got {dsn!r}"
    assert "${STAGING_OWNER_PASSWORD}" not in dsn, (
        "api must not hold owner credentials; those belong to migrate"
    )
    assert "ALLOW_PRIVILEGED_DB_ROLE" not in api_env, (
        "staging must not set the escape hatch that disables row-level security"
    )


def test_migrate_uses_owner_credentials(compose: dict) -> None:
    migrate_env = compose["services"]["migrate"]["environment"]
    dsn = str(migrate_env.get("MIGRATE_DATABASE_URL", ""))
    assert "${STAGING_OWNER_USER}" in dsn and "${STAGING_OWNER_PASSWORD}" in dsn


def test_redis_requires_a_password(compose: dict) -> None:
    redis_cmd = " ".join(compose["services"]["redis"].get("command", []))
    assert "requirepass" in redis_cmd, "staging Redis must require a generated password"


def _parse_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def test_env_example_has_no_upstream_dev_secrets(env_example: str) -> None:
    lowered = env_example.lower()
    for secret in UPSTREAM_DEV_SECRETS:
        assert secret.lower() not in lowered, (
            f"staging .env.example inherits development credential {secret!r}"
        )


def test_env_example_uses_a_distinct_database_name(env_example: str) -> None:
    values = _parse_env(env_example)
    assert values["STAGING_DB"] == "tenant_platform_staging"
    assert values["STAGING_DB"] != "tenant_platform"
