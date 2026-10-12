# Staging Readiness — Isolated Tenant API Baseline (Task 1)

Scope: **Task 1 only**. This document records the isolated, real tenant-api-platform
staging baseline — its provenance, the exact reproduction commands, the observed
resource isolation, and the remaining blockers. It is not a production-readiness
claim and does not cover the injected-fault/recovery or live-provider work
(Tasks 2–4).

## What was established

An isolated Docker Compose project, `incident-recovery-staging`, running the **real**
pinned tenant API, its migrations, and the webhook worker against dedicated
PostgreSQL and Redis, with generated credentials and loopback-only host ports.
Authenticated tenant-scoped business operations were exercised end to end and
two-tenant isolation was verified against the database-enforced policies.

## Source provenance

The workload is built from a parent-supplied pinned git archive. It is a metadata
input, not evidence produced by this repository, and this repository never reads or
verifies the original sibling checkout.

| Field | Value |
| --- | --- |
| Component | `tenant-api-platform` |
| Pinned full SHA | `a6f715aac1d4e46b2ef30e12fb42d4719672f7f5` |
| Short SHA | `a6f715a` |
| Archive | `.hermes/tenant-api-a6f715a.tar` |
| Archive SHA-256 | `3837fb8bf2bf06080af068a75a6cfd2e22d1f4e15e5b104b73dacd015c5ca48c` |
| Commit embedded in archive pax header | `a6f715aac1d4e46b2ef30e12fb42d4719672f7f5` (matches) |
| Snapshot (gitignored) | `staging/vendor/tenant-api-platform` |
| Resolved provenance | `staging/vendor/source-manifest.resolved.json` |
| Known-good image | `incident-recovery-staging-tenant-api:a6f715a` |

**Original service unmodified.** The pin above is supplied by the parent and is
recorded, not independently verified here. The pinned archive is never written to;
the snapshot is extracted under `staging/vendor/` (gitignored) and left byte-identical
to the archive for provenance. The upstream source tree is not patched, and the
upstream `docker-compose.yml` is not reused.

## Reproduction

```bash
# 1. Generate the gitignored, distinct staging credentials and probe loopback ports.
uv run python scripts/staging_env.py

# 2. Materialize the pinned source snapshot (traversal-safe, hash/commit-bound).
uv run python scripts/staging_source.py

# 3. Validate the Compose configuration without printing secrets.
docker compose -f staging/compose.yaml --env-file staging/.env \
  -p incident-recovery-staging config -q

# 4. Bring the isolated stack up.
docker compose -f staging/compose.yaml --env-file staging/.env \
  -p incident-recovery-staging up --build -d --wait

# 5. Run the real authenticated baseline (registers two synthetic tenants,
#    performs business writes, asserts isolation + readiness, inspects resources).
uv run python scripts/staging_baseline.py
```

Tests:

```bash
uv run pytest tests/staging -q                 # isolation/archive/manifest/unit
uv run pytest tests/unit -q                    # existing backend unit suite (unchanged)
STAGING_E2E=1 uv run pytest tests/staging/test_baseline.py -q   # real containers
```

## Isolation properties (observed)

- Compose project `incident-recovery-staging`; container names prefixed
  `incident-recovery-staging-`; no `container_name` pins and no `tap-*` names.
- Network `incident-recovery-staging-net`; volumes `incident-recovery-staging-pgdata`
  and `incident-recovery-staging-redisdata`. No shared volumes with the demo.
- Published ports are loopback only:
  - staging API `127.0.0.1:18092 -> 8080`
  - worker metrics `127.0.0.1:18091 -> 9090`
  - PostgreSQL and Redis publish **no host port**.
  - `18090` (gateway) and `18093` (console) are the reviewed preferred ports;
    they are probed and reserved but not bound in Task 1.
- Container user is `app` (non-root); no Docker socket is mounted.
- Credentials are freshly generated into `staging/.env` (gitignored); the upstream
  development defaults (`postgres`/`app_rw`, db `tenant_platform`) are not reused.
  The `app_rw` role is created by migration `0001`; a one-shot `app-role-provision`
  service rotates its password from the migration default, feeding it over stdin.

## Verified baseline behavior

- Migrations applied: 12. Worker and API `/readyz` ready; worker `/metrics` exposes
  `webhook_outbox_depth`.
- `app_rw` is `NOSUPERUSER` and `NOBYPASSRLS`; RLS is enabled **and forced** on
  `tenants`, `memberships`, and `projects`. The API and worker refuse to start on a
  privileged role, and both started healthy — so they are connected as the
  unprivileged application role.
- Two synthetic tenants registered through the real API; authenticated `/v1/me`;
  idempotent authenticated project create (retry replays, exactly one row);
  cross-tenant read refused with `404` (never `403`); each tenant observes only its
  own project.

Machine-readable results: `.hermes/evidence/staging-task1/results.json`
(25/25 checks passed). Sanitized logs and provenance artifacts are in the same
directory.

## Task 2 provider gate (blocked, no live calls)

Runtime provider **eligibility remains BLOCKED**. The official OpenCode Go
documentation (`https://opencode.ai/docs/go/`, section *Where can I use it*)
describes Go as designed for OpenCode and coding agents issuing similar
coding-agent traffic; it does **not** explicitly approve a non-coding runtime
incident-investigation workload. The scope of this application is therefore
unresolved, recorded as blocked rather than claimed eligible or prohibited.

- `src/incident_recovery/provider_policy.py` fails closed: a blocked gate
  prevents **any** transport call, and no self-asserted boolean can enable it.
  Enabling the runtime requires reviewed, scoped eligibility evidence supplied
  through secure orchestrator configuration; a user account authorization is not
  provider permission.
- The bounded adapter sends the truthful `incident-recovery-staging` user agent
  and a stable incident-derived `x-opencode-session` (same session across turns
  and retries, different across incidents). It never spoofs another client.
- Paid calls are bounded by a staging-specific durable ledger: at most 12
  investigations plus **one single-use smoke call** (one turn, one attempt,
  never retried), concurrency 1, 8 provider turns per incident, 4096 output
  tokens per call, 20000 input characters per call and 12 tools / 120 seconds;
  attempts (including retries) are counted separately and cannot exceed the paid
  allowance.  Every attempt re-checks the durable billing latch, admission, and
  budget inside a cross-process transport slot, so a refusal latched by another
  instance/process between attempts is enforced before transport.  Unknown
  provider usage/cost is recorded as unknown, never zero.  An existing ledger
  that is null/empty/corrupt/negative/oversized is refused (not silently reset);
  only a missing file starts a new batch, and v1/v2 records migrate retaining
  usage.
- **No live provider call was made in Task 2.** The live gate is reported
  explicitly blocked; this is not a live provider compatibility claim. Coding
  through OpenCode remains allowed separately.

## Existing demo

The original `incident-recovery` demo stack was left running and unmodified; its
containers (ports `18080`–`18083`, `15432`) were observed present before and after
the staging baseline. This baseline does not run the demo's full regression suite;
that independent run belongs to Task 5.

## Task 3: real injected fault and approved recovery

The injected faulty revision, the isolated staging traffic gateway/control plane,
and the operator-approved real recovery are implemented and recorded in
`docs/staging-recovery.md`. Task 3 uses the `recovery` Compose profile and a
separate control database, so the default `up` (and this document) remain the
Task 1 baseline. Runtime provider eligibility is still **blocked**: Task 3 runs
through the labelled `scripted:tenant-api-staging` adapter, not a live model.

## Task 5: serial reproducible staging verification

`scripts/staging_verify.py` is the Task 5 independent verification driver. It
runs every staging gate **serially** (never two mutating steps at once), then the
full `scripts/verify.py --docker --ui` demo regression, and restores both stacks
healthy in a `finally` block. It writes a machine-readable report and sanitized
logs to `.hermes/evidence/staging-task5/`.

```bash
uv run python scripts/staging_verify.py          # full serial run
uv run python scripts/staging_verify.py --skip-build --skip-demo
```

Reported status (actual, from the executed run):

| Gate | Status | Evidence |
| --- | --- | --- |
| `staging_integration` | passed | source/fault materialization; Docker-free staging suite 221 passed (+1 opt-in skip run separately via `STAGING_E2E=1`); real baseline 25/25; real recovery 20/20; scripted evaluation 12/12 |
| `demo_regression` | passed | `scripts/verify.py --docker --ui`: 19 checks passed / 0 failed / 0 blocked; 229 executed test cases |
| `live_readiness` | **blocked** | 12 blocked cases, 0 executed, 0 provider requests, `safety_ok: null` (not established) |
| `provider_blocked` | **blocked** | `go_runtime_eligible(default_go_runtime_eligibility())` is `False` |

The two readiness gates are deliberately separate: **staging integration is
verified while live-readiness remains blocked.** This is not a production
readiness claim.

Loopback ports (probed, all `127.0.0.1`): staging gateway `18090`, worker metrics
`18091`, API `18092`, console `18093`, control PostgreSQL `18094`, control API
`18095`, workload PostgreSQL `18096`, workload Redis `18097`. The demo uses
`18080`/`18081` (test override)/`18082`/`18083`/`15432` and is unchanged.

The driver's report records the actual `source.sha`, `source.dirty`, every
command and exit code, the pinned source/archive/fault-patch hashes, the
manifest hash, the adapter identity, and the scripted/live case counts. The live
case artifacts are checked to have `tokens: null` / `cost: null` (unknown usage
is never recorded as `0`) and `provider_transport_attempted: false`.

## Remaining blockers / out of scope

- Live paid provider eligibility and bounded live investigation (Task 2) —
  **still blocked**; the live-readiness gate stays blocked with 0 executed cases.
- Independent fresh adversarial review of the Task 5 verification (performed by
  the parent only after the writer exits; this document does not replace it).
- The staging gateway/console are implemented for Task 3 under the `recovery`
  profile; the default `up` remains the Task 1 baseline.
