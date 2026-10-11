# Incident Recovery

Local Docker demo of a detectable broken deployment and a stable gateway that
switches real HTTP traffic between a predefined healthy and broken version, with
a durable incident workflow and operator control surface.

**Milestones 1–2.** This repository implements the real demo deployment slice
(Task 1) and the durable incident workflow plus operator API (Task 2). The
investigation agent, approval-gated recovery execution, verification, and the
console are later milestones and are **not** implemented here.

## Architecture

```
                 host 127.0.0.1
   public  :18080 ──► gateway (proxy)  ──demo_net──► demo-healthy-v1 / broken-v2
   api     :18082 ──► api ──internal_net──► postgres
   postgres:15432 ──────────────────────────┘
                        api ──internal_net──► gateway-control (no host port)
```

- `gateway` (proxy role): public listener. Proxies fixed functional paths to the
  active demo deployment chosen from PostgreSQL. It has **no** switch route.
- `gateway-control` (control role): authenticated compare-and-set switch. It is
  attached to `internal_net` only and requires the internal token. The default
  stack publishes **no** host port for it, so it is not a permanent host-facing
  bypass of the forthcoming approval gate.
- `api`: operator control API. Authenticated `POST /alerts` and
  `POST /demo/faults`; read-only `GET /incidents`, `GET /incidents/{id}`, and
  SSE `GET /incidents/{id}/events`. Published on loopback only.
- `demo-healthy-v1` / `demo-broken-v2`: predefined workloads on `demo_net`.
- `postgres`: source of truth for deployment state and the durable incident
  workflow (incidents, immutable evidence, append-only events, and the
  proposal/approval/operation tables later milestones build on).

### Task 2 durable workflow (PostgreSQL, asyncpg)

- **Versioned schema bootstrap** (`schema_version` + advisory-locked migrations)
  adds incidents, evidence, events, proposals, approvals, and recovery
  operations on top of the Task 1 deployment tables.
- **Duplicate alerts collapse** to one incident via a unique `dedupe_key`
  (`INSERT ... ON CONFLICT`), proven under concurrency.
- **Legal state transitions** are pure conditional `UPDATE ... WHERE state = ANY(...)`
  against explicit predecessor sets; illegal transitions are refused.
- **Evidence is immutable**: database rules make `UPDATE`/`DELETE` on
  `incident_evidence` no-ops, independently of application code.
- **Durable leases**: `lease_owner` / `lease_expires_at` columns. An expired
  lease permits takeover by another worker; a stale owner can never commit under
  a renewed owner's lease.
- **Append-only events** with a global `BIGSERIAL` id; SSE uses `Last-Event-ID`
  to backfill in id order and polls the persisted event table, so a reconnect
  cannot lose events emitted between backfill and subscription.
- All timestamps are UTC `TIMESTAMPTZ`; alert/evidence/event payloads are
  bounded (16 KiB) at both the API and database layers.

### Security model (Task 2)

- Every write requires `Authorization: Bearer <OPERATOR_TOKEN>` with a
  constant-time comparison. No cookies are used or trusted.
- Any request with an `Origin` header outside the explicit `ALLOWED_ORIGINS`
  localhost allowlist is rejected with HTTP 403 even when a valid token is sent.
- The operator token is never echoed in errors, event payloads, or logs.
- Fault injection is fixed to `demo-api` / `broken-v2` only (the API rejects any
  other target) and is refused while a recovery is pending.

### Consistency approach (fault injection)

Fault injection reads the authoritative snapshot, then performs the switch
through the authenticated **internal gateway-control listener over `internal_net`**
(the API holds no database transaction across that call, so it cannot
self-deadlock with the control transaction). The switch serialises on the same
`deployment_state` row lock used by Task 1, and idempotency is keyed by
`operation_id`. If the switch response is ambiguous (network failure), the API
**reconciles against persisted state** and only reports success if the read-back
shows the target revision; a stale/conflict response reports the actual current
revision instead of a false success.

## Prerequisites

- Docker Engine with Compose v2 (tested: Docker 29.6.2, Compose v5.3.1)
- `uv` (tested: 0.12.13) for the host test environment
- A bash shell (Windows: Git Bash or equivalent)

## Configuration

Runtime secrets live in a gitignored `.env`. Start from the template and replace
every placeholder with locally generated values:

```bash
cp .env.example .env
```

`INTERNAL_TOKEN`, `OPERATOR_TOKEN`, and `POSTGRES_PASSWORD` are required.
`INTERNAL_TOKEN` and `OPERATOR_TOKEN` are distinct; neither is ever logged.

Ports (all loopback-only):

| Variable        | Default | Purpose                          |
| --------------- | ------- | -------------------------------- |
| `GATEWAY_PORT`  | 18080   | public gateway                   |
| `API_PORT`      | 18082   | operator HTTP API                |
| `CONTROL_PORT`  | 18081   | internal switch (test override only) |
| `POSTGRES_PORT` | 15432   | PostgreSQL (host test access)    |

`CONTROL_PORT` is **not** published by the default stack. It is published only
by the test-only override `compose.test.yaml`.

## Run the stack

```bash
uv run pytest tests/unit -v                        # unit tests (no Docker)
docker compose -p incident-recovery config -q      # validate config quietly
docker compose -p incident-recovery up --build -d --wait
uv run pytest tests/integration -v                 # real PostgreSQL integration
```

`tests/conftest.py` loads `.env`, so token-based tests pick up values without
exporting them manually.

Stop the stack without deleting unrelated resources:

```bash
docker compose -p incident-recovery down
```

`docker compose -p incident-recovery down -v` additionally removes this
project's named volume `incident-recovery-pgdata`. It does not touch any other
Compose project, container, network, or volume.

## Task 1 end-to-end tests (test-only override)

Task 1's Docker E2E suite drives the internal switch directly and therefore needs
`gateway-control` reachable on the host. Use the test-only override, which is the
only place the control port is published:

```bash
docker compose -p incident-recovery -f compose.yaml -f compose.test.yaml up --build -d --wait
uv run pytest tests/e2e/test_deployment.py -v
# restore the default stack (no host control port):
docker compose -p incident-recovery up --build -d --wait
```

Task 1 tests **fail loudly** when prerequisites are missing; they never skip and
silently pass.

## Operator API demonstration

With the stack running:

```bash
# authenticated write: ingest an alert (duplicate keys return the same incident)
curl -s -X POST http://127.0.0.1:18082/alerts \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"dedupe_key":"demo-1","service_id":"demo-api","summary":"first alert"}'

# read-only views
curl -s http://127.0.0.1:18082/incidents
curl -s http://127.0.0.1:18082/incidents/<incident-id>

# SSE stream, resumable by event id
curl -N -H "Last-Event-ID: 0" http://127.0.0.1:18082/incidents/<incident-id>/events

# authenticated fault injection (fixed demo-api/broken-v2 only)
curl -s -X POST http://127.0.0.1:18082/demo/faults \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_revision":"broken-v2"}'
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/api/work   # 500 while broken
```

A write without a token returns 401; a write with an untrusted `Origin` returns
403 even with a valid token.

## Scope and limitations

- Local Docker only; no Kubernetes, cloud deployment, or publishing.
- No Docker socket is mounted for this milestone. The privileged executor trust
  boundary is reserved for a later milestone.
- The broken revision is a predefined demo fault; it is not a production
  control surface.
- Task 2 persists incidents, evidence, events, and leases, and exposes operator
  control. It does **not** yet run investigation, gate recovery on approval, or
  execute rollback.
- The internal token and operator token are shared secrets for this local demo;
  the internal switch is reachable over the Compose internal network.
