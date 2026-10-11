# Incident Recovery

Local Docker demo of a detectable broken deployment and a stable gateway that
switches real HTTP traffic between a predefined healthy and broken version, with
a durable incident workflow, operator control surface, and approval-gated,
independently verified rollback.

**Milestones 1–3.** This repository implements the real demo deployment slice
(Task 1), the durable incident workflow plus operator API (Task 2), and
approval-gated rollback with durable recovery and sustained functional
verification (Task 3). The bounded model investigation agent (Task 4) and the
console (Task 5) are later milestones and are **not** implemented here.

## Architecture

```
                 host 127.0.0.1
   public  :18080 ──► gateway (proxy)  ──demo_net──► demo-healthy-v1 / broken-v2
   api     :18082 ──► api ──internal_net──► postgres
   postgres:15432 ──────────────────────────┘
                        api ──internal_net──► gateway-control (no host port)
                      worker ──internal_net──► executor (no host port)
                        │                         │
                        └──────────► gateway (verification) ◄── gateway-control
```

- `gateway` (proxy role): public listener. Proxies fixed functional paths to the
  active demo deployment chosen from PostgreSQL. It has **no** switch route.
- `gateway-control` (control role): authenticated, reservation-gated
  compare-and-set switch. It is attached to `internal_net` only and requires the
  internal token. The default stack publishes **no** host port for it.
- `api`: operator control API. Authenticated `POST /alerts`,
  `POST /demo/faults`, `POST /incidents/{id}/approve`, and
  `POST /incidents/{id}/reject`; read-only `GET /incidents`,
  `GET /incidents/{id}`, and SSE `GET /incidents/{id}/events`. Published on
  loopback only.
- `executor`: restricted internal executor. Accepts only a persisted operation
  id over an authenticated channel, exposes **no** host port, and receives
  **no** Docker socket (revision switching needs no Docker power).
- `worker`: durable recovery worker. Claims leased incidents, executes the
  persisted operation through the executor, and runs sustained functional
  verification through the public gateway.
- `demo-healthy-v1` / `demo-broken-v2`: predefined workloads on `demo_net`.
- `postgres`: source of truth for deployment state and the durable incident
  workflow (incidents, immutable evidence, append-only events, proposals,
  approvals, recovery operations, and deployment reservations).

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

### Task 3 approval-gated rollback and verification

- **Exact approval binding.** `POST /incidents/{id}/approve` accepts a proposal
  *digest* and actor, not action fields. The approval binds the incident, digest,
  fixed service, current revision/generation, known-good predecessor target,
  actor, and a UTC five-minute TTL. Rejections never execute an action.
- **Fail-closed authorization.** Unknown digests, stale generations, targets
  that are not the recorded predecessor, service mismatches, expired or consumed
  approvals, and competing reservations are refused. Concurrent duplicate
  approvals collapse to one logical approval and one operation.
- **Authoritative reservation boundary.** `deployment_reservations` is the
  deployment-mutation token. A partial unique index allows at most one *active*
  reservation per service, so fault injection and recovery are mutually
  exclusive. Every gateway switch validates its reservation (and, for recovery,
  re-validates the approval/operation/TTL/consumption) inside the switch
  transaction that locks `deployment_state`. A switch without a matching
  reservation is refused (`unauthorized`). The internal switch therefore is not
  an approval bypass.
- **Restricted executor.** The executor accepts only `{operation_id}`, loads the
  authoritative operation/approval/reservation, re-validates scope, and drives
  the fixed desired-state switch. Arbitrary shell, container, image, mount, or
  revision inputs are rejected at the schema boundary.
- **Durable recovery + reconciliation.** The worker claims incidents with a
  durable lease and commits conditionally under that lease. A crash during
  recovery resumes the *same persisted operation id*; if an operation already
  executed it proceeds to verification. Response ambiguity is reconciled against
  the durable `deployment_operations` record by operation id, never a blind
  repeat, and an unrelated deployment change can never manufacture success.
- **Independent sustained verification.** Resolution requires the public gateway
  to report the matching known-good revision and functional health **three
  consecutive times, two seconds apart, within 30 seconds**. Failures reset the
  streak; an expired deadline or functional/ambiguous failure becomes
  `recovery_failed`. An executor `200` alone never resolves.

### Security model

- Every write requires `Authorization: Bearer <OPERATOR_TOKEN>` with a
  constant-time comparison. No cookies are used or trusted.
- Any request with an `Origin` header outside the explicit `ALLOWED_ORIGINS`
  localhost allowlist is rejected with HTTP 403 even when a valid token is sent.
- The operator token and internal token are never echoed in errors, event
  payloads, or logs.
- Fault injection is fixed to `demo-api` / `broken-v2` only and is refused while
  a recovery is pending.
- No container receives the Docker socket. The executor exposes no host port and
  needs no Docker power (see `docs/security.md`).

### Consistency approach (fault injection)

Fault injection creates its persisted fault reservation first (atomically, so a
concurrent recovery reservation cannot also win), then performs the switch
through the authenticated **internal gateway-control listener over `internal_net`**
(the API holds no database transaction across that call, so it cannot
self-deadlock with the control transaction). The switch serialises on the same
`deployment_state` row lock, validates the reservation, and is idempotent by
`operation_id`. If the switch response is ambiguous (network failure), the API
reconciles against the durable operation record and only reports success if that
record shows the applied target; otherwise it reports the actual current
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

## End-to-end tests

The deployment E2E suite provisions test-side reservations and drives the
internal switch directly, so it needs `gateway-control` reachable on the host.
Use the test-only override, which is the only place the control port is
published. The recovery E2E suite needs the `worker` and `executor` services
(part of the default stack):

```bash
docker compose -p incident-recovery -f compose.yaml -f compose.test.yaml up --build -d --wait
uv run pytest tests/e2e/test_deployment.py -v   # reservation-gated switch + real traffic
uv run pytest tests/e2e/test_recovery.py -v     # approved rollback, rejection, worker restart
# restore the default stack (no host control port):
docker compose -p incident-recovery up --build -d --wait
```

E2E tests **fail loudly** when prerequisites are missing; they never skip and
silently pass. `test_recovery.py` performs a real approved rollback through the
live API and asserts sustained checks; it briefly stops and restarts the real
`worker` container to prove recovery resumes from persisted state.

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

### Approval-gated recovery demonstration

Task 3 binds approval to a proposal digest; the bounded investigation agent that
*creates* proposals automatically is Task 4. Until then, a proposal can be
inserted through the repository (as the tests do), after which the operator
approves or rejects it over the API:

```bash
# approve the exact proposal digest (actor recorded; five-minute TTL)
curl -s -X POST http://127.0.0.1:18082/incidents/<incident-id>/approve \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"proposal_digest":"<digest>","actor":"local-operator"}'

# or reject it (never executes an action)
curl -s -X POST http://127.0.0.1:18082/incidents/<incident-id>/reject \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"actor":"local-operator","reason":"hold"}'
```

Approval moves the incident to `recovering` and creates one operation. The
`worker` executes it via the `executor` and then verifies sustained functional
recovery through the public gateway; `GET /incidents/{id}` returns the
proposal/approval/operation/verification needed by the future console.

## Scope and limitations

- Local Docker only; no Kubernetes, cloud deployment, or publishing.
- No Docker socket is mounted in any container. The executor is an internal,
  authenticated, fixed-operation surface and deliberately has no Docker power
  (see `docs/security.md`); container restart is deferred to a later milestone.
- The broken revision is a predefined demo fault; it is not a production
  control surface.
- Task 3 gates rollback on exact approval and verifies sustained functional
  recovery. It does **not** yet run bounded model investigation (Task 4) or
  provide the console (Task 5); proposals are created by repository fixtures or
  tests until Task 4.
- The internal token and operator token are shared secrets for this local demo;
  the internal switch and executor are reachable only over the Compose internal
  network and expose no host port.
