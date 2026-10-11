# Incident Recovery

Local Docker demo of a detectable broken deployment and a stable gateway that
switches real HTTP traffic between a predefined healthy and broken version, with
a durable incident workflow, operator control surface, and approval-gated,
independently verified rollback.

**Milestones 1–6.** This repository implements the real demo deployment slice
(Task 1), the durable incident workflow plus operator API (Task 2),
approval-gated rollback with durable recovery and sustained functional
verification (Task 3), the bounded, evidence-backed investigation agent
(Task 4), the operator console (Task 5), and the reproducible whole-stack
verification driver with adversarial resilience gates (Task 6).

### Real service recovery vs scripted agent inference

These are deliberately separate, and the console and reports always label which
is which:

- **Real service recovery.** The gateway reads the active revision from
  PostgreSQL and proxies real HTTP traffic to the predefined healthy/broken demo
  containers. Fault injection, deployment reservations, approvals, the restricted
  executor, and sustained functional verification (three consecutive functional
  checks two seconds apart within 30 seconds) all run as real services.
- **Scripted agent inference.** The investigation adapter is a deterministic
  script (`scripted:demo`), enabled only by the explicit
  `compose.investigation.yaml` override. It requests the real read-only tools
  (`health`, `logs`, `metrics`, `deployments`) but is not a language model. Every
  run records its identity, and the console labels it prominently.
- **Live model.** With no runtime provider configured the worker fails closed
  (`missing-credentials`) and escalates; it never substitutes a script. Live
  investigation is an optional, separately configured path (see
  [Whole-stack verification](#reproducible-whole-stack-verification)).

## Operator console

The console is a React/TypeScript/Vite app served by nginx at
**http://127.0.0.1:18083** (loopback only). nginx also acts as the same-origin
reverse proxy for the operator API and the resumable SSE event stream, so the
browser only ever talks to the console origin.

- The operator enters the bearer token in the UI; it is held **only in memory**
  for that tab (never `localStorage`, `sessionStorage`, cookies, the URL, logs,
  or build output).
- The queue shows persisted incidents with status and update time; the detail
  panel shows the recorded investigation identity (prominently labeling
  `scripted:demo` or `missing-credentials`), the evidence-linked diagnosis, the
  actual bounded tool trace, the active deployment revision/generation, the
  proposal's current/target revisions and five-minute approval TTL, and the
  recovery operation's **executed vs verified** distinction.
- Approve binds the exact proposal digest; in-flight and stale/expired approvals
  are disabled and the server's refusal is shown. Reject never executes an
  action. There is no proposal-injection endpoint.
- Rendered logs, model text, and payloads are untrusted and rendered as inert
  text (React escaping plus a restrictive Content-Security-Policy); no HTML/script
  injection is possible.

## Architecture

```
                 host 127.0.0.1
   public  :18080 ──► gateway (proxy)  ──demo_net──► demo-healthy-v1 / broken-v2
   api     :18082 ──► api ──internal_net──► postgres
   console :18083 ──► console (nginx) ──internal_net──► api  (same-origin proxy)
   postgres:15432 ──────────────────────────┘
                        api ──internal_net──► gateway-control (no host port)
                      worker ──internal_net──► executor (no host port)
                        │                         │
                        └──────────► gateway (verification) ◄── gateway-control
```

- `console`: static React bundle served by nginx. It serves the app and proxies
  the operator API and SSE stream same-origin to `api`; it never reaches the
  internal executor or `gateway-control` and holds no Docker socket. Published on
  loopback only.
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
- `worker`: durable recovery worker. Claims leased incidents, runs the bounded
  investigation stage for `detected`/`investigating` incidents, executes the
  persisted recovery operation through the executor, and runs sustained
  functional verification through the public gateway.
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

### Task 4 bounded investigation agent

- **Bounded read-only tools.** The agent can call exactly four tools: `health`,
  `logs`, `metrics`, and `deployments`. `ToolRequest` forbids every field except
  the tool name and an optional bounded `lines` count, so a model can never
  supply a URL, path, container id, shell command, or arbitrary destination.
  `health`/`logs`/`metrics` read the fixed gateway paths; `deployments` reads the
  authoritative PostgreSQL deployment state and history.
- **Real, not fabricated, observations.** The demo workload records an in-memory
  structured log ring buffer (`/logs`) and actual runtime request counters
  (`/metrics`), exposed through the stable gateway (`/api/logs`, `/api/metrics`).
  Log and metric text is treated as untrusted data, redacted for secret-shaped
  values, and size-limited before it is persisted as evidence.
- **Durable budget and traces.** One investigation *run* per incident epoch
  persists the adapter identity, the tool-call count, and the wall-clock
  deadline; logical step traces are unique per `(incident, epoch, step_index)`.
  A worker restart resumes the same epoch with the same budget and cannot
  duplicate a trace. Server-enforced maxima are **12 tool calls** and **120
  seconds**; per-provider deadlines and bounded retries count toward the budget.
- **Deterministic proposal gate.** The model's diagnosis is never trusted as an
  authorization. A proposal is only created when the cited evidence belongs to
  the incident's current epoch, shows observed current functional failure, the
  deployment evidence matches the authoritative revision/generation, and the
  target is the recorded known-good predecessor `healthy-v1`. Unsupported
  conclusions, foreign/nonexistent/stale evidence, prompt injection in logs,
  malformed provider JSON, provider unavailability, and budget exhaustion all
  **escalate** instead of recovering. There is no proposal-injection endpoint.
- **Fail-closed runtime model.** The live adapter is an OpenAI-compatible
  chat-completions client configured only through `MODEL_BASE_URL`,
  `MODEL_NAME`, and `MODEL_API_KEY` (separate from any coding-CLI credential).
  When credentials are absent the adapter is `missing-credentials` and the
  investigation escalates; it never silently substitutes a script. The
  deterministic `scripted:demo` adapter is enabled only by the explicit
  `INVESTIGATION_ADAPTER=scripted` opt-in (tests / the labeled demo override) and
  every run records its adapter identity.
- **State flow.** The worker moves `detected` → `investigating` → either
  `awaiting_approval` (a gated, evidence-linked proposal) or `escalated`; the
  existing Task 3 approval/recovery path then proceeds unchanged.

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
| `CONSOLE_PORT`  | 18083   | operator console (http://127.0.0.1:18083) |
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

# frontend unit tests, typecheck, and production build (Node 22+)
npm --prefix frontend ci
npm --prefix frontend test -- --run
npm --prefix frontend run build
```

Open **http://127.0.0.1:18083** in a browser and paste the operator token to use
the console. `tests/conftest.py` loads `.env`, so token-based tests pick up
values without exporting them manually.

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

The scripted-investigation E2E suite needs the worker to use the explicitly
labeled `scripted:demo` adapter, which is enabled only by the opt-in override
(never the default stack):

```bash
docker compose -p incident-recovery -f compose.yaml -f compose.investigation.yaml up --build -d --wait
uv run pytest tests/e2e/test_investigation.py -v   # alert -> real tools -> proposal -> approve -> rollback -> verify
docker compose -p incident-recovery up --build -d --wait   # restore default
```

E2E tests **fail loudly** when prerequisites are missing; they never skip and
silently pass. `test_recovery.py` performs a real approved rollback through the
live API and asserts sustained checks; it briefly stops and restarts the real
`worker` container to prove recovery resumes from persisted state.
`test_investigation.py` drives a real alert through the real worker/gateway
health/logs/metrics/deployments tools to a gated proposal, then through the real
approval and sustained-verification path. Scripted runs are recorded with the
`scripted:demo` adapter identity.

### Console browser E2E (Playwright)

`tests/e2e/test_console.py` drives the real console in a real Chromium browser
against the live stack: it injects the demo fault and submits an alert from the
UI, waits for the real diagnosis, approves the exact digest in the UI, and
asserts the real sustained recovery. It also covers a **real escalation**
(scripted investigation against a healthy deployment), a **real operator
rejection**, a `recovery_failed` view backed by a clearly labeled test-side
fixture, and a narrow-viewport/accessibility check. Playwright's browser is
installed separately:

```bash
uv run playwright install chromium
docker compose -p incident-recovery -f compose.yaml -f compose.investigation.yaml up --build -d --wait
uv run pytest tests/e2e/test_console.py -v
docker compose -p incident-recovery up --build -d --wait   # restore default
```

## Reproducible whole-stack verification

`scripts/verify.py` is the reproducible gate driver. It runs real commands,
records each command's exit code and captured output, writes a machine-readable
report plus sanitized durable logs, and distinguishes **passed / failed /
blocked**. It exits non-zero if any *required* check fails or is blocked; the
optional live-model check is reported separately.

```bash
uv run python scripts/verify.py --docker --ui   # all backend, frontend, Docker, and browser checks
uv run python scripts/verify.py                 # host-only (unit + frontend) checks
uv run python scripts/verify.py --live          # additionally run the optional live-model check
```

- The driver applies the test-only control override and the explicit
  scripted-investigation override for the Docker E2E phase and **restores the
  default stack in a `finally` block even if a check fails**.
- No secrets are printed: output is sanitized against the values in the
  gitignored `.env`, Compose config is validated only with `config -q`, and it
  scans tracked files for credential material without printing any value.
- Report: `.hermes/evidence/verify/report.json`; logs:
  `.hermes/evidence/verify/logs/`. The committed summary and observed counts are
  in [docs/evidence.md](docs/evidence.md).

The last full run (`--docker --ui`) recorded **19 checks passed, 0 failed,
0 blocked**, covering **154 executed test cases** (101 backend, 31 frontend, and
22 real Docker/browser E2E). Counts are generated from the actual report; see
`docs/evidence.md` for the exact commands and results.

### Optional live-model check

`--live` uses runtime credentials already configured through
`MODEL_BASE_URL` / `MODEL_NAME` / `MODEL_API_KEY` (separate from any coding-CLI
credential). When they are absent the check is reported as **blocked**
(`live_model_unconfigured`), never as a success. When configured it performs a
real provider call and asserts the recorded investigation adapter is
`openai-compatible:*`.

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

### Investigation and approval-gated recovery demonstration

An alert starts a real worker investigation. With the default stack and no
runtime model credentials, the investigation fails closed and escalates:

```bash
curl -s -X POST http://127.0.0.1:18082/alerts \
  -H "Authorization: Bearer $OPERATOR_TOKEN" -H "Content-Type: application/json" \
  -d '{"dedupe_key":"demo-2","service_id":"demo-api","summary":"functional failure"}'
# shortly after: state == "escalated" (events: investigation_started, escalated)
```

With a live provider configured (`MODEL_BASE_URL` / `MODEL_NAME` / `MODEL_API_KEY`)
the worker investigates with real tools and, when the gate passes, records an
evidence-linked proposal and moves the incident to `awaiting_approval`. To run the
deterministic, explicitly labeled scripted path without a provider, use the opt-in
override:

```bash
docker compose -p incident-recovery -f compose.yaml -f compose.investigation.yaml up --build -d --wait
curl -s -X POST http://127.0.0.1:18082/alerts \
  -H "Authorization: Bearer $OPERATOR_TOKEN" -H "Content-Type: application/json" \
  -d '{"dedupe_key":"demo-3","service_id":"demo-api","summary":"functional failure"}'
# GET /incidents/{id}: state "awaiting_approval" with a proposal whose evidence_ids
# reference tool:health and tool:deployments observations (adapter scripted:demo)
docker compose -p incident-recovery up --build -d --wait   # restore default
```

The operator then approves the exact proposal digest (or rejects it):

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
recovery through the public gateway. The same state is shown in the console at
http://127.0.0.1:18083.

## Scope and limitations

- Local Docker only; no Kubernetes, cloud deployment, or publishing.
- The console is a static SPA served by nginx plus a narrow same-origin API/SSE
  proxy. It reads and writes only through the real persisted API and renders all
  untrusted text as inert text; it is not a generic chat UI.
- No Docker socket is mounted in any container. The executor is an internal,
  authenticated, fixed-operation surface and deliberately has no Docker power
  (see `docs/security.md`); container restart is deferred to a later milestone.
- The broken revision is a predefined demo fault; it is not a production
  control surface.
- Task 5 provides the operator console. All normal UI data comes from the real
  persisted API; no seeded fake dashboards are used. The single test-side fixture
  is a labeled `recovery_failed` row used only by the browser E2E failure view.
- Live-model investigation is **blocked** without a separately configured
  OpenAI-compatible runtime model. The default stack therefore escalates
  investigations (`adapter=missing-credentials`) rather than fabricating a
  scripted success. Scripted investigation requires the explicit opt-in override
  and is always labeled `scripted:demo`.
- The internal token and operator token are shared secrets for this local demo;
  the internal switch and executor are reachable only over the Compose internal
  network and expose no host port.
