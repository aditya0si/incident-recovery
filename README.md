# Incident Recovery

Local Docker demo of a detectable broken deployment and a stable gateway that
switches real HTTP traffic between a predefined healthy and broken version.

**Milestone 1 (Task 1) only.** This repository currently implements the real
demo deployment slice: packaging and locked dependencies, a Dockerfile, Compose
orchestration, PostgreSQL-backed active revision/generation state, a stable
public traffic gateway, an authenticated internal switch listener, and real
Docker end-to-end tests. Incident workflow, approvals, the investigation agent,
recovery execution, and the console are later milestones and are **not**
implemented here.

## Architecture (Task 1)

```
                 host 127.0.0.1
   public  :18080 ──► gateway (proxy)  ──demo_net──► demo-healthy-v1
   internal:18081 ──► gateway-control  ──internal_net──► postgres
   postgres:15432 ───────────────────────────────────────┘
```

- `gateway` (proxy role): public listener. Proxies fixed functional paths to
  the active demo deployment chosen from PostgreSQL. It has **no** switch route.
  It runs on both `demo_net` and `internal_net`.
- `gateway-control` (control role): authenticated compare-and-set switch. It
  is attached to `internal_net` only and requires the internal token. Published
  only on loopback.
- `demo-healthy-v1` / `demo-broken-v2`: predefined workloads on `demo_net` with
  no host ports. Same image, different `DEMO_REVISION`.
- `postgres`: source of truth for `deployment_state`, `deployment_operations`
  (idempotency), and append-only `deployment_history`.

The proxy re-reads the active revision on every proxied request, so a completed
switch is immediately observable through real traffic. Destinations are a fixed
mapping (`healthy-v1` -> `demo-healthy-v1:8000`, `broken-v2` ->
`demo-broken-v2:8000`); the API rejects unknown revisions and extra fields, so
callers cannot supply an arbitrary destination.

## Prerequisites

- Docker Engine with Compose v2 (tested: Docker 29.6.2, Compose v5.3.1)
- `uv` (tested: 0.12.13) for the host test environment
- A bash shell (Windows: Git Bash or equivalent)

## Configuration

Runtime secrets live in a gitignored `.env` file. Start from the template and
replace every placeholder with locally generated values:

```bash
cp .env.example .env
```

`INTERNAL_TOKEN` and `POSTGRES_PASSWORD` are required. The defaults in
`.env.example` are placeholders only and must not be used as-is. Secrets are
never printed by the application or tests and are omitted from logs.

Ports (all loopback-only):

| Variable        | Default | Purpose                          |
| --------------- | ------- | -------------------------------- |
| `GATEWAY_PORT`  | 18080   | public gateway                   |
| `CONTROL_PORT`  | 18081   | internal switch listener         |
| `POSTGRES_PORT` | 15432   | PostgreSQL (host debugging)      |

## Run the stack

```bash
uv run pytest tests/unit/test_gateway.py -v          # unit tests (no Docker)
docker compose -p incident-recovery config -q         # validate config quietly
docker compose -p incident-recovery up --build -d --wait
uv run pytest tests/e2e/test_deployment.py -v         # real Docker E2E
```

`tests/conftest.py` loads `.env`, so the E2E suite picks up `INTERNAL_TOKEN`
without exporting it manually.

Stop the stack without deleting unrelated resources:

```bash
docker compose -p incident-recovery down
```

`docker compose -p incident-recovery down -v` additionally removes this
project's named volume `incident-recovery-pgdata`. It does not touch any other
Compose project, container, network, or volume.

## Manual demonstration

With the stack running, `GET /snapshot` on the public gateway reports the active
revision. The internal switch performs a compare-and-set on the generation:

```bash
# healthy revision serves real functional traffic
curl -s http://127.0.0.1:18080/api/work

# inject the broken revision through the authenticated internal listener
curl -s -X POST http://127.0.0.1:18081/internal/switch \
  -H "X-Internal-Token: $INTERNAL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"operation_id":"<uuid>","expected_generation":<n>,"target_revision":"broken-v2"}'

# functional traffic now genuinely fails through the same public gateway
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/api/work

# switch back to the known-good predecessor using the new generation
```

Switch semantics:

- Generation increments on every applied switch; `predecessor` records the
  revision that was active before.
- An exact replay of a recorded `operation_id` returns the recorded result with
  no second mutation.
- A conflicting replay (same `operation_id`, different request), a stale
  `expected_generation`, a missing/wrong token, or an unknown revision is
  refused (HTTP 409/401/422).
- `/work` fails and `/health` reports failure on the broken revision while
  `/livez` (process liveness) stays up, so liveness is never mistaken for
  functional health.

## Scope and limitations

- Local Docker only; no Kubernetes, cloud deployment, or publishing.
- No Docker socket is mounted for this task. The privileged executor trust
  boundary is reserved for a later milestone.
- The broken revision is a predefined demo fault; it is not a production
  control surface.
- Task 1 exposes only the demo deployment and switch surface. It does not yet
  persist incidents, gate recovery on approval, or run investigation.
- The public gateway and the internal switch are separate listeners on separate
  networks; the internal token is still a shared secret and the internal
  listener is reachable on host loopback in this demo deployment.
