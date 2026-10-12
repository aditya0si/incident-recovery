# Incident Recovery

Evidence-backed investigation and approval-gated rollback with **Python, FastAPI, PostgreSQL/asyncpg, React/TypeScript, and Docker Compose**. Real HTTP traffic switches between fixed revisions; recovery is persisted and independently verified rather than declared successful when an executor returns success.

Two local workloads exercise the control plane: a healthy/broken demo and an isolated tenant API staging stack with PostgreSQL and Redis. Scripted investigation is explicitly labeled and is not live-model inference. This is an engineering demonstration, not production-ready autonomous remediation.

## Architecture

```text
Operator → React console / nginx → FastAPI API → PostgreSQL workflow store
                                                  ↕
                                      bounded investigation worker
                                                  │ approval required
                                      restricted executor
                                                  ↓
                                      internal gateway control
                                                  ↓
Client → stable HTTP gateway → fixed healthy / faulty revision
          ↑ sustained functional verification
```

PostgreSQL persists incidents, evidence, ordered events, investigation budgets, proposals, approvals, leases, reservations, and durable operations. The console uses a same-origin API/SSE proxy and displays evidence, tool traces, adapter identity, and separate execution/verification results.

The worker reads fixed health, logs, metrics, and deployment tools. A deterministic evidence gate—not model confidence—decides proposal eligibility. The executor accepts a persisted operation ID, revalidates authoritative scope and approval, and requests a fixed desired-state switch. The default stack publishes neither the executor nor the mutation listener; no container mounts a Docker socket.

Staging binds a fixed `tenant-api-staging` profile, probes authenticated tenant business behavior and dependencies independently, and uses a separate control PostgreSQL database to preserve incident state during workload outages.

## Workflow

```text
detected → investigating → awaiting_approval → recovering → verifying → resolved
                 │                 │                          │
              escalated         rejected                recovery_failed
```

1. Deduplicate the alert, claim a durable lease, and collect bounded real evidence.
2. Validate incident epoch, current revision/generation, functional failure, and the known-good predecessor. Unsupported diagnoses escalate.
3. Require operator approval of the exact proposal digest, service, revisions, generation, and five-minute TTL.
4. Reserve the deployment and execute the persisted operation. Reconcile the exact durable operation after interruption or ambiguous responses rather than blindly repeating it.
5. Resolve only after **three consecutive functional successes, two seconds apart within 30 seconds**, with matching deployment identity. Execution alone is not recovery.

## Safety controls

Implemented controls and regression tests exercise the following boundaries; they are not an absolute security guarantee:

- Closed service/revision/destination sets; no arbitrary model-supplied URLs, commands, paths, or container identifiers.
- Persisted server-enforced investigation limits: 12 tool calls and 120 seconds.
- Approval freshness/scope validation at the mutation boundary, transactional reservations, and stale-lease refusal.
- Staging dependency refusal at proposal and execution time, followed by sustained verification.
- Bounded payloads, recursive secret redaction at persistence boundaries, inert untrusted-text rendering, and a restrictive console CSP.
- Bearer-authenticated writes, browser-origin checks, loopback bindings, and an in-memory console token rather than browser storage.
- Missing runtime model credentials escalate; they never silently select scripted inference.

See [security notes](docs/security.md), [adversarial regressions](docs/adversarial-repair.md), and [staging repair limitations](docs/staging-repair-round3.md).

## Run the demo

Requires Docker Engine with Compose, Python 3.11+, `uv`, and a bash-compatible shell. Host frontend verification also needs Node.js 22+. Run commands from the repository root.

Generate distinct secrets into the gitignored `.env` without printing them. This refuses to overwrite an existing configuration:

```bash
uv run python - <<'PY'
from pathlib import Path
import secrets
config = Path(".env.example").read_text()
for placeholder in ("replace-with-local-password", "replace-with-local-internal-token", "replace-with-local-operator-token"):
    config = config.replace(placeholder, secrets.token_hex(32))
with Path(".env").open("x") as output:
    output.write(config)
PY
docker compose -p incident-recovery config -q
docker compose -p incident-recovery -f compose.yaml -f compose.investigation.yaml up --build -d --wait
```

The explicit override enables **`scripted:demo`**. Traffic, observations, approval, rollback, and verification are real; investigation decisions are deterministic scripts.

Open **http://127.0.0.1:18083** and enter the generated `OPERATOR_TOKEN` through your local editor/secret-handling workflow, without printing it into logs or terminal output. The console keeps it in memory for that tab.

1. Inject a demo fault and submit an alert from the console.
2. Inspect the labeled investigation, evidence, and proposal.
3. Approve the exact proposal or reject it; rollback requires approval.
4. Watch execution and sustained verification separately; successful recovery reaches `resolved`.

Default loopback ports: gateway `18080`, API `18082`, console `18083`, PostgreSQL `15432`. The control port is exposed only by the test override.

```bash
# Restore default adapter behavior; absent credentials, investigations escalate.
docker compose -p incident-recovery up -d --wait
# Stop this project, retaining its database volume.
docker compose -p incident-recovery down
```

The optional demo OpenAI-compatible adapter uses `MODEL_BASE_URL`, `MODEL_NAME`, and `MODEL_API_KEY`, separate from coding-tool credentials. Configuration is not evidence of successful live evaluation.

## Reproduce isolated staging

Staging requires external **public upstream source** for `tenant-api-platform` at commit `a6f715aac1d4e46b2ef30e12fb42d4719672f7f5`. Vendor trees and the archive are not committed here. Obtain a checkout containing that exact commit, then materialize an isolated snapshot:

```bash
uv run python scripts/staging_env.py
uv run python scripts/staging_env.py --control
uv run python scripts/staging_source.py --source-repo <upstream-checkout> --sha a6f715aac1d4e46b2ef30e12fb42d4719672f7f5
uv run python scripts/staging_fault.py
uv run python scripts/staging_verify.py
```

Alternatively supply the pinned archive specified by `staging/source-manifest.json` and run `scripts/staging_source.py` without `--source-repo`. That path validates the archive hash and embedded commit, not an independent upstream provenance audit.

Setup scripts generate separate gitignored workload/control secrets without printing values and probe loopback ports. The faulty revision is an explicitly injected patch in an isolated copy, not a claimed upstream regression. See [staging setup](docs/staging-readiness.md) and [recovery reproduction](docs/staging-recovery.md).

## Verification and evidence

**Run verification serially.** Drivers mutate shared deployment state, apply Compose overrides, inject faults, and restore stacks. Do not run demo, staging, or evaluation drivers concurrently against the same projects.

```bash
uv sync
npm --prefix frontend ci
uv run playwright install chromium
uv run python scripts/verify.py --docker --ui
uv run python scripts/staging_verify.py
```

Drivers record command output and distinguish passed, failed, and blocked checks. Test overrides expose extra control surfaces; restoration is included in the gates. `--skip-build --skip-demo` is an iteration shortcut, not full verification.

The latest independent full staging report provided for this repository is `.hermes/evidence/hermes-round3-frozen/report.json`, captured at **`ffa8a3f` with a clean tree**:

| Evidence slice | Recorded result |
| --- | --- |
| Full staging driver | 17 checks, 0 failures |
| Offline staging suite | 226 passed; baseline executed separately |
| Real authenticated baseline | 25 checks passed |
| Real injected-fault recovery and dependency refusal | 20 checks passed |
| Scripted evaluation | 12 cases passed: 2 recoveries, 10 refusals |
| Demo regression | Full `verify.py --docker --ui` passed |
| Live staging evaluation | 12 blocked, 0 executed, 0 provider requests |

The blocked-path gate passed refusal assertions; **live investigation safety and utility were not established**. Staging currently blocks live execution, so adding credentials alone does not make the batch live. Scripted results demonstrate orchestration, not model reasoning quality.

These results are revision-scoped evidence, **not a final clean adversarial verdict or production certification**. See [staging evidence](docs/staging-evidence.md) and [readiness gates](docs/staging-readiness.md). A [sanitized machine-readable summary](docs/evidence/staging-ffa8a3f.json) is committed for inspection; raw generated reports and logs remain local and are absent from a fresh clone.

## Limitations

- Local Docker and fixed workloads only; no general-purpose remediation or autonomous production recovery authorization.
- Operator/internal tokens are shared local secrets, not per-user identity, RBAC, or production credential management. The host and Docker administrator remain trusted.
- External dependencies can change between the final observation and mutation. Execution-time checks reduce but do not eliminate that race; post-action verification can fail.
- Idempotent desired-state changes plus exact operation reconciliation do not claim exactly-once physical side effects.
- Redaction/rendering tests cover defined cases, not perfect data-loss prevention or every adversarial input.
- Reproduction depends on pinned upstream source and build dependencies. Port probing does not reserve ports until containers bind them.
