# Security model and trust boundaries (Milestones 1–5)

## Network and credential boundaries

- Host-facing ports bind to `127.0.0.1` only.
- `gateway-control` and `executor` expose **no** host port; they are reachable
  only over the Compose internal network with the `INTERNAL_TOKEN` credential.
- The public `gateway` (proxy role) has no switch route. `POST /internal/switch`
  on the public listener returns 404.
- Operator writes (`/alerts`, `/demo/faults`, `/incidents/{id}/approve`,
  `/incidents/{id}/reject`) require a bearer operator token with a constant-time
  comparison, reject any `Origin` outside the explicit localhost allowlist, and
  never echo credentials into responses, events, or logs.
- No container is mounted with the Docker socket.

## Authoritative deployment mutation boundary

The gateway switch is the single authoritative mutation boundary. It runs in one
transaction that locks the `deployment_state` row and validates a persisted
`deployment_reservations` token before it may mutate anything:

- A partial unique index permits at most one **active** reservation per service,
  so a fault injection and a recovery can never both own the deployment. This
  closes the previous check-then-act race (`has_pending_recovery` followed by a
  network switch) because the reservation is created atomically *before* the
  switch and is the thing the switch validates.
- A switch whose `operation_id` does not match the active reservation (or whose
  scope/expected generation/target disagree) is refused with `unauthorized`.
- A `recovery` switch additionally re-loads the persisted operation, approval,
  and proposal and re-checks the fixed service, expected/current revision,
  generation, known-good target, five-minute TTL, and single consumption. The
  internal switch therefore cannot be used as an approval bypass by the API or
  the worker.

The API and worker never hold a database transaction across the HTTP call into
`gateway-control`, so they cannot deadlock with the control transaction.

## Least-privilege executor refinement (Milestone 3)

The original design reserved a privileged executor container that would receive
the Docker socket. Analysis of the actual required capability showed that
rollback is a **pure PostgreSQL desired-state change** (switch the active revision
between two predefined demo targets). It requires no Docker power at all.

Therefore:

- The executor accepts only a persisted `operation_id` over an authenticated
  internal channel; it rejects any additional/unsupported fields (schemas use
  `extra="forbid"`).
- The executor receives **no** Docker socket and exposes **no** host port. There
  is no ornamental privileged access.
- Commands are fixed argument-free desired-state changes; there is no dynamic
  shell dispatch and no caller-selected project, service, image, mount, command,
  or revision.
- Container **restart** capability (which would need Docker power) is deferred to
  a later milestone with its own acceptance gate.

This is an explicit limitation: the executor is trusted internal code, not a
sandbox, and it can only express the fixed rollback desired state.

## Response ambiguity and reconciliation

Exactly-once physical side effects are not claimed. After a network failure the
executor reconciles the durable `deployment_operations` record **by operation
id**; it never blind-repeats a switch and never infers success from a matching
revision alone, so an unrelated deployment change cannot manufacture success.
Idempotent desired-state changes plus operation-id reconciliation prevent a
duplicate logical rollback.

## Verification trust

Resolution is decided by independent sustained functional verification through
the public gateway (matching revision + functional health, three consecutive
successes two seconds apart within 30 seconds). An executor success response
alone never resolves an incident.

## Investigation trust boundary (Milestone 4)

The investigation agent is deliberately the least-privileged component:

- **Read-only, fixed tools.** Exactly four tools exist (`health`, `logs`,
  `metrics`, `deployments`). `ToolRequest` uses `extra="forbid"` and accepts only
  a tool name plus an optional bounded `lines` count, so model output can never
  carry a URL, filesystem path, container identifier, shell command, image,
  mount, or arbitrary destination. Tool results are size-bounded.
- **Untrusted observations.** Log and metric text is treated as data, never as
  instructions. Secret-shaped values are redacted before evidence is persisted,
  and the deterministic proposal gate refuses a proposal that cites
  prompt-injection content. The agent has no write tool and no shell.
- **No model authority.** A model diagnosis cannot authorize recovery. The
  deterministic gate independently requires observed functional failure,
  deployment evidence matching the authoritative revision/generation, evidence
  that belongs to the incident's current epoch, and the recorded known-good
  predecessor as the target. Unsupported conclusions, foreign/nonexistent/stale
  evidence, malformed provider JSON, provider unavailability, and budget
  exhaustion all escalate. There is no proposal-injection endpoint.
- **Bounded and durable.** Server-enforced maxima of 12 tool calls and 120
  seconds are persisted per investigation epoch, so a worker restart cannot reset
  the limits or duplicate a logical step trace. Per-provider deadlines and bounded
  retries count toward the budget.
- **Lease-guarded writes.** Evidence, step traces, proposals, and escalations are
  written only while the worker still owns the incident's lease for the current
  epoch; a stale owner writes nothing.
- **Separate runtime credentials.** The OpenAI-compatible adapter reads only
  `MODEL_BASE_URL` / `MODEL_NAME` / `MODEL_API_KEY` from the worker environment.
  It never reads OpenCode auth or Hermes secrets. Missing credentials fail closed
  to escalation; the `scripted:demo` adapter is enabled only by the explicit
  `INVESTIGATION_ADAPTER=scripted` opt-in and every run records its identity.

## Operator console boundary (Milestone 5)

- **Single browser origin.** The console is the only browser-facing origin
  (loopback `:18083`). nginx serves the static bundle and reverse-proxies exactly
  the operator API prefixes (`/incidents`, `/alerts`, `/demo`, `/deployment`,
  `/healthz`) to the internal `api` service. It does **not** proxy
  `gateway-control` or the `executor`; unknown paths return 404 rather than an
  `index.html` fallback, and the console holds no Docker socket.
- **Explicit origin allowlist.** The API's browser-origin allowlist is the fixed
  `ALLOWED_ORIGINS` value plus the loopback console origin. A write with any other
  `Origin` is refused with 403 even when a valid token is supplied, and all ports
  bind to `127.0.0.1` only.
- **Token in memory only.** The operator token is entered at runtime and held in
  an in-memory closure for the tab. It is never written to `localStorage`,
  `sessionStorage`, cookies, the URL, logs, screenshots, or build output, and it
  is sent only as an `Authorization: Bearer` header.
- **Inert untrusted rendering.** Persisted logs, model text, and evidence/model
  payloads are untrusted and rendered as text (React escaping); the console never
  uses `dangerouslySetInnerHTML`. A restrictive Content-Security-Policy
  (`script-src 'self'`, `frame-ancestors 'none'`, `base-uri 'none'`) plus
  `X-Content-Type-Options` / `X-Frame-Options` further blocks HTML/script
  injection and framing.
- **No new write surface.** The console adds only read-only API views
  (`GET /deployment` and the investigation identity/tool-trace fields on
  `GET /incidents/{id}`). Approve still binds the exact proposal digest and the
  server re-validates generation and TTL; there is no proposal-injection path, and
  the in-flight/stale/expired controls only disable client intent — the server
  refusal is authoritative.
