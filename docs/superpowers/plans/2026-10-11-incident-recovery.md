# Incident Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Demonstrate real local broken-deployment investigation and approval-gated, durably recorded rollback.

**Architecture:** FastAPI API and worker share PostgreSQL workflow records. A stable Python HTTP gateway routes traffic to predefined healthy/broken demo containers; a privileged internal executor performs fixed deployment switching and reconciles it with database state. React displays snapshots and resumable SSE events.

**Tech Stack:** Python, FastAPI, Pydantic, SQLAlchemy, PostgreSQL, pytest, React, TypeScript, Vite, Playwright, Docker Compose. Lock dependencies in implementation rather than invent version numbers here.

**Spec:** docs/superpowers/specs/2026-10-11-incident-recovery-design.md

## Global Constraints
- OpenCode model opencode-go/deepseek-v4.1-flash writes production code and tests; Hermes writes briefs, reviews diffs, and independently executes verification.
- No publishing or cloud deployment is authorized.
- Host-facing ports bind to 127.0.0.1. Executor exposes no host port; only executor receives Docker socket.
- Default bounds: at most 12 tool calls and 120 seconds per investigation; configured values cannot exceed those maxima in v1.
- Approval TTL is five minutes.
- Resolution requires three consecutive successful functional checks separated by two seconds, within a 30-second verification deadline.
- Missing model credentials escalate; scripted adapters remain explicitly labeled and never silently replace live inference.
- Only fixed project incident-recovery and service demo-api are actionable; rollback targets only its recorded known-good predecessor.
- No arbitrary shell, URLs, paths, image names, or container identifiers in agent tool parameters.
- Every milestone includes RED → GREEN test execution, a scoped commit, and independent Hermes verification before the next coding brief.

## Review Focus
- Approval races with a new fault injection: serialize deployment changes and reject stale approvals (Tasks 2–3).
- Executor response loss after switching: reconcile desired revision using the same persisted operation ID (Task 3).
- Reconnected SSE client: backfill ordered IDs without losing events (Tasks 2 and 5).
- Poisoned or oversized logs: bounded untrusted evidence must not broaden permissions or leak credentials (Task 4).
- Model unavailable or invalid JSON: visible escalation, no disguised scripted success (Tasks 4–5).

## File Map
- compose.yaml, .env.example, .gitignore: local stack and safe configuration.
- pyproject.toml, uv.lock, Dockerfile: reproducible Python environment.
- src/incident_recovery/demo.py: real healthy/broken HTTP workload and structured observations.
- src/incident_recovery/gateway.py: stable request routing and fixed internal revision switch.
- src/incident_recovery/contracts.py: validated public/internal payloads and state enums.
- src/incident_recovery/db.py, models.py, repository.py: schema, transactions, leases, append-only evidence/events.
- src/incident_recovery/api.py: operator-authenticated routes and SSE.
- src/incident_recovery/executor.py: approval enforcement and scoped idempotent rollback.
- src/incident_recovery/worker.py, verification.py: recovery orchestration and sustained checks.
- src/incident_recovery/agent.py, tools.py, model_adapter.py: bounded investigation and configurable live adapter.
- frontend/src/: console, API client, event reducer, incident/evidence/approval components.
- tests/unit/, tests/integration/, tests/e2e/: focused, real PostgreSQL, Docker and UI checks.
- scripts/verify.py, docs/security.md, docs/evidence.md, README.md: reproducible verification and honest claims.

## Interface Contracts
Define these in contracts.py before use; later briefs must reconcile signatures with the independently verified tree.
- Revision = Literal['healthy-v1', 'broken-v2']; service ID = 'demo-api'.
- DeploymentSnapshot: service_id, revision, generation:int, activated_at:datetime, predecessor:Revision|None.
- Evidence: id:UUID, incident_id:UUID, source:str, observed_at:datetime, payload:dict.
- Proposal: incident_id, service_id, expected_generation, current_revision, target_revision, evidence_ids:list[UUID], digest:str.
- Operation: id:UUID, incident_id, approval_id, status, target_revision, result:dict|None.
- Gateway client: snapshot() -> DeploymentSnapshot; switch(expected_generation:int, target:Revision, operation_id:UUID) -> DeploymentSnapshot. Fixed service only, authenticated internal requests.
- Repository: ingest_alert(key:str, service_id:str) -> Incident; append_evidence(incident_id:UUID, source:str, payload:dict) -> Evidence; claim_next(worker_id:str, lease_seconds:int) -> Incident|None; append_event(incident_id:UUID, kind:str, payload:dict) -> Event.
- Executor: execute(operation_id:UUID) -> Operation; caller cannot supply action arguments overriding persisted proposal.
- ModelAdapter: next_step(context:InvestigationContext) -> ToolRequest|Diagnosis; scripted implementations are test-only or explicitly selected demo mode.
- Tool runner: collect(request:ToolRequest, incident_id:UUID) -> Evidence.

### Task 1: Real demo deployment slice
**Files:** compose.yaml; Python packaging/Docker files; demo.py; gateway.py; contracts.py; tests/unit/test_gateway.py; tests/e2e/test_deployment.py.
- [ ] Write tests proving healthy functional HTTP succeeds, broken deployment returns a genuine failing functional result, generation increments on switch, stale generations reject, and duplicate operation IDs do not switch twice.
- [ ] Run `uv run pytest tests/unit/test_gateway.py -v`; record real failure before implementation.
- [ ] Implement gateway using PostgreSQL-backed active revision and generation. Proxy requests only to fixed Compose DNS targets. Switch is an internal authenticated compare-and-set transaction; no caller-supplied destination. Demo health must reflect functional failure, not merely process liveness. Keep public demo and internal switch routes separated by Compose network and credential.
- [ ] Run unit tests, `docker compose -p incident-recovery config`, and `docker compose -p incident-recovery up --build -d --wait`.
- [ ] Run `uv run pytest tests/e2e/test_deployment.py -v` against real containers; assert healthy → broken → healthy functional traffic and revision read-back. No fabricated deployment responses in this suite.
- [ ] Commit `feat: add real demo deployment and gateway`; Hermes repeats checks and inspects network/socket exposure.

### Task 2: Durable incidents and operator control
**Files:** db.py; models.py; repository.py; api.py; tests/integration/test_incidents.py; tests/integration/test_events.py.
**Interfaces:** produces repository contracts above plus authenticated POST /alerts, GET /incidents, GET /incidents/{id}, GET /incidents/{id}/events SSE, POST /demo/faults.
- [ ] Write tests asserting concurrent duplicate alert keys yield one incident, illegal state transitions fail, evidence remains immutable, lease expiry allows takeover, and SSE Last-Event-ID returns ordered subsequent events.
- [ ] Write auth/origin tests: unauthenticated write rejected, untrusted Origin rejected even with a token, tokens absent from event payloads. Use explicit localhost Origin allowlist and Authorization bearer token, not ambient cookie authentication.
- [ ] Run `uv run pytest tests/integration/test_incidents.py tests/integration/test_events.py -v` against test PostgreSQL; record RED.
- [ ] Implement transactional repository/state transitions and schema bootstrap with version tracking; persist timestamps in UTC. Token-protected fault injection calls fixed internal gateway switch and records deployment history atomically/reconciliably. Pending recovery prevents competing fault changes.
- [ ] Repeat tests including process restart and persistence read-back; commit `feat: persist incident workflow and event stream`. Hermes independently repeats against isolated test database.

### Task 3: Approval-gated rollback and recovery verification
**Files:** executor.py; worker.py; verification.py; API approval/rejection routes; tests/integration/test_approvals.py; tests/e2e/test_recovery.py.
**Interfaces:** POST /incidents/{id}/approve accepts proposal digest, not arbitrary action fields; POST /incidents/{id}/reject; executor execute(operation_id).
- [ ] Write tests asserting no action before approval, exact digest/service/generation binding, 300-second expiry, rejection, concurrent duplicate approvals, replay refusal, and stale revision refusal.
- [ ] Write crash/response-loss tests asserting a resumed operation reconciles actual revision before retry and creates one logical rollback; use test-side network/process interruption, not production-only debug callbacks.
- [ ] Write verification tests asserting three successes separated by at least two seconds resolve only with matching revision; failed checks reset the success streak and exceeding 30 seconds yields recovery_failed. Use injected clocks/clients for unit tests and real elapsed checks in Docker E2E.
- [ ] Run `uv run pytest tests/integration/test_approvals.py tests/unit/test_verification.py -v`; capture RED.
- [ ] Implement authenticated internal executor loading authoritative approval/proposal by operation ID. Persist claim/consumption and serialize deployment changes; enforce expiry and preconditions before mutation. Use fixed desired-state switching and durable reconciliation. Do not mount socket elsewhere; no dynamic shell dispatch or Docker resource selection.
- [ ] Run tests and real Docker E2E for approved rollback, rejection, stale/expired approval, interrupted recovery, unsuccessful recovery. Failure injection stays test-side or the explicit demo surface.
- [ ] Commit `feat: gate rollback and verify sustained recovery`; Hermes independently verifies action/read-back and audits executor boundary.

### Task 4: Bounded evidence-backed investigation
**Files:** agent.py; tools.py; model_adapter.py; worker investigation stage; tests/unit/test_agent.py; tests/integration/test_investigation.py.
**Interfaces:** next_step and collect above. ToolRequest uses four fixed tool names health, logs, metrics, deployments and no arbitrary destination. Diagnosis contains symptoms, candidate cause, uncertainty, evidence IDs, and optional proposed rollback.
- [ ] Write tests for 12-call and 120-second limits, oversized payloads, unsupported tools/arguments, nonexistent evidence IDs, malicious log instructions, invalid model JSON, missing credentials, provider timeout, and insufficient evidence escalation.
- [ ] Assert policy refuses rollback unless observations show current functional failure and the proposed target is the recorded known-good predecessor. Enforce evidence IDs belong to this incident and current investigation epoch; confidence alone is irrelevant.
- [ ] Run `uv run pytest tests/unit/test_agent.py -v`; capture RED.
- [ ] Implement schema-validated bounded loop, tool deadlines, bounded retries counted toward time budget, secret redaction, and explicit adapter identity on all runs. Collect actual demo observations and persist tool request/result traces.
- [ ] Implement configurable OpenAI-compatible adapter using runtime-only environment credentials. Verify its actual provider contract before a live run; do not extract or reuse coding CLI secrets implicitly. If credentials are unavailable, preserve implementation and record the live-run blocker.
- [ ] Run scripted adversarial tests and real-container investigation with explicit scripted label. Run a live investigation only after a real provider smoke test; never report scripted results as live evidence.
- [ ] Commit `feat: investigate incidents with bounded agent tools`; Hermes repeats tests and reviews permission boundaries.

### Task 5: Incident console
**Files:** frontend package/lock/Docker files; frontend/src/api.ts; events.ts; App.tsx; components/IncidentTimeline.tsx, EvidencePanel.tsx, ApprovalPanel.tsx; frontend/tests/; tests/e2e/test_console.py.
**Interfaces:** consumes Tasks 2–4 routes and event records; no mock data in normal UI.
- [ ] Write UI tests asserting ordered SSE dedup/backfill, visible scripted/live identity, evidence linking, approval digest binding, disabled in-flight controls, expired/stale approval errors, and escalated/model-unavailable display.
- [ ] Run `npm --prefix frontend test -- --run`; capture RED.
- [ ] Implement purposeful operational console: incident queue, status, deployment revision, evidence-linked diagnosis, bounded trace details, proposal/approve/reject, and verification timeline. Keep operator token in memory, not committed, URL, logs, or localStorage. Configure same-origin API proxy and local-only access.
- [ ] Run frontend unit tests/build and Playwright real browser against Compose; exercise actual approval through UI and recovery_failed/escalated views. Check reconnect behavior, keyboard controls, loading/error states, and narrow viewport.
- [ ] Commit `feat: add incident response console`; Hermes independently runs browser probes.

### Task 6: Whole-stack adversarial gates and delivery
**Files:** scripts/verify.py; tests/e2e/test_resilience.py; docs/security.md; docs/evidence.md; README.md; dependency locks and CI workflow if local verification commands can be faithfully reproduced.
- [ ] Add failing tests for restart during investigation/recovery, duplicate alerts under contention, response loss, changed deployment, injected logs, unauthorized executor operations, and recovery failure. Refuse widening production debug surfaces to enable tests.
- [ ] Run focused failures, delegate fixes, and independently repeat exact adversarial payloads. Review privileged executor honesty: Docker socket grants broad host power even if the application exposes a narrow API.
- [ ] Implement a verification runner producing machine-readable results with passed/failed/blocked status, adapter identity, command exit codes, and source revision. No invented totals, relaxed assertions, or silent skipped live-model checks.
- [ ] Execute `uv run pytest tests/unit tests/integration -v`, frontend tests/build, `docker compose -p incident-recovery config`, and real Docker/API/Playwright E2E via `uv run python scripts/verify.py --docker --ui`. Runner must return nonzero on required failures and distinguish optional blocked live checks.
- [ ] Run fresh read-only adversarial review after writer exits; scope any repair brief to reproduced issues plus regressions. Hermes reviews complete diff and reruns high-impact checks after fixes.
- [ ] Document exact launch, token setup, demo, teardown without deleting unrelated volumes, model configuration, trust boundaries, and measured evidence. Preserve local credentials only in gitignored files. Do not publish.
- [ ] Commit `test: verify incident recovery end to end`; report actual results and any blocked live-model check, not a blanket completion claim.

## Execution Handoff
User-selected method is preserved: one OpenCode DeepSeek writer per scoped milestone, Hermes orchestrates and reviews. Written-plan review is required before implementation. After approval, bootstrap isolated execution using the applicable execution skill; author each repository-local brief just in time against verified predecessor outputs. Start Task 1 only, and gate advancement on independent real execution.

## Self-review
Spec acceptance 1–2 maps to Task 1; 3 and 10 to Task 4; 4–7 and 9 to Task 3; 8 to Tasks 2, 3, and 6; 11 to Task 5; 12 to every milestone and Task 6. All five Review Focus cases have explicit owning tests. Runtime-model credentials remain a possible live-demo blocker, not permission to fabricate or silently substitute. The gateway fulfills real revision switching without pretending a Docker socket mount makes the executor sandboxed.
