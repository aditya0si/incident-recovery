# Incident Investigation & Recovery — v1 Design

Status: design approved in conversation; written specification awaiting user review.

## Purpose and scope
Build a reproducible, local Docker portfolio system demonstrating evidence-backed agent investigation, approval-gated recovery, durable workflows, and independently verified outcomes. Hermes owns orchestration and review; OpenCode using opencode-go/deepseek-v4.1-flash owns production and test implementation. No publishing or cloud deployment is authorized.

The first milestone is one real end-to-end broken-deployment rollback. Dependency failures and resource-exhaustion scenarios are later milestones, not v1 acceptance requirements.

## Architecture
Docker Compose runs a React/TypeScript console, FastAPI control API, Python investigation worker, PostgreSQL, a restricted recovery executor, and demo service containers. Host-facing ports bind to 127.0.0.1. The application API, frontend, worker, and demo services never receive the Docker socket. The executor alone receives it and is treated as a privileged trusted component, not a security sandbox. It exposes no host port. Its API requires an internal credential and validates all requests against fixed project/service identifiers and operation schemas. Credentials are environment-provided and omitted from traces.

Demo deployment uses a stable gateway and a predefined healthy/broken version pair. An explicit fault-injection operation switches the active version to broken; rollback selects the known-good predecessor. Fault injection is restricted to this demo, separate from agent tools, and never described as a production control. Deployment history records revision and activation time. The precise gateway implementation belongs in the implementation plan; it must support real traffic switching and read-back verification.

PostgreSQL is the source of truth for incidents, immutable evidence records, deployment revisions, investigation steps, proposals, approvals, recovery operations, and events. The console obtains snapshots and streams incident events using SSE with reconnect/backfill by event ID.

## Investigation agent
The worker runs a bounded tool-calling loop through a configurable model adapter. Allowed tools read health, structured recent logs, service metrics, and deployment history for the fixed demo service. No arbitrary URLs, shell commands, filesystem paths, or container identifiers are accepted from model output. Tool input/output is schema-validated and size-limited. Log contents are untrusted data, not instructions. Each evidence record receives an ID, observation timestamp, source, and bounded payload.

A diagnosis identifies observed symptoms, candidate cause, uncertainty, and evidence IDs. A rollback proposal must reference actual recorded evidence and a known-good deployment predecessor. A deterministic policy gate independently checks proposal eligibility; model confidence alone never authorizes recovery. Unsupported conclusions, unavailable model credentials, exhausted step/time budgets, or insufficient evidence lead to explicit escalation. No automatic fixture fallback masquerades as live inference.

Default bounds: at most 12 tool calls and 120 seconds per investigation, with per-tool deadlines and bounded retries. These are configurable within server-enforced maximums. Provider credentials and the runtime investigation model are separate from the coding CLI credential. Tests may use explicitly labeled scripted adapters; a live-agent demo requires a separately successful real model call.

## Workflow and durability
States: detected, investigating, awaiting_approval, recovering, verifying, resolved, escalated, rejected, recovery_failed. State transitions use transactional conditional updates and append-only events. A duplicate alert key maps to the existing incident, not a second recovery. A worker lease with expiry permits restart recovery without concurrent ownership.

Approval records bind incident ID, proposal digest, fixed service ID, expected current revision, target revision, actor, creation time, and expiration. Approval TTL is five minutes. Changed proposals or deployment revisions invalidate approval. Rejection cannot execute an action. The API requires a local operator token for approval, rejection, fault injection, and other writes; permissive cross-origin writes are forbidden.

Recovery uses a persisted operation ID and executor idempotency record. Network ambiguity never triggers blind repeat execution: reconcile observed deployment state before retry. The executor revalidates approval scope and revision preconditions against authoritative persisted state before changing the deployment. A consumed approval cannot authorize another operation.

After restart the worker resumes from persisted state and reconciles outstanding operations. Exactly-once physical side effects are not claimed; idempotent desired-state changes plus reconciliation prevent duplicate logical rollback.

## Recovery and verification
V1 permits rollback only to the recorded known-good predecessor of the allowlisted demo service. Restart may be added later under its own acceptance gate. Executor commands use fixed argument arrays, never model-generated shell text. Requests for another Compose project, service, image, mount, command, or revision fail closed.

Verification checks both active deployment revision and functional HTTP behavior through the stable gateway. Resolution requires three consecutive successful functional checks separated by two seconds, within a 30-second verification deadline. Failure or ambiguous status becomes recovery_failed with evidence, never resolved merely because an executor returned success. The investigation and recovery timeline distinguishes proposed, approved, executed, verified, and failed actions.

## Interface and demo
Console shows incident list, status, evidence-linked diagnosis, actual tool traces, proposal/approval controls, deployment revision, and recovery verification results. It clearly marks scripted test runs versus live-model runs. All controls expose loading/error states and prevent accidental repeated submission. README documents prerequisites, Compose startup/shutdown, credential setup without embedding secrets, the fault injection demonstration, and limitations.

## Acceptance criteria
1. Compose builds and starts the real stack locally; readiness is checked from real output.
2. Functional requests succeed on healthy deployment and fail on the injected broken deployment.
3. Investigation records real observations and produces an evidence-linked rollback proposal through the selected adapter; a scripted adapter is explicitly labeled.
4. No recovery happens before approval; approval then causes real traffic to return to the known-good revision.
5. Resolution occurs only after revision read-back and sustained functional checks.
6. Duplicate alerts and duplicate approval requests do not create duplicate logical recovery.
7. Expired, mismatched, replayed, and stale-revision approvals are refused.
8. Restart during investigation or recovery resumes safely from PostgreSQL state.
9. Unsuccessful rollback/verification results in recovery_failed, not resolved.
10. Unsupported tool calls, injected log instructions, nonexistent evidence IDs, and out-of-scope executor requests are refused or escalated.
11. Console shows actual persisted events and evidence; end-to-end UI probes exercise approval and failure states.
12. Unit/integration tests and real Docker end-to-end checks are executed independently by Hermes. Reports distinguish passed, failed, and unexecuted checks; published counts come only from actual output.

## Delivery and non-goals
Repository: C:/Users/oliad/Desktop/incident-recovery. Ship application, Docker configuration, tests, architecture/security notes, and reproducible demo instructions. No Kubernetes, general-purpose shell agent, autonomous production recovery, broad multi-agent framework, fabricated monitoring data, automatic GitHub push, or public deployment. Local Docker and its executor trust boundary are explicit limitations.

## Build order
First establish the real healthy/broken gateway and observed rollback behavior. Then add persisted incident workflow and scoped approval/execution. Add the bounded model investigation adapter and console. Finish with recovery interruption tests, adversarial checks, and independently executed end-to-end evidence. Author milestone briefs just in time against the actual verified tree.
