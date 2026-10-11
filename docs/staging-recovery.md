# Staging Recovery — Injected Fault and Approved Recovery (Task 3)

Scope: **Task 3 only**. This document records the real, isolated staging
recovery: a genuine faulty revision of the pinned tenant API, real authenticated
tenant observations, a fixed service binding, and an operator-approved traffic
rollback with independent sustained verification. It is not a production
certification, and it does not claim a live paid-provider run (the runtime gate
remains **blocked**).

The Task 1 baseline remains in `docs/staging-readiness.md`; this document is
additive and does not change the demo stack or the pinned pristine vendor
snapshot.

## What was implemented

A narrow staging adapter and an isolated control plane, all bound to the fixed
service `tenant-api-staging` and the closed revision set
`tenant-api-healthy-a6f715a` / `tenant-api-faulty-a6f715a`:

- `src/incident_recovery/service_profile.py` — the only place a service identity
  and its fixed revision→destination map are defined (`demo` default, `staging`).
  `SERVICE_PROFILE` selects a profile and **fails closed** on anything else.
- `src/incident_recovery/staging/contracts.py` — fixed staging contracts, a
  closed-revision `StagingSwitchRequest`, and `StagingObservation`.
- `src/incident_recovery/staging/observations.py` — allowlisted observations:
  an **authenticated tenant business request** through the stable gateway, a
  **direct dependency check** independent of the active API's behaviour,
  gateway-captured real request logs/metrics, and deployment history. The tenant
  token is held by the adapter and never placed in evidence or model context.
- `src/incident_recovery/staging/workload.py` — `TenantStagingAdapter`
  (observe / verify / recover) and the shared-interface `StagingToolRunner`; a
  clearly-labelled `scripted:tenant-api-staging` adapter identity.
- `src/incident_recovery/staging/gateway.py` — the stable **traffic gateway**
  (routes real `/v1` requests to the active binary, stamps
  `X-Deployment-Revision`/`X-Deployment-Generation`) and the staging **control
  switch** (`StagingSwitchRequest` only).
- `src/incident_recovery/staging/control.py` / `control_worker.py` — the
  isolated staging operator API and durable recovery worker, reusing the
  reviewed repository/gateway/agent/executor/worker classes with the staging
  profile.

The reviewed demo components were parameterized *minimally* and keep their demo
defaults: `DeploymentStore(profile=...)`, `evaluate_switch(service_id=...)`,
`IncidentRepository.approve_incident(service_id=...)` /
`get_deployment_snapshot(service_id=...)`, `InvestigationAgent(service_id=...)`,
and a dependency-refusal rule in the proposal gate. The default demo contracts
(`SwitchRequest`, `FaultRequest`, `AlertCreate`) are unchanged.

## Injected fault provenance

The fault is a real change to an authenticated business endpoint handler in the
actual tenant API binary (the tenant-scoped project listing), applied **only** to
an isolated build copy:

| Field | Value |
| --- | --- |
| Patch | `staging/faults/broken-revision.patch` |
| Patch SHA-256 | `644c758d35d4edccf62db2200c5511fac79bda518232ea2b8e13cbae0bc6036f` |
| Target | `internal/httpx/handlers_projects.go` (`handleListProjects`) |
| Isolated copy | `staging/vendor/tenant-api-faulty` (gitignored) |
| Materializer | `scripts/staging_fault.py` |

The pristine snapshot `staging/vendor/tenant-api-platform` and the parent-supplied
archive are never written to. The faulty image is transparently labelled
(`injected-fault`) and the change is not claimed to be an upstream regression.

## Isolation and service binding

- Dedicated control PostgreSQL server (`control-postgres`) with its own volume,
  separate from the workload PostgreSQL, so a workload dependency outage does not
  take the incident store with it.
- Every incident, proposal, approval, reservation, operation, and deployment row
  is bound to `tenant-api-staging` explicitly; a foreign (demo) reservation or
  approval is refused by the staging switch and vice versa.
- GPG/Redis ports, the gateway, the control API, and the console are loopback
  only; no Docker socket is mounted anywhere; the model never receives a
  destination, credential, SQL, container id, or shell command.

## Reproduction (real recovery)

```bash
# 1. Workload + control-plane configuration (generated, gitignored).
uv run python scripts/staging_env.py
uv run python scripts/staging_env.py --control

# 2. Materialize the pinned snapshot and the isolated faulty copy.
uv run python scripts/staging_source.py
uv run python scripts/staging_fault.py

# 3. Run the real recovery driver: healthy -> faulty -> scripted investigation
#    -> operator-harness approval -> traffic rollback -> sustained verification,
#    plus a real workload dependency outage that must escalate.
uv run python scripts/staging_recovery.py
```

The driver publishes the control/workload data endpoints on loopback only, via
`staging/compose.recovery.yaml` (a driver-only override), and is gated behind the
`recovery` Compose profile so a default `up` is byte-for-byte the Task 1 stack.

Unit / integration tests:

```bash
uv run pytest tests/unit tests/staging -q          # 207 passed
uv run pytest tests/integration -q                  # 78 passed (includes staging control)
```

## Verified recovery (real containers)

Observed by `scripts/staging_recovery.py` (20/20 checks passed, evidence under
`.hermes/evidence/staging-task3`):

- real authenticated tenant business health is `200` on the healthy binary;
- the fault switch routes traffic to the real faulty binary, whose authenticated
  business request returns `500`;
- the scripted investigation produced an evidence-supported rollback proposal
  bound to the staging service;
- the operator-harness approval (`operator-harness (scripted/test)`) bound the
  staging service, target, revision and TTL;
- the rollback executed, and the incident reached `resolved` only after three
  consecutive authenticated business successes two seconds apart within 30s
  (`tenant-api-healthy-a6f715a`);
- a real workload PostgreSQL/Redis outage was observed independently, escalated,
  and admitted **no** executable rollback; restoring dependencies recovered
  health;
- a duplicate/interrupted claim resumed the same investigation without resetting
  the run budget.

## Live provider status: BLOCKED

The runtime model gate remains **blocked** (see Task 2 and
`docs/staging-readiness.md`): no live provider call is made by this work. The
investigation ran through the explicitly labelled `scripted:tenant-api-staging`
adapter. This is not a live-provider compatibility claim.

## Remaining blockers / out of scope

- Live paid-provider eligibility and bounded live investigation (Task 2).
- Predeclared 12-case evaluation: implemented in Task 4 and recorded in
  `docs/staging-evidence.md` (scripted 12/12 passed, live blocked with 0 calls).
- Independent full verification (Task 5).
