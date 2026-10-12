# Staging repair round 2 — transport budgets and dependency checks

Scope: the isolated tenant-staging control plane (`feat/incident-recovery`).
This document records the round-2 reproduced defects, the fix for each, and the
*actual* verification evidence, separating isolated-mock tests from real
PostgreSQL proof.  No live provider call was made and no credential was used.

## Disposition summary

| # | Defect | Fix | Evidence |
|---|--------|-----|----------|
| 1 | One `admit_smoke` permitted three successive `next_step(None)` transports (`smoke_calls=1`, `turns=3`, `attempts=3`) | smoke admission is a single-use, atomically-consumed permission; distinct `max_smoke_turns=1` / `max_smoke_attempts=1`; smoke is never retried | ledger + mock-transport tests, cross-instance test |
| 2 | A billing refusal latched by another ledger instance *between* retries was not seen, so the retry still reached the transport | billing latch + admission + attempt budget are re-checked at **every attempt inside the transport slot**; the transport slot also enforces concurrency 1 **cross-process** | mock-transport test + **real two-process** serialization test |
| 3 | An existing ledger of `null` / `{}`, or with negative/oversized counters, silently reset the allowance | an existing ledger is strictly validated (schema/scope/type/duplicates/unknown fields/bounds); only a missing file initializes a new batch; supported v1/v2 records migrate while retaining usage | isolated validation tests (original file unchanged after rejection) |
| 4 | The execution-time dependency check ran only *before* approval consumption; a dependency failing during the awaited admission still let the switch run and be recorded executed | the bounded fresh attestation is repeated **after admission and immediately before the mutation**, failing closed on a missing/raising/stale/negative check | real-PostgreSQL executor tests + real staging executor wiring |

## 1. Single-use smoke admission

`JsonBudgetLedger.admit_smoke` now records a one-shot `smoke_pending` permission
alongside the capped `smoke_calls` counter.  The adapter consumes it exactly once
via an atomic `consume_smoke` (inside the ledger's cross-process transaction)
before transport; a second consumption — in the same instance, another instance,
or a restarted process over the same file — is refused.  Smoke turns and attempts
have their own limits of 1, and a smoke call is never retried automatically
(`max_retries` is forced to 0 for the smoke context).

Evidence (isolated, mock transport, zero real calls):
`test_smoke_admission_is_single_use`, `test_smoke_consume_before_admit_is_refused`,
`test_smoke_turns_and_attempts_are_capped_at_one`,
`test_one_admitted_smoke_permits_exactly_one_transport` (one admission, three
attempts ⇒ one transport, `turns["__smoke__"] == 1`, `attempts["__smoke__"] == 1`),
`test_consumed_smoke_permission_is_not_reusable_across_instances`,
`test_smoke_is_never_retried`.

## 2. Per-attempt latch/admission/budget recheck under a cross-process transport lock

`OpenAICompatibleAdapter.next_step` wraps every attempt in
`StagingProviderPolicy.transport_slot`: an in-process `asyncio` lock plus a
separate cross-process file lock (`provider_budget.json.transport.lock`), held
for the whole request.  *Inside* that slot the adapter re-checks the durable
billing latch, the incident admission, and the attempt budget, then posts.  A
`402` latched by another instance during the sleep between attempts is therefore
observed before the retry can reach the transport.

The transport lock is a different file from the ledger mutation lock, so holding
it across the network request cannot deadlock the ledger transaction; the OS
releases it if the holder crashes (no orphaned sentinel).

Evidence (isolated, mock transport): `test_billing_latch_between_attempts_refuses_before_second_request`
(one request, then a refusal raised).
Evidence (real OS processes): `test_multiprocess_transport_is_serialized` starts
two separate Python processes whose mock transports each sleep; the recorded
enter/exit windows never overlap, proving cross-process serialization.

**Honest limit.** An already-in-flight provider call is not cancellable
retroactively: a refusal latched *after* the request has left the process cannot
un-send that request.  It only guarantees no *further* request is sent.

## 3. Fail-closed ledger validation (no silent reset)

`JsonBudgetLedger._read` now distinguishes a **missing** file (a deliberate new
batch) from an **existing** file, which is strictly validated: an unknown or
missing schema, a wrong scope, a non-object (`null`, list), a missing/extra
field, a bool-as-int, a negative or oversized counter, a duplicate admission, or
an unsupported active investigation all raise `ProviderPolicyError`.  The
existing file is never overwritten by a rejected read.  Supported v1/v2 records
are migrated to the current schema **retaining every counter and usage value**;
new fields default conservatively (never granting a permission).  Any other
schema is refused and requires deliberate operator recovery.

Evidence (isolated):
`test_valid_current_ledger_loads_and_retains_usage`,
`test_supported_v2_ledger_migrates_and_retains_usage`,
`test_corrupt_existing_ledger_fails_closed_without_overwrite` (parametrized over
`null`, `{}`, `[]`, truncated JSON, negative/bool/huge counters, wrong scope,
duplicate admissions, unknown field, unsupported schema, negative turn, non-bool
latch — each asserting the original file bytes are unchanged), and
`test_missing_ledger_initializes_a_new_batch_and_can_admit`.

## 4. Dependency recheck after admission, immediately before the mutation

`RecoveryExecutor.execute` now performs the bounded fresh dependency attestation
**twice**: once before the approval is consumed (so an already-unhealthy workload
refuses without consuming the approval) and once **after** consumption,
immediately before the switch.  This closes the reproduced consumption-flip
window: a dependency that turns unhealthy while the approval is being consumed
(an awaited, network/DB round-trip) still refuses, and the switch is never
invoked or recorded executed.  A raising/missing attestation fails closed.

The isolated staging executor now builds a real `StagingDependencyProbe` (its own
PostgreSQL/Redis TCP reachability) from `SERVICE_PROFILE=staging`, and the
`staging_recovery` driver supplies the same observer-backed check, so the
mutation boundary has an authoritative, best-effort fresh attestation.  The demo
executor (profile `demo`) keeps its unchanged, check-free behaviour.

Evidence (real PostgreSQL): `test_executor_rechecks_dependencies_after_admission_before_switch`
(the check returns healthy then unhealthy ⇒ operation failed, **no switch call**,
revision unchanged, approval consumed by the admission step),
`test_executor_fails_closed_when_a_dependency_attestation_errors`, and the
existing refuse/allow tests.

**Honest limit (residual external TOCTOU).** Dependency health is an external
property observed over the network; it cannot be sampled atomically with the
gateway mutation.  This fix is a *timestamped best-effort observation* plus a
conservative pre-action re-check.  A dependency change that happens *after the
last observation* can still allow the switch; that residual change is expected to
surface as a failed post-action functional verification (the sustained
three-check verification), not as a false success.

## Actual verification results

- Backend: `uv run pytest tests/unit tests/staging -q` → **319 passed, 1 skipped**
  (the skip is the declared opt-in Docker baseline).
- Integration (real PostgreSQL): `uv run pytest tests/integration -q` →
  **84 passed**.
- Frontend: `npx vitest run` → **31 passed** (5 files); `npm run build` → passed.
- Serial driver: `uv run python scripts/staging_verify.py --evidence-dir
  .hermes/evidence/staging-repair-round2` → **17 passed, 0 failed, 0 blocked**
  (exit 0); `staging_integration` passed (offline suite 221 passed, real baseline
  25/25, real recovery 20/20, scripted evaluation 12/12), `demo_regression`
  passed, `environment_restore` passed, `live_readiness` blocked (12 blocked /
  0 executed / `safety_ok: null`), `provider_blocked` blocked.  Both stacks were
  restored healthy.

## Residual blocked / not-established

- **Live provider inference remains blocked.**  Go runtime eligibility for the
  non-coding incident-investigation workload is unresolved, so the live batch
  makes zero provider requests, executes zero cases, and claims no accuracy or
  cost (`safety_ok: null`, never a vacuous `true`).
- **External dependency health is not atomically observable**; see the honest
  limit in section 4.
- This is **not** a production-readiness claim.
