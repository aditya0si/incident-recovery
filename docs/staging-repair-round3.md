# Staging repair round 3 — status-write attestation and duplicate JSON keys

Scope: the isolated tenant-staging control plane (`feat/incident-recovery`).
This document records the two round-3 reproduced defects, the fix for each, and
the *actual* verification evidence, separating isolated-mock tests from real
PostgreSQL proof.  No live provider call was made, no credential was used, and
the serial staging driver was **not** re-run (its writer was already active).
This is **not** a production-readiness claim.

## Disposition summary

| # | Defect | Fix | Evidence |
|---|--------|-----|----------|
| 1 | The final dependency attestation ran *before* the awaited `set_operation_status(OPERATION_EXECUTING)` write; a dependency turning unhealthy during that write was not re-observed, so the switch still ran and was recorded executed | every controllable awaited admission/status write now completes first, and the bounded fresh attestation runs *last*, immediately before the switch; missing/raising/stale checks still fail closed | real-PostgreSQL executor tests (status-write flip, consumption flip, attestation error, healthy allow, happy/replay) |
| 2 | `json.loads` silently keeps the **last** duplicate key, so a completed valid ledger with `billing_refused:true` followed by a trailing `billing_refused:false` loaded as not-refused and `admit_smoke` succeeded | the durable ledger reader parses with a strict `object_pairs_hook` that refuses a duplicate key at **every** object level (root and nested), preserves the original file bytes, and fails closed with `ProviderPolicyError` | isolated ledger tests (root latch, nested counters, nested usage, v2 migration, unique-key control) |

## 1. Final attestation after the executing-status write

`RecoveryExecutor.execute` performs the bounded fresh dependency attestation
**twice**: once before the approval is consumed (so an already-unhealthy workload
refuses without consuming the approval), and once **after** the approval has been
consumed **and** after the awaited `set_operation_status(OPERATION_EXECUTING)`
write, immediately before the switch.  Round 2 moved the second check after
consumption but *before* the executing-status write; the reproduced status-write
flip turned the dependency unhealthy during that write, which the pre-write check
could not see, so the switch ran and was recorded executed.

The fix reorders the mutation boundary so that *every* controllable awaited
admission/status operation — approval consumption and the executing-status write
— completes before the final observation.  A missing, raising, or unhealthy
attestation still fails closed (`dependencies_unhealthy`), the approval stays
consumed, and the operation is recorded failed.  A healthy path is unchanged and
still executes and records the rollback.

Evidence (real PostgreSQL, `tests/integration/test_approvals.py`):

- `test_executor_rechecks_dependencies_after_status_write_before_switch` — the
  dependency is healthy for the pre-admission check and turns unhealthy during
  the awaited executing-status write ⇒ operation failed, **no switch call**,
  revision unchanged, approval consumed by the admission step.
- `test_executor_rechecks_dependencies_after_admission_before_switch` — the
  round-2 consumption flip still refuses (`calls == 2`, no switch).
- `test_executor_fails_closed_when_a_dependency_attestation_errors` — a raising
  attestation is never healthy; no switch, revision unchanged.
- `test_executor_dependency_recheck_allows_rollback_when_dependencies_healthy`
  and `test_executor_rolls_back_broken_to_healthy` — the healthy path still
  executes; `test_consumed_approval_cannot_authorize_second_operation` covers the
  replay/idempotent path.

**Honest limit (residual external TOCTOU).** Dependency health is an external
property observed over the network; it cannot be sampled atomically with the
gateway mutation.  This fix additionally closes the *controllable* status-write
window, but a dependency change that happens **after the final observation** can
still allow the switch.  That residual change is expected to surface as a failed
post-action functional verification (the sustained three-check verification), not
as a false success.  There is an unavoidable external race between the last
observation and the mutation itself; it is not eliminated.

## 2. Duplicate JSON keys fail closed at every object level

`JsonBudgetLedger._read` previously used plain `json.loads`, which for a
duplicated object key keeps the last value.  A completed valid ledger that latched
`billing_refused: true` and then carried a trailing `"billing_refused": false`
therefore loaded as *not* refused, and a subsequent `admit_smoke` succeeded —
silently clearing a durable safety latch.

The reader now parses with an `object_pairs_hook` that raises
`ProviderPolicyError("provider_budget_ledger_duplicate_key")` as soon as any key
repeats within a single JSON object.  Because the hook is applied to every JSON
object, a duplicate anywhere — the root latch, a nested `turns`/`attempts`/
`input_chars` counter map, or a nested `usage` entry — is refused.  The existing
record is never rewritten by a rejected read, so the original bytes are preserved
and the failure is fail-closed (the ledger cannot be constructed over a
duplicate-key file).  This is scoped to the durable ledger reader; it does not
claim that every JSON file in the project previously tolerated duplicates.

Evidence (isolated, `tests/staging/test_provider_budget.py`):

- `test_duplicate_root_billing_refused_latch_cannot_be_cleared` — a latched
  `billing_refused:true` with a trailing duplicate `false` is rejected and the
  original bytes are unchanged.
- `test_duplicate_nested_counter_key_is_rejected` — a duplicate key inside
  `turns` is rejected.
- `test_duplicate_nested_usage_key_is_rejected` — a duplicate key inside a
  `usage` entry is rejected.
- `test_duplicate_key_in_migratable_v2_ledger_is_rejected` — the strict reader
  also guards the v1/v2 migration path.
- Control: `test_unique_key_ledger_still_loads_and_retains_the_latch` (plus the
  existing `test_valid_current_ledger_loads_and_retains_usage` and
  `test_supported_v2_ledger_migrates_and_retains_usage`) prove a duplicate-free
  record — current or migratable — still loads and retains its counters.

## Actual verification results

- Backend (isolated): `uv run pytest tests/unit tests/staging -q` →
  **324 passed, 1 skipped** (the skip is the declared opt-in Docker baseline).
- Integration (real PostgreSQL): `uv run pytest tests/integration -q` →
  **85 passed**.
- Frontend: `npx vitest run` → **31 passed** (5 files).

Each new regression test was confirmed to fail against the pre-fix source and
pass after the fix (targeted TDD run), then the fix was restored.

## Residual blocked / not-established

- The serial `staging_verify.py` driver and the full/compose staging driver were
  **not** re-run in this round, because the parent driver may still be writing.
  The round-3 proof is the targeted isolated and real-PostgreSQL suites above.
- **Live provider inference remains blocked** (Go runtime eligibility for the
  non-coding incident-investigation workload is unresolved); no live call was
  made and no credential was used.
- External dependency health is **not** atomically observable; see the honest
  limit in section 1.
- This is **not** a production-readiness claim.
