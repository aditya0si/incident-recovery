# Staging final repair — safety and evaluation integrity

Scope: the isolated tenant-staging control plane (`feat/incident-recovery`,
HEAD `cd4d01a`).  This document records the seven reproduced safety/evidence
defects, the fix for each, and the *actual* verification evidence, clearly
separating isolated-mock tests from real PostgreSQL / real Docker proof.  No
live provider call was made and no credential was used.

## Disposition summary

| # | Defect | Fix | Evidence |
|---|--------|-----|----------|
| 1 | Proposal gate only vetoed dependency outages that the model *cited* | `agent.evaluate_diagnosis` vetoes over **all** current-epoch dependency evidence (contradiction/missing fail closed for a dependency-attested workload); `RecoveryExecutor` rechecks dependencies at execution time | mock gate tests + real-PostgreSQL executor test |
| 2 | `JsonBudgetLedger` cached per instance under an in-process lock only | cross-process exclusive file lock + reload-under-lock transaction (no instance cache) | two-instance test + **real two-process race** |
| 3 | `next_step(None)` reached transport with no admission | authoritative `admit_smoke`/`admit_investigation` required before every turn/attempt; billing refusal latched durably | mock-transport tests |
| 4 | A failed cleanup still produced a green case/metrics/driver | cleanup is a required part of `case_passed`, `safety_ok`, scripted status, and the verify driver's restore gate | pure metrics tests + driver restore-gate tests |
| 5 | A store used for one run mode could be reused for another | immutable run header binds manifest + mode + adapter + execution identity; cross-mode reuse refused before any action | run-store tests + driver live-mode rejection test |
| 6 | The stored manifest-hash string was trusted | stored manifest is rebuilt and its hash **recomputed** from content; content compared to the approved manifest on resume/read | tamper tests |
| 7 | `reject_incident` ignored the service binding | service is bound in the same conditional `UPDATE` as the state; foreign incident stays unchanged (404) | real-PostgreSQL tests (demo + staging profiles) |

## 1. Dependency veto over all current-epoch evidence

`src/incident_recovery/agent.py` now derives the dependency signal from every
health observation in the incident/epoch, independent of what the model cited.
A later (or uncited) outage vetoes a rollback that cites only an earlier healthy
sample; contradictory dependency observations and (for a dependency-attested
workload) missing attestation fail closed.  The demo workload, which omits
`dependencies_ok`, is unchanged.

Execution-time recheck: `RecoveryExecutor` accepts an optional
`dependency_check`; a deployment that became dependency-unhealthy after approval
is failed with `dependencies_unhealthy` **before** the approval is consumed, so
no rollback runs and the approval remains intact.

Evidence (mock gate): `tests/staging/test_staging_gate.py` (uncited-outage,
contradiction, order-independence, missing-attestation, healthy control).
Evidence (real PostgreSQL): `tests/integration/test_approvals.py::
test_executor_dependency_recheck_refuses_rollback_when_dependencies_fail` and
`..._allows_rollback_when_dependencies_healthy` prove the real durable operation
is not switched when dependencies fail.

## 2. Cross-process atomic budget ledger

`JsonBudgetLedger` performs every mutation inside an exclusive OS file lock
(`flock` on POSIX, `msvcrt.locking` on Windows), re-reads the JSON state from
disk, applies the mutation, and atomically replaces the file.  There is no
per-instance cache and no module-global counter; a crashed holder releases the
lock automatically.  Unknown provider usage/cost is still recorded as `None`,
and an unreadable existing ledger refuses to load.

Evidence (isolated): `test_two_preloaded_instances_do_not_both_admit`,
`test_two_instances_share_a_single_batch_cap`, `test_billing_latch_persists_across_instances`,
`test_malformed_existing_ledger_refuses_to_load`, and the cap/turn/attempt/output
restart tests.
Evidence (real OS processes): `test_multiprocess_concurrent_admission_is_serialized`
starts two separate Python processes that race to admit with
`max_investigations=1`; exactly one is admitted and the on-disk state retains
that single winner.

## 3. Admission before transport and durable billing latch

`OpenAICompatibleAdapter.next_step` now refuses, before any accounting or
transport, unless the smoke call or the incident is authoritatively admitted
(`check_smoke_admission`/`check_investigation_admission`).  A revoked/completed
admission refuses subsequent turns.  A provider billing refusal is latched
durably for the batch, so the next call — and a restarted process over the same
ledger — refuses before transport.

Evidence (mock transport, zero real calls): unadmitted smoke/investigation make
zero requests and zero attempts; one admitted smoke makes exactly one request;
revoked admission refuses; a second call after a 402 makes zero requests; a
fresh adapter over the same durable path refuses after a latched billing refusal.

## 4. Cleanup failures fail closed

`case_passed` requires a completed cleanup; `compute_metrics` reports
`cleanup_failures`/`cleanup_established`/`cleanup_ok` and folds cleanup into
`safety_ok`; the scripted status helper refuses a green verdict without completed
cleanup and a restored environment; the verify driver records **every** restore
command and exit code as a required `environment_restore` gate and returns
nonzero if any restore failed.  The original cause and the cleanup cause are both
preserved (`detail` and `cleanup_detail`).

Evidence (isolated): metrics/case tests in `test_evaluation_manifest.py`,
`scripted_status` tests in `test_staging_evaluate.py`, restore-gate and
`overall_exit_code` tests in `test_staging_verify.py`.
Evidence (real driver): the serial `staging_verify` run below reports
`cleanup_failures=0`, `environment_restore: passed`, `restore_demo_default: exit 0`,
`restore_staging_default: exit 0`.

## 5. Run header binds mode / adapter / execution identity

`RunStore.begin` writes an immutable header (`run.json`) binding the manifest
content, run mode (`scripted`/`live`), adapter identity, and execution identity.
A store already used for one mode (or with a different adapter/execution
identity) is refused before any case is written or report is emitted.  Every case
record is checked against the header mode on write and read, and a fresh live
batch is still 12 blocked / 0 executed with `safety_ok=None`.

Evidence (isolated): run-store tests in `test_evaluation_manifest.py` and the
driver test `test_live_mode_rejects_a_store_already_used_for_scripted`, which
proves a scripted store is refused and no report/case is written.

## 6. Stored manifest hash is recomputed, never trusted

`RunStore.stored_manifest` rebuilds the manifest from the stored case content and
recomputes its hash, refusing a stale stored hash string.  On every resume/read
the stored content is compared to the approved manifest and each case's expected
definitions are verified.  Records are created with `O_CREAT|O_EXCL` so an
append-only write can never overwrite via a TOCTOU race.

Evidence (isolated): `test_tampered_stored_manifest_hash_is_detected`,
`test_resume_refuses_a_content_tampered_manifest_even_with_updated_hash`,
`test_read_case_rejects_a_tampered_case_definition`,
`test_existing_records_rejects_a_foreign_manifest`, plus the existing
append-only/overwrite tests.

## 7. Reject binds the service

`IncidentRepository.reject_incident` takes a `service_id` and enforces it in the
same conditional `UPDATE` as the state; an incident belonging to another service
is not disclosed or mutated (`NotFound`).  The demo endpoint passes the demo
service and the staging endpoint passes the staging service, mirroring approve.

Evidence (real PostgreSQL): `tests/integration/test_approvals.py::
test_reject_refuses_a_foreign_incident_and_leaves_it_unchanged` (404, state
unchanged) and `tests/integration/test_staging_control.py::
test_reject_binds_the_staging_service_and_refuses_foreign`.

## Actual verification results

Backend (isolated + real PostgreSQL):

- `uv run pytest tests/unit tests/staging tests/integration -q` →
  **377 passed, 1 skipped** (the skip is the declared opt-in Docker baseline,
  run separately by the driver).

Frontend:

- `npx vitest run` → **31 passed** (5 files).
- `npm run build` (`tsc --noEmit && vite build`) → **passed**.

Serial driver (`uv run python scripts/staging_verify.py --skip-build
--evidence-dir .hermes/evidence/staging-final-repair`):

- `staging_integration`: **passed** (source materialize, fault prepare,
  offline tests 197 passed + 1 opt-in skip run separately, real E2E baseline,
  real recovery, real scripted evaluation 12/12, live blocked 12/0/0).
- `demo_regression`: **passed** (`verify.py --docker --ui`).
- `environment_restore`: **passed** (`restore_demo_default: exit 0`,
  `restore_staging_default: exit 0`).
- `live_readiness`: **blocked** (12 blocked / 0 executed / 0 provider requests;
  `safety_ok=None`).
- totals: **17 passed, 0 failed, 0 blocked**; exit **0**.

## Residual blocked / not-established

- **Live provider inference is legitimately blocked.**  Go runtime eligibility
  for the non-coding incident-investigation workload is unresolved, so the live
  batch makes zero provider requests, executes zero cases, and claims no
  accuracy or cost.  `safety_ok` is `null`, never a vacuous `true`.
- **The real Docker E2E baseline is an explicit opt-in test.**  It is not
  counted as an offline pass; the driver invokes it separately as a required
  check.
- **No live stack corruption** was performed: the controlled cleanup failure and
  the foreign-service rejection are exercised against isolated schemas and the
  serial driver leaves both stacks healthy in a `finally` block.
- This is **not** a production-readiness claim.
