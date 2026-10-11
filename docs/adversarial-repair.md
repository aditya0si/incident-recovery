# Adversarial repair — findings and dispositions

This document records the seven independently reproduced defects from the final
adversarial repair brief, the code change made for each, and the regression test
that proves the defect is closed. Every RED/GREEN result below was produced by
running the named test against the pre-fix source (`git stash` of the source
changes only) and then against the fixed source; no count or status is invented.

All repairs preserve the original requirements and do not weaken any gate.

## Summary

| # | Severity | Defect | Regression test(s) |
| --- | --- | --- | --- |
| 1 | BLOCKER | Gateway switch captured admission time before the row lock; an approval expiring during the lock wait was still applied | `test_switch_expiry_after_lock_wait_cannot_mutate` |
| 2 | MAJOR | Crash between the durable switch and `record_execution` made a retry reject an operation that had actually applied | `test_switch_replays_exact_durable_operation_after_expiry`, `test_executor_reconciles_durable_operation_on_resume`, `test_executor_reconciles_when_switch_response_rejected` |
| 3 | MAJOR | `_bounded_json` never shrank a single-element list, returning an oversized payload | `test_single_huge_entry_is_byte_bounded` and the other `test_tools.py` bound tests |
| 4 | MAJOR | Tool observations retained nested/list secret-shaped keys | `test_tool_runner_observe_metrics_redacts_nested_secrets`, `test_redact_structure_redacts_secret_keys_recursively`, `test_repository_redacts_nested_secrets_at_persistence` |
| 5 | MAJOR | Verification counted a probe that completed after the 30s deadline as success | `test_slow_probe_cannot_resolve_after_deadline`, `test_slow_real_client_never_resolves_beyond_deadline` |
| 6 | MAJOR | Functional check blessed an independent snapshot / unrelated success instead of the health response's authoritative identity | `test_probe_rejects_health_identity_revision_mismatch` and four sibling identity tests |
| 7 | MINOR | The verify driver reported a skipped-only pytest run as `passed` | `test_pytest_gate_rejects_skipped_only_run`, `test_vitest_gate_rejects_zero_skipped_and_failing` |

## 1 — BLOCKER: admission time must be refreshed after lock waits

**Root cause.** `DeploymentStore.switch` computed `now = datetime.now(timezone.utc)`
before acquiring a pool connection and before the `SELECT ... FOR UPDATE` row
lock. `_recovery_authorized` then compared the approval `expires_at` against that
stale time, so an approval that expired while the switch waited on the lock was
still admitted and applied.

**Fix.** The admission time is now read from the database with
`SELECT clock_timestamp()` *after* the row lock is acquired and immediately before
the mutation decision. `clock_timestamp()` advances during a transaction, so it
reflects the true time after the wait (unlike `now()`/`transaction_start`, which
is fixed at transaction start).

**Real PostgreSQL contention regression.**
`tests/integration/test_resilience.py::test_switch_expiry_after_lock_wait_cannot_mutate`
holds the `deployment_state` row lock from a competing connection, starts the
switch (which blocks), waits past the 1s approval TTL, releases the lock, and
asserts the switch is `unauthorized` and `deployment_state` is unchanged.

- RED (pre-fix): `AssertionError: assert 'applied' == 'unauthorized'`
- GREEN (fixed): `1 passed`

## 2 — MAJOR: crash-window reconciliation of the exact durable operation

**Root cause.** If the gateway switch committed durably but the executor died
before `record_execution`, the persisted operation stayed `executing` with an
active reservation and a durable `deployment_operations` row, while the approval
had expired. A retry hit the fresh-admission checks first and was refused
(`unauthorized` / `approval_expired`) even though the mutation had happened.

**Fix.**
- `DeploymentStore.switch` now checks for an exact durable replay **before** any
  fresh-admission check. Replay requires an exact
  operation/service/expected-generation/target/scope match (`_exact_replay`) and
  never mutates. The durable operation record now stores the reservation `scope`
  (migration 6) so scope is part of the exact match.
- `RecoveryExecutor` reconciles an exact durable operation on resume (before
  admission) and after a rejected/ambiguous switch response, and only when the
  record exactly matches the operation (service, expected generation, target,
  `recovery` scope). A merely-matching active revision can never manufacture
  success.

**Regressions (real PostgreSQL persisted state, test-side interruption only).**

- `test_switch_replays_exact_durable_operation_after_expiry`
  - RED: `AssertionError: assert 'unauthorized' == 'replayed'`
  - GREEN: `1 passed`
- `test_executor_reconciles_durable_operation_on_resume`
  - RED: `AssertionError: assert 'failed' == 'executed'`
  - GREEN: `1 passed`
- `test_executor_reconciles_when_switch_response_rejected`
  - RED: `AssertionError: assert 'failed' == 'executed'`
  - GREEN: `1 passed`
- `test_switch_replay_requires_exact_scope` (guard: a scope mismatch is neither
  `replayed` nor `applied`).

## 3 — MAJOR: guaranteed byte-bounded tool observations

**Root cause.** `_bounded_json` shrank the largest list by halving it. A
single-element list (`value[:max(1, len//2)]`) never shrank, so
`{'lines': [{'message': 'x'*20000}]}` returned 20043 bytes, over the 8192-byte
cap.

**Fix.** `_bounded_json` now performs a deterministic, provably-terminating
recursive fit: it truncates strings, drops list/mapping entries, and marks the
result `truncated`, with a final hard guarantee that the canonical JSON encoding
never exceeds the budget (for any budget that can hold `{}`). It handles nested
lists/dicts, multibyte characters, and tiny budgets, and preserves useful
non-secret fields.

**Evidence.**

- RED (direct reproduction on pre-fix source):
  `finding3: bounded=False size=20043 cap=8192`
- GREEN: `tests/unit/test_tools.py` (8 bound tests) pass, including
  `test_single_huge_entry_is_byte_bounded`, `test_nested_structures_are_byte_bounded`,
  `test_multibyte_characters_are_byte_bounded`, `test_tiny_budgets_are_never_oversized`,
  and `test_exact_budget_is_respected`.

## 4 — MAJOR: recursive secret redaction at every persistence boundary

**Root cause.** `_observe_metrics` only redacted top-level and one level of
nested string values, so nested dictionaries, lists, and secret-shaped *keys*
were retained. `_observe_logs` flattened nested entries to strings before
redaction.

**Fix.** A recursive `redact_structure` replaces the value of any secret-shaped
key (`password`, `api_key`/`api-key`, `token`, `authorization`, `credential`, ...,
case-insensitive) with `[REDACTED]`, walks lists and nested mappings, and applies
`redact_secrets` to string values/keys (bearer tokens, `key=value` assignments,
configured secret values). It is applied in `ToolRunner.observe` and at the
repository persistence boundaries (incidents, evidence, investigation steps,
events, operation results, verification, failures). Provider adapter errors
already carry no credential material.

**Evidence.**

- RED (direct reproduction on pre-fix source): `finding4: redacted=False`
- GREEN:
  - `tests/unit/test_tools.py`: `test_redact_structure_redacts_secret_keys_recursively`,
    `test_redact_structure_preserves_nonsecret_controls`,
    `test_redact_structure_covers_case_and_key_variants`,
    `test_redact_structure_redacts_assignment_text_in_values`,
    `test_tool_runner_observe_metrics_redacts_nested_secrets`,
    `test_tool_runner_observe_logs_redacts_nested_secret_keys`,
    `test_provider_errors_do_not_leak_api_key`
  - `tests/integration/test_resilience.py::test_repository_redacts_nested_secrets_at_persistence`
- Synthetic sentinels only; no real credentials are printed.

## 5 — MAJOR: strict elapsed verification deadline

**Root cause.** `RecoveryVerifier.verify` only checked the deadline before and
after sleeps, not after a probe. Three 9s checks plus two 2s waits (31s) could
therefore report `verified` despite the 30s deadline.

**Fix.** The verifier now: refuses to start a probe once the deadline has passed;
bounds each probe with `asyncio.wait_for(..., timeout=remaining)`; and applies
strict elapsed semantics after each probe, so a probe that completes after the
deadline can never contribute to the streak. A timed-out probe is recorded as a
failed `deadline_exceeded` check. The result is never `resolved` beyond the
deadline.

**Regressions.**

- `test_slow_probe_cannot_resolve_after_deadline` (injected clock, 9s checks)
  - RED: `AssertionError: assert True is False`
  - GREEN: `1 passed`
- `test_slow_real_client_never_resolves_beyond_deadline` (real httpx client +
  slow `MockTransport`, tiny deadline) — fails closed within the deadline.
- `test_slow_probe_within_deadline_can_still_verify` (a genuinely fast recovery
  still verifies).

## 6 — MAJOR: authoritative functional identity

**Root cause.** `GatewayFunctionalProbe.check` trusted the `/snapshot` revision
and then accepted any `200`/`status=pass` from `/api/health`, ignoring the
gateway's authoritative `X-Deployment-Revision`/`X-Deployment-Generation`
headers. A health response from a different revision/generation was blessed.

**Fix.** The probe now requires the health response's
`X-Deployment-Revision` to equal the intended revision and
`X-Deployment-Generation` to be a valid integer equal to the snapshot
generation, requires the body to be a JSON object whose `revision` (when
present) matches, and fails closed on missing or malformed identity. It no
longer blesses an independent snapshot or an unrelated success.

**Regressions.** `test_probe_rejects_health_identity_revision_mismatch`,
`test_probe_rejects_missing_health_identity_headers`,
`test_probe_rejects_malformed_generation_header`,
`test_probe_rejects_generation_inconsistent_with_snapshot`,
`test_probe_rejects_body_revision_mismatch` — all RED with
`AssertionError: assert True is False`, all GREEN after the fix. Existing probe
tests were updated to emit the real identity headers (fidelity, not circular
assertions).

## 7 — MINOR: required test suites must execute tests

**Root cause.** `scripts/verify.py::_run_check` treated any zero exit code as a
pass. A subprocess that exited 0 with `5 skipped in 0.01s` was reported as
`passed` with `{'skipped': 5}`.

**Fix.** Required pytest and vitest checks are now gated: zero executed tests,
skipped-only runs, and failing/error runs are `failed`; a real passing run
reports its executed count. Optional checks (the live-model check) are exempt.

**Regressions.**

- `test_pytest_gate_rejects_skipped_only_run` (and zero/failed/mixed cases)
  - RED: `AttributeError: module 'verify_runner_under_test' has no attribute '_pytest_gate'`
  - GREEN: `7 passed` in `tests/unit/test_verify_runner.py`
- `test_vitest_gate_rejects_zero_skipped_and_failing`

## Remaining limits and non-claims

- This is a local Docker demo, not production software.
- Exactly-once physical side effects are not claimed: recovery remains an
  idempotent desired-state change plus exact operation-id reconciliation.
- The live investigation model is not configured here; the optional live check
  is reported `blocked`, never as success.
- The contention regression uses a bounded real-time lock wait (~1.4s) and the
  injected-clock probe tests simulate slow probes; the real-client control bounds
  a real slow HTTP probe.
