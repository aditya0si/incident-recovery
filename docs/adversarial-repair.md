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

# Round 2 — second adversarial repair (generalized gaps)

The parent independently reproduced four further gaps against the committed
`c2932f0` source. Each was fixed with RED→GREEN tests, not instance-only regex
patches. Every RED result below was produced by running the named new test
against the pre-fix source (the test existed before the fix); no count or status
is invented.

| # | Severity | Defect | Regression test(s) |
| --- | --- | --- | --- |
| 1 | MAJOR | Redaction missed quoted keys/values and JSON-encoded secret lines, leaking trailing words | `test_redact_secrets_redacts_json_encoded_line`, `test_redact_secrets_redacts_quoted_key_and_value_variants`, `test_redact_secrets_redacts_quoted_value_with_spaces`, `test_redact_secrets_redacts_nested_json_and_lists`, `test_redact_secrets_redacts_escaped_quoted_value`, `test_redact_secrets_redacts_header_and_scheme_forms`, `test_tool_runner_logs_redacts_*` |
| 2 | MAJOR | Admission clock was sampled before the awaited approval `SELECT ... JOIN`; an approval expiring during that wait was still applied (3 writes) | `test_expiry_enforced_after_awaited_approval_select` |
| 3 | MAJOR | `last_error` text columns bypassed redaction while structured results were cleaned | `test_set_operation_status_redacts_last_error`, `test_fail_recovery_redacts_error_and_event`, `test_set_investigation_run_state_redacts_last_error` |
| 4 | MINOR | The required vitest gate accepted `Tests 1 passed | 2 todo (3)` as success | `test_vitest_gate_rejects_todo_tests`, `test_vitest_gate_rejects_unexecuted_total_mismatch`, `test_pytest_gate_rejects_deselected_tests` |

## 1 — MAJOR: generalized secret-text redaction

**Root cause.** `redact_secrets` required a secret-shaped key immediately followed
by `:`/`=`. A JSON-encoded log line `json.dumps({'password': 'SYNTHETIC_SENTINEL'})`
has a closing quote between the key and the colon, so it never matched. A quoted
value with spaces (`password="two word synthetic secret"`) matched only the first
word, leaking the trailing words.

**Fix.** `redact_secrets` now recognises bearer/basic/token authorization schemes,
and `key` / `"key"` assignments for secret-shaped names followed by a quoted value
(spaces and backslash escapes allowed) or a bare value, including JSON-encoded
text and nested JSON/list payloads embedded in a string. Quoted values keep their
quotes so redacted JSON stays well-formed. `redact_structure` is still applied
first in `ToolRunner.observe`, so redaction precedes truncation and a truncated
tail can never contain a secret. This is documented as best-effort pattern
redaction, **not** a DLP guarantee.

**Evidence.**

- RED (pre-fix): `8 failed, 1 passed`; representative
  `AssertionError` showing `'two' is contained here: ... REDACTED] two word value`.
- GREEN: `tests/unit/test_tools.py` `24 passed`, including the exact
  `json.dumps({'password': ...})` reproduction.

## 2 — MAJOR: expiry enforced after the awaited approval SELECT

**Root cause.** `DeploymentStore.switch` sampled `clock_timestamp()` *before*
`_recovery_authorized` ran its awaited `recovery_operations ⋈ approvals ⋈ proposals`
query. If that query blocked (e.g. behind an `ACCESS EXCLUSIVE` lock or a slow
connection), the loaded approval was compared against a pre-wait clock and an
approval that expired during the wait was still applied.

**Fix.** `_recovery_authorized` now selects `clock_timestamp()` in the *same*
query as the approval row, so the admission time is evaluated only after every
lock wait the SELECT incurs, and compares the loaded `expires_at` against it.
The `applied` mutation for `recovery` scope additionally carries an atomic
`EXISTS (... a.expires_at > clock_timestamp())` predicate, so no further awaited
round-trip can write an expired approval into `deployment_state`. Exact durable
replay is still checked first and is unaffected.

**Real PostgreSQL contention regression.** `test_expiry_enforced_after_awaited_approval_select`
holds `ACCESS EXCLUSIVE` on `approvals` from a competing connection, starts the
switch (which blocks inside the approval SELECT), waits past the 1s TTL, releases
the lock, and asserts the switch is `unauthorized` and neither
`deployment_operations` nor `deployment_history` gained a row.

- RED (pre-fix): `AssertionError: assert 'applied' == 'unauthorized'`
- GREEN (fixed): `1 passed`; full `tests/integration` `73 passed`.

## 3 — MAJOR: redact every error/trace text write sink

**Root cause.** `set_operation_status` passed `last_error` as a raw SQL
parameter; `fail_recovery` passed `error` raw to the `last_error` column and
`set_investigation_run_state` passed `last_error` raw. The structured `result`
dictionary was redacted, but the text columns were not, so a synthetic
`password=SYNTHETIC_SENTINEL` survived in the durable row.

**Fix.** A shared repository helper `_redact_text` runs `redact_secrets` on every
textual error column (`recovery_operations.last_error`,
`investigation_runs.last_error`, `fail_recovery` error). Event payloads already
flow through `redact_structure`, which also redacts strings. Provider adapter
errors remain fixed identifier strings.

**Evidence.**

- RED (pre-fix): `assert 'SYNTHETIC_SENTINEL' not in 'token=SYNTHETIC_SENTINEL'`
  and the sibling operation/failure assertions failed (`3 failed`).
- GREEN: `3 passed`; benign control `last_error == "switch_unauthorized"` is
  preserved unchanged.

## 4 — MINOR: required test gates must reject todo/unexecuted tests

**Root cause.** `_test_gate` only rejected zero-test, skipped, and failed runs.
Vitest reports planned-but-unimplemented tests as `todo`, which the gate ignored:
`Tests 1 passed | 2 todo (3)` was reported as success with
`{'passed': 1, 'todo': 2}`.

**Fix.** `_vitest_counts` also parses the total (`(3)`) and `_test_gate` fails on
any `todo` count or a passed+failed+skipped+todo total mismatch. `_pytest_counts`
now recognises `deselected`, and `_pytest_gate` fails on deselected/unexecuted
tests as well as skips. A genuinely clean `31 passed (31)` still passes.

**Evidence.**

- RED (pre-fix): `3 failed` (`test_vitest_gate_rejects_todo_tests`,
  `test_vitest_gate_rejects_unexecuted_total_mismatch`,
  `test_pytest_gate_rejects_deselected_tests`).
- GREEN: `tests/unit/test_verify_runner.py` `13 passed`.

# Round 3 — third adversarial repair (structural JSON containers, gate totals)

The parent independently reproduced two further gaps against the committed
`0dbe0b2` source and reran the reviewer probes. As before, every new test was
written first and run against the pre-fix source (RED), then against the fixed
source (GREEN); no count or status is invented and no test was relaxed.

| # | Severity | Defect | Regression test(s) |
| --- | --- | --- | --- |
| 1 | MAJOR | Redaction of JSON-encoded log/error text matched the single opening bracket of a container value, leaking every list/object element | `test_redact_secrets_redacts_json_list_valued_secret`, `test_redact_secrets_redacts_json_object_valued_secret`, `test_redact_secrets_redacts_nested_nonsensitive_containers`, `test_redact_secrets_redacts_json_fragment_with_prefix_and_suffix`, `test_redact_secrets_fails_closed_on_malformed_sensitive_container`, `test_redact_secrets_redacts_error_render_with_json_container`, `test_tool_runner_observe_logs_redacts_json_container_secret`, `test_set_investigation_run_state_redacts_json_container_last_error` |
| 2 | MINOR | Required test gates accepted `1 passed, 2 xfailed`, `xpassed`, and a malformed vitest `Tests 2 passed (1)` total | `test_pytest_gate_rejects_xfailed_tests`, `test_pytest_gate_rejects_xpassed_tests`, `test_vitest_gate_rejects_passed_exceeding_total` |

## 1 — MAJOR: structurally redact secret-bearing JSON containers

**Root cause.** The round-2 assignment pattern treated a container's opening
bracket as a bare value. `redact_secrets(json.dumps({'password': ['SYNTHETIC
alpha beta', 'SECOND_SENTINEL']}))` produced
`'{"password": [REDACTED]"SYNTHETIC alpha beta", "SECOND_SENTINEL"]}'`, leaking
both elements; the object-valued form
`{'password': {'value': 'SYNTHETIC alpha beta'}}` leaked identically. Native
dictionary redaction (`redact_structure`) already replaced the whole value, but
the JSON-*encoded string* path did not. The defect was proven at the real
`ToolRunner.observe(logs)` sink and at the
`repository.set_investigation_run_state` SQL `last_error` boundary.

**Fix (class, not instance).** Text redaction is now layered:

- `_redact_text` is a pure pattern/known-value pass (bearer/basic/token schemes,
  `key`/`"key"` assignments, configured values). It never parses JSON, so
  `redact_structure` can call it without a recursion cycle.
- `_redact_json_string` decodes a complete JSON object/array and runs it through
  `redact_structure` (which replaces a secret-shaped key's **entire** value,
  whatever its type). Text that is not one JSON document is scanned for complete
  embedded object fragments, which are redacted in place while surrounding
  prefixes/suffixes are preserved. Ordinary JSON with no secret-shaped field is
  returned byte-for-byte unchanged.
- A container that cannot be parsed safely is redacted conservatively to the end
  of the fragment by `_redact_text`, failing closed rather than leaking.

`redact_structure` now delegates string values to `_redact_json_string`, so the
same structural handling applies to native dictionaries and to JSON encoded
inside a string. This is documented as best-effort redaction, **not** a DLP
guarantee: it does not claim to defeat arbitrary obfuscation, and an
unterminated sensitive container is over-redacted to the fragment end.

**Evidence.**

- RED (pre-fix): the round-3 probe tests `7 failed, 3 passed`; representative
  `AssertionError` showing
  `'SYNTHETIC alpha beta' is contained here: ... EDACTED]\"SYNTHETIC alpha beta\", \"SECOND_SENTINEL\"]`.
  The `3 passed` are controls that assert preservation of ordinary JSON and
  unicode, which the old instance-only fix already satisfied.
- GREEN: `tests/unit/test_tools.py` `36 passed`; full `tests/unit` `98 passed`.
- Existing controls unchanged: ordinary JSON, quoted strings, escapes, nesting,
  unicode, and bounded output all still pass.

## 2 — MINOR: required gates must reject xfail/xpass and non-exact vitest totals

**Root cause.** `_pytest_gate` ignored `xfailed`/`xpassed`, so `1 passed, 2
xfailed` was `passed`. `_test_gate` used `passed + ... < total` (`>=`
acceptance), so a malformed `Tests 2 passed (1)` was `passed`. No required
category is optional in v1.

**Fix.** `_pytest_gate` fails on any `xfailed` or `xpassed` count (in addition to
failures, errors, skips, and deselected tests). `_test_gate` now requires the
executed statuses (`passed + failed + skipped + todo`) to equal the parsed total
**exactly**, failing on any over- or under-count.

**Evidence.**

- RED (pre-fix): `3 failed, 1 passed`
  (`test_pytest_gate_rejects_xfailed_tests`,
  `test_pytest_gate_rejects_xpassed_tests`,
  `test_vitest_gate_rejects_passed_exceeding_total`; the pass is the clean-total
  control).
- GREEN: `tests/unit/test_verify_runner.py` `18 passed`.

**Scope of this round.** Only the shared redaction module
(`src/incident_recovery/tools.py`), the verification driver gates
(`scripts/verify.py`), their tests, and this document changed. No existing
control or gate was weakened, and no real credential is used anywhere — all
sentinels are synthetic.

