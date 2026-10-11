# Verification evidence (Milestone 6 + adversarial repair)

This document records the commands that were actually executed, the observed
results, and the explicit blockers. It contains no projected or estimated
counts: every number below is copied from the machine-readable report produced by
the verification driver at `.hermes/evidence/verify/report.json` (logs alongside
it under `.hermes/evidence/verify/logs/`).

- **Source revision:** `436587b6654eb0bb115c8c2a7b33020245d5b95a`
  (`feat/incident-recovery`, clean working tree at run time)
- **Report generated:** `2026-10-11T18:56:16Z` → `2026-10-11T19:04:22Z` (UTC)
- **Host:** Windows, Python 3.14.5, Docker Engine 29.6.2, Compose v5.3.1,
  Node v26.7.0, npm 11.19.0

## Reproduce

```bash
# from the repository root, with the gitignored .env populated
uv run python scripts/verify.py --docker --ui
```

The driver exits non-zero if any *required* check fails or is blocked. Required
pytest and vitest checks are now gated: a zero-test, skipped-only, or
failing/collection-error run is reported `failed`, never `passed`. The driver
applies the test-only control override and the explicit scripted-investigation
override for the Docker E2E phase and restores the default stack in a `finally`
block even when a check fails. It never prints secrets: output is sanitized
against the values in `.env`, and Compose configuration is validated only with
`config -q`.

## Observed results

| Check | Command | Result | Counts |
| --- | --- | --- | --- |
| backend_unit | `uv run pytest tests/unit -q` | passed | 69 passed |
| frontend_install | `npm --prefix frontend ci` | passed | — |
| frontend_unit | `npm --prefix frontend test -- --run` | passed | 31 passed |
| frontend_build | `npm --prefix frontend run build` | passed | — |
| frontend_audit | `npm --prefix frontend audit --audit-level=high` | passed | no high/critical advisories |
| compose_config_default | `docker compose -p incident-recovery -f compose.yaml config -q` | passed | — |
| compose_config_overrides | `docker compose -p incident-recovery -f compose.yaml -f compose.test.yaml -f compose.investigation.yaml config -q` | passed | — |
| compose_up_default | `docker compose -p incident-recovery -f compose.yaml up --build -d --wait` | passed | — |
| backend_integration | `uv run pytest tests/integration -q` | passed | 69 passed |
| compose_up_overrides | override `up --build -d --wait` | passed | — |
| e2e_deployment | `uv run pytest tests/e2e/test_deployment.py -q` | passed | 4 passed |
| e2e_recovery | `uv run pytest tests/e2e/test_recovery.py -q` | passed | 3 passed |
| e2e_investigation | `uv run pytest tests/e2e/test_investigation.py -q` | passed | 1 passed |
| e2e_resilience | `uv run pytest tests/e2e/test_resilience.py -q` | passed | 9 passed |
| e2e_console | `uv run pytest tests/e2e/test_console.py -q` | passed | 5 passed (real Chromium) |
| compose_restore_default | default `up --build -d --wait` | passed | — |
| tracked_secret_scan | `git ls-files` + pattern scan | passed | 85 tracked files, no secret material |

Totals from the report: **19 checks passed, 0 failed, 0 blocked; required checks
OK.** That corresponds to 191 executed test cases
(138 backend, 31 frontend, 22 real Docker/browser E2E).

## Adversarial repair

The final adversarial repair closed seven independently reproduced defects. Each
one has a RED→GREEN regression test; the full findings, dispositions, and the
observed RED/GREEN outputs are in `docs/adversarial-repair.md`. In summary:

- **BLOCKER** — the gateway switch now refreshes the authoritative admission time
  with `clock_timestamp()` after the row lock, so an approval that expires during
  a lock wait cannot be applied (`test_switch_expiry_after_lock_wait_cannot_mutate`).
- **MAJOR** — an exact durable operation is replayed/reconciled before any
  fresh-admission check, closing the crash window between the durable switch and
  `record_execution` (`test_switch_replays_exact_durable_operation_after_expiry`,
  `test_executor_reconciles_durable_operation_on_resume`,
  `test_executor_reconciles_when_switch_response_rejected`).
- **MAJOR** — `_bounded_json` is now guaranteed byte-bounded for nested lists,
  single huge entries, multibyte values, and tiny budgets
  (`test_tools.py` bound tests).
- **MAJOR** — secret-shaped keys and values are recursively redacted at every
  evidence/trace persistence boundary (`test_tools.py` redaction tests and
  `test_repository_redacts_nested_secrets_at_persistence`).
- **MAJOR** — verification uses strict elapsed semantics and bounds each probe by
  the remaining deadline, never resolving beyond the deadline
  (`test_slow_probe_cannot_resolve_after_deadline`,
  `test_slow_real_client_never_resolves_beyond_deadline`).
- **MAJOR** — the functional check requires the health response's authoritative
  `X-Deployment-Revision`/`X-Deployment-Generation` to match the intended
  revision and snapshot generation, failing closed on missing/malformed identity
  (`test_probe_rejects_health_identity_revision_mismatch` and four siblings).
- **MINOR** — the verify driver rejects zero-test, skipped-only, and
  failing/collection-error test runs for required pytest and vitest suites
  (`test_verify_runner.py`).

## Real service recovery vs scripted agent inference

These are deliberately separate, and the report labels which is which.

- **Real service recovery (not scripted):** the gateway reads the active revision
  from PostgreSQL and proxies real HTTP traffic to the healthy/broken demo
  containers; fault injection, reservations, approvals, the restricted executor,
  and sustained functional verification all run as real services. The
  `e2e_deployment`, `e2e_recovery`, and the recovery portions of `e2e_console`
  exercise this path with real containers and real PostgreSQL.
- **Scripted agent inference:** the investigation adapter is
  `scripted:demo`, enabled only by the explicit `compose.investigation.yaml`
  override. It is a deterministic script that requests real read-only tools; it
  is not a language model. Every run records this identity, and the console shows
  it prominently. The `e2e_investigation` and `e2e_console` proposal steps run
  under this labeled scripted adapter.
- **Live model:** not exercised here (see blocker below). When no runtime model is
  configured, the worker fails closed with adapter identity
  `missing-credentials` and escalates rather than silently substituting a script.

## Live-model blocker

The runtime investigation model is **not configured** in this environment:
`MODEL_BASE_URL`, `MODEL_NAME`, and `MODEL_API_KEY` are absent. The optional live
check (`uv run python scripts/verify.py --live`) therefore reports
`live_model_investigation: blocked (live_model_unconfigured)` and never a
success. The live path is implemented (`tests/live/test_live_model.py`) and
requires a separately configured OpenAI-compatible provider; it performs a real
provider call and asserts the recorded adapter identity is `openai-compatible:*`.
It deliberately does not read or reuse any coding-CLI credential.

## Explicit non-claims

- This is a **local Docker demo**, not a production system, and is not production
  ready.
- **Exactly-once physical side effects are not claimed.** Recovery is an
  idempotent desired-state change plus exact operation-id reconciliation; a crash
  can resume the same persisted operation, but no physical exactly-once guarantee
  is asserted.
- The scripted adapter is not live inference, and no scripted result is reported
  as live evidence.
