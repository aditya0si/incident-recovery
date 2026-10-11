# Verification evidence (Milestone 6)

This document records the commands that were actually executed, the observed
results, and the one explicit blocker. It contains no projected or estimated
counts: every number below is copied from the machine-readable report produced by
the verification driver at `.hermes/evidence/verify/report.json` (logs alongside
it under `.hermes/evidence/verify/logs/`).

- **Source revision:** `35e1584f015352df39e11d881b245f2929adcffc`
  (`feat/incident-recovery`, clean working tree at run time)
- **Report generated:** `2026-10-11T17:36:25Z` → `2026-10-11T17:42:45Z` (UTC)
- **Host:** Windows, Python 3.14.5, Docker Engine 29.6.2, Compose v5.3.1,
  Node v26.7.0, npm 11.19.0

## Reproduce

```bash
# from the repository root, with the gitignored .env populated
uv run python scripts/verify.py --docker --ui
```

The driver exits non-zero if any *required* check fails or is blocked. It applies
the test-only control override and the explicit scripted-investigation override
for the Docker E2E phase and restores the default stack in a `finally` block even
when a check fails. It never prints secrets: output is sanitized against the
values in `.env`, and Compose configuration is validated only with `config -q`.

## Observed results

| Check | Command | Result | Counts |
| --- | --- | --- | --- |
| backend_unit | `uv run pytest tests/unit -q` | passed | 38 passed |
| frontend_install | `npm --prefix frontend ci` | passed | — |
| frontend_unit | `npm --prefix frontend test -- --run` | passed | 31 passed |
| frontend_build | `npm --prefix frontend run build` | passed | — |
| frontend_audit | `npm --prefix frontend audit --audit-level=high` | passed | no high/critical advisories |
| compose_config_default | `docker compose -p incident-recovery -f compose.yaml config -q` | passed | — |
| compose_config_overrides | `docker compose -p incident-recovery -f compose.yaml -f compose.test.yaml -f compose.investigation.yaml config -q` | passed | — |
| compose_up_default | `docker compose -p incident-recovery -f compose.yaml up --build -d --wait` | passed | — |
| backend_integration | `uv run pytest tests/integration -q` | passed | 63 passed |
| compose_up_overrides | override `up --build -d --wait` | passed | — |
| e2e_deployment | `uv run pytest tests/e2e/test_deployment.py -q` | passed | 4 passed |
| e2e_recovery | `uv run pytest tests/e2e/test_recovery.py -q` | passed | 3 passed |
| e2e_investigation | `uv run pytest tests/e2e/test_investigation.py -q` | passed | 1 passed |
| e2e_resilience | `uv run pytest tests/e2e/test_resilience.py -q` | passed | 9 passed |
| e2e_console | `uv run pytest tests/e2e/test_console.py -q` | passed | 5 passed (real Chromium) |
| compose_restore_default | default `up --build -d --wait` | passed | — |
| tracked_secret_scan | `git ls-files` + pattern scan | passed | 82 tracked files, no secret material |

Totals from the report: **19 checks passed, 0 failed, 0 blocked; required
checks OK.** That corresponds to 154 executed test cases
(101 backend, 31 frontend, 22 real Docker/browser E2E).

A prior run of the driver failed `compose_up_default` loudly with exit 1 because
the Docker image build hit a transient `pip` read timeout against
`files.pythonhosted.org`; the run exited non-zero rather than masking it. After
the image cache was warmed, the re-run above passed cleanly. The driver never
treats a masked pipeline or a retried failure as success.

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

## Adversarial resilience coverage

`tests/e2e/test_resilience.py` (real containers) and
`tests/integration/test_resilience.py` (real PostgreSQL, no containers) cover:
duplicate alerts and duplicate approvals collapsing to one logical incident /
operation; a worker restart preserving the investigation epoch, tool-call count,
and deadline; a competing fault injection refused while a recovery owns the
deployment; an approval that expired during recovery admission refused at the
authoritative internal switch; the public gateway exposing no switch and the
internal switch requiring the internal token; no container mounted with the
Docker socket and the executor publishing no host port; an unsuccessful
(stale-generation) recovery becoming `recovery_failed` rather than resolving;
oversized/poisoned observations bounded and redacted; foreign and stale-epoch
evidence escalating without a proposal; malformed provider output escalating; and
a stale recovery lease being unable to finalize verification. Runtime secrets are
asserted absent from persisted evidence, events, and gateway logs.

Fixing the oversized-observation gap required a code change: `_bounded_json` in
`src/incident_recovery/tools.py` now deterministically shrinks a hostile payload
below `MAX_RESPONSE_BYTES` (previously a single huge field or a large log list
could exceed the 16 KiB evidence cap and escalate as a tool failure).

## Explicit non-claims

- This is a **local Docker demo**, not a production system, and is not production
  ready.
- **Exactly-once physical side effects are not claimed.** Recovery is an
  idempotent desired-state change plus operation-id reconciliation; a crash can
  resume the same persisted operation, but no physical exactly-once guarantee is
  asserted.
- The scripted adapter is not live inference, and no scripted result is reported
  as live evidence.
