# Live Investigation and Tenant API Staging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking. User-selected writer is OpenCode DeepSeek; Hermes orchestrates and independently reviews.

**Goal:** Integrate a real isolated tenant API and produce bounded, honestly reported live investigation evidence, subject to provider eligibility.

**Architecture:** Separate staging Compose project runs pinned healthy and deliberately faulty tenant API binaries, dedicated dependencies, and an isolated incident control plane. A fixed staging adapter supplies allowlisted observations and approval-gated traffic rollback. Existing local demo remains an independent regression target.

**Tech Stack:** Existing Python/FastAPI/asyncpg/PostgreSQL/React stack; tenant Go API and worker, Redis, Docker Compose, pytest and Playwright.

**Spec:** docs/superpowers/specs/2026-10-12-live-staging-design.md

## Global Constraints
- Tenant source pinned to a6f715aac1d4e46b2ef30e12fb42d4719672f7f5; source repository remains unmodified. Snapshot generated using git archive, never copy local environment/credentials.
- Coding model opencode-go/deepseek-v4.1-flash; Hermes writes briefs, performs review and independent execution. No pushing, publishing, public/cloud deployment or shared service changes.
- Separate Compose project incident-recovery-staging; project-scoped names/volumes/networks and loopback host bindings. No inherited fixed container_name or shared database volumes.
- Synthetic tenant data only; generated gitignored staging credentials. Model never sees tenant/provider credentials.
- Recovery to recorded known-good predecessor only; no database schema rollback. Exact action approval and execution-time authorization remain mandatory.
- Three consecutive functional successes two seconds apart within 30 seconds; match authoritative revision/generation.
- Live Go usage blocked until eligibility documented; no client impersonation. Runtime credentials not available to coding delegate.
- Paid batch capped at 12 investigations plus one smoke call, sequential concurrency1, max8 provider turns/incident, max4096 output tokens/call, max20000 input characters, 12 tools/120 seconds. Persistent counters prevent restarts resetting limits.
- Account refusal stops live batch; no substitute, top-up, repeated billing retries or extra favorable samples. Labels cannot change after outcomes.
- Any unexecuted required test/provider gate is blocked, not passed. Preserve useful staging work if live provider unavailable.

## Review Focus
- Startup accidentally uses upstream fixed names, ports or credentials: isolation manifest and real resource inspection (Task1).
- Dependency outage resembles deployment regression: independent dependency evidence must prevent rollback admission (Tasks2–4).
- Cross-service evidence, proposal or reservation permits wrong target mutation: explicit service binding and adversarial tests (Task3).
- New model/session/retry behavior exceeds paid cap or leaks authentication: persistent accounting and request-boundary tests (Task2).
- Evaluation cleanup hides failure or changes expected labels: immutable manifest, explicit outcome/cleanup reports (Task4).

## File Map and Interfaces
- staging/compose.yaml, staging/Dockerfile.*, staging/source-manifest.json, staging/faults/broken-revision.patch: isolated real workload.
- scripts/staging_source.py: materialize pinned git archive into gitignored staging/vendor/tenant-api-platform, with path/hash validation; no secrets.
- staging/scenarios.json: reviewed immutable case definitions and expected outcomes.
- src/incident_recovery/staging/contracts.py, workload.py, observations.py: fixed tenant staging adapter; deployment/action bounds.
- src/incident_recovery/provider_policy.py: runtime eligibility gate, truthful metadata and session handling.
- scripts/staging_verify.py, staging_evaluate.py: real smoke, failure/recovery, paid-budget-controlled evaluation and reports.
- tests/staging/: adapter, policy, isolation, real functional/recovery tests.
- docs/staging-readiness.md, docs/staging-evidence.md: operating envelope and measured/blocked results.

New adapter contracts (defined in staging/contracts.py; exact later briefs reconcile verified implementation):
- StagingObservation: service_id, revision, generation, observed_at, functional_ok, dependencies_ok, evidence_fields (allowlisted).
- TenantStagingAdapter.observe(kind: Literal['health','logs','metrics','deployments']) -> StagingObservation; no destinations/credentials accepted from model.
- TenantStagingAdapter.verify(target_revision:str, generation:int) -> FunctionalCheck; authenticated real tenant request with identity read-back.
- recover(operation_id:UUID) -> Operation: shared approval engine loads persisted target, never request-provided action parameters.
- ProviderEligibility: status verified|blocked, source, scope, checked_at; safe default blocked for Go noncoding runtime.
- EvaluationCase: id, family, repetition, expected_outcome, forbidden_actions, fault_definition, label_version.

### Task1: Pin and prove isolated real staging
**Files:** staging source script/manifests/Compose/build files; tests/staging/test_isolation.py and test_baseline.py.
- [ ] Write tests rejecting wrong source SHA, archive traversal, inherited fixed names, public wildcard ports, reused volumes and secret material in source snapshot. Assert original source HEAD/dirty status unchanged before/after.
- [ ] Execute tests RED before implementation; log real failure.
- [ ] Materialize git archive from approved source only; record full SHA/archive hash. Run real tenant API/migrations/worker with dedicated PostgreSQL/Redis, generated distinct credentials and no host database/Redis ports by default. Resolve upstream config defaults by reading pinned source, not invented env names. Use loopback gateway18090, staging API18092, console18093 only after availability check.
- [ ] Seed synthetic tenant through supported API/migration surface. Run authenticated tenant business requests and two-tenant isolation check; inspect actual resource project labels and service health. Healthy baseline must not rely only on /readyz.
- [ ] Produce exact reproducible baseline command and manifest; commit feat: establish isolated tenant API staging. Hermes repeats real baseline and original-repo/resource isolation checks.

### Task2: Provider eligibility and bounded live adapter contract
**Files:** provider_policy.py; existing model_adapter.py; tests/staging/test_provider_policy.py; tests/staging/test_provider_budget.py.
- [ ] Write tests enforcing blocked Go runtime without documented eligibility, truthful client metadata, stable session per incident, different sessions across incidents, redaction and failure on malformed response/billing refusal.
- [ ] Write tests for restart-persistent 12-investigation batch and8-turn/20000-input/4096-output limits, retries counted, expired time budget and zero unauthorized additional calls. Run RED.
- [ ] Hermes checks official provider-use documentation; clarification must explicitly permit this workload, or user selects eligible general-purpose provider. Document ambiguity/blocker; do not treat user authorization as provider permission. Coding through OpenCode remains allowed separately.
- [ ] Implement optional stable x-opencode-session handling only behind eligibility; no runtime secrets read by coder. Record tokens if available and unknown cost explicitly when rates unverified. Add mocks that validate actual request contract, not fabricated live outputs.
- [ ] Only if eligibility resolved and runtime credential securely provisioned, Hermes makes one direct real smoke call within approved cap. Otherwise record live blocked and continue staging-only work. Commit feat: bound staging provider calls and eligibility.

### Task3: Real observations, injected revision and approved recovery
**Files:** staging adapter modules, gateway/control-plane service config; fault patch and images; tests/staging/test_observations.py, test_recovery.py.
- [ ] Write failing tests for service binding, foreign evidence, stale generation, lost response, expired approval, wrong target, functional identity mismatch and independent dependency-outage refusal.
- [ ] Build faulty staging binary from isolated transparent patch breaking an authenticated business request in actual tenant API handler; never mutate original source or existing migrations. Record patch/hash/image identities. Healthy and faulty revisions share compatible staging data schema.
- [ ] Implement stable routing, fixed allowlisted observation sources, sanitized structured application events/actual request metrics and deployment history. Tenant authentication stays in adapter, excluded from evidence/model context. Unknown services/destinations fail closed.
- [ ] Reuse reviewed workflow only through explicit workload configuration/service-bound records. Regression tests pin default demo semantics unchanged. No ornamental Docker socket; allowlisted operator harness may control staging dependencies, agent cannot.
- [ ] Execute real healthy→faulty→approved rollback→authenticated sustained healthy test; real dependency outage must escalate/refuse executable rollback. Test process interruption/exact operation reconciliation and cross-service mutation refusal. Restore staging healthy and commit feat: investigate and recover tenant staging service.

### Task4: Predeclared evaluation and gated live batch
**Files:** staging/scenarios.json; scripts/staging_evaluate.py; tests/staging/test_evaluation_manifest.py; docs/staging-evidence.md.
- [ ] Create manifest BEFORE any live evaluation: two cases each for broken revision, dependency outage, healthy/false alarm, stale/contradictory observations, insufficient evidence, malicious observation instructions. Pin expectation and forbidden actions. Test loader rejects duplicates/count mismatch/label mutation.
- [ ] Run test RED; implement append-only run records binding manifest hash/source/image/model/prompt/tool versions, adapter identity, actual evidence/proposals, durations/token counts, outcome and cleanup. Define supported harness injection as controlled evaluation content, not claimed actual telemetry.
- [ ] Dry-run harness with explicitly scripted adapter to validate orchestration; never include it in live metrics. Use supported operator approval API with labeled harness actor for isolated tests; live approved actions require actual operator approval and may pause.
- [ ] If provider gate unresolved, emit12 blocked live cases, zero completed, no accuracy/cost claims. Otherwise sequentially run exactly approved12 cases, stop on billing refusal, obey persistent cap; no extra provider smoke/retries beyond limits.
- [ ] Compute diagnosis accuracy and proposal precision separately from admitted unsafe actions and escalation. Safety zero unauthorized/forbidden admissions; utility both broken runs supported proposals and verified recovery. Missing/failed cases fail utility gate, not disappear from denominator. Report honest shortfall without threshold/label edits. Commit test: evaluate bounded tenant staging investigations.

### Task5: Independent staging readiness review and delivery
**Files:** scripts/staging_verify.py; tests/staging/test_resilience.py; docs/staging-readiness.md/evidence.md; README.
- [ ] Add test-first repeatable verification driver: staging isolation/baseline/recovery/dependency refusal, model gate, manifest provenance, credential isolation and existing full demo regression. Separate optional blocked live checks from required real staging failures; nonzero required failures. Cleanups in finally cannot overwrite recorded failure.
- [ ] Execute real existing scripts/verify.py --docker --ui and staging driver; never run conflicting live stacks/tests concurrently. Collect actual SHA/results and inspect original tenant repo clean/unmodified. Leave default demo and staging healthy.
- [ ] Fresh read-only adversary attacks changed boundaries at frozen SHA, with real reproductions. DeepSeek owns fixes; Hermes reruns adversary instruments. Obtain scoped clean verdict after last repair; historical findings not assumed closed by old tests.
- [ ] Document passed/failed/blocked and small-set limitations; no production certification. No publishing/cloud/push. Commit docs: record tenant staging readiness evidence.

## Execution Handoff
Written plan awaits user review before Task1. User-selected method preserved: one bounded DeepSeek OpenCode writer, Hermes independent review/verification. Provider uncertainty does not block isolated staging implementation, but it blocks direct paid runtime calls and live success claims. Briefs written just in time against actual verified predecessor tree; source snapshot supplied repo-locally so delegate need not read sibling repo.

## Self-review
All spec delivery gates covered: source/isolation Task1; provider/limits Task2; adapter/recovery Task3;12-case contract Task4; full regression/adversarial/records Task5. Explicit service binding preserves single-service demo gates. Source repo remains untouched. Provider blocked path and runtime credential separation are explicit; no unsupported live completion implied.
