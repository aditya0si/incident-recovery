"""Predeclared evaluation manifest, run records, and outcome classification.

Task 4 tests.  These exercise the pure evaluation core only: the versioned
manifest loader (count/duplicate/label validation and mutation detection), the
append-only run store, the non-circular outcome classifier, the separated
metrics, and the blocked-live record builder (zero provider transport).  No
Docker, no provider, no credential is touched here.
"""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest

from incident_recovery.staging import evaluation as ev

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "staging" / "scenarios.json"


@pytest.fixture(scope="module")
def manifest() -> ev.ScenarioManifest:
    return ev.load_scenarios(MANIFEST_PATH)


def _raw_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _write(tmp_path: Path, document: dict) -> Path:
    path = tmp_path / "scenarios.json"
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def _record(case: ev.EvaluationCase, manifest: ev.ScenarioManifest, **overrides) -> ev.CaseRecord:
    base = dict(
        run_id="run-1",
        case_id=case.id,
        family=case.family,
        manifest_hash=manifest.manifest_hash,
        status="passed",
        executed=True,
        live=False,
        expected_outcome=case.expected_outcome,
        expected_diagnosis=case.expected_diagnosis,
        actual_outcome="escalated_no_proposal",
        adapter_identity="scripted:tenant-api-staging",
        evidence_ids=[],
        gate_reason="no_functional_failure",
        proposal=False,
        proposal_target=None,
        approval=False,
        recovery_verified=False,
        safety_violations=[],
        unauthorized_writes=0,
        forbidden_admissions=0,
        cleanup_ok=True,
        tokens=None,
        cost=None,
        provider_transport_attempted=False,
        detail="",
    )
    base.update(overrides)
    return ev.CaseRecord(**base)


# --- manifest shape -----------------------------------------------------------


def test_manifest_has_exactly_twelve_unique_cases_two_per_family(manifest) -> None:
    assert len(manifest.cases) == ev.CASE_COUNT == 12
    assert len({case.id for case in manifest.cases}) == 12
    counts: dict[str, int] = {}
    for case in manifest.cases:
        counts[case.family] = counts.get(case.family, 0) + 1
    assert set(counts) == set(ev.FAMILIES)
    assert all(count == 2 for count in counts.values())


def test_manifest_hash_is_stable_and_recomputed_from_cases(manifest) -> None:
    again = ev.load_scenarios(MANIFEST_PATH)
    assert again.manifest_hash == manifest.manifest_hash
    assert manifest.hash_matches(manifest.manifest_hash) is True
    assert manifest.hash_matches("0" * 64) is False


def test_manifest_ships_the_exact_family_and_outcome_vocabulary(manifest) -> None:
    for case in manifest.cases:
        assert case.expected_outcome in ev.EXPECTED_OUTCOMES
        assert case.expected_diagnosis in ev.EXPECTED_DIAGNOSES
        assert case.fault_definition.kind in ev.FAULT_KINDS
        assert case.fault_definition.adapter in ev.ADAPTER_KINDS
        assert case.fault_definition.fixture in ev.FIXTURE_KINDS
        assert case.injection_provenance.strip()
        assert set(case.forbidden_actions) <= ev.FORBIDDEN_ACTIONS
    broken = manifest.cases_of("broken_revision")
    assert all(case.expected_outcome == "recovered" for case in broken)
    recoverable = [case for case in manifest.cases if case.expected_outcome == "recovered"]
    assert {case.family for case in recoverable} == {"broken_revision"}


# --- manifest validation ------------------------------------------------------


def test_wrong_case_count_is_rejected(tmp_path: Path) -> None:
    document = _raw_manifest()
    document["cases"] = document["cases"][:-1]
    with pytest.raises(ev.ManifestError):
        ev.load_scenarios(_write(tmp_path, document))


def test_duplicate_case_ids_are_rejected(tmp_path: Path) -> None:
    document = _raw_manifest()
    document["cases"][1]["id"] = document["cases"][0]["id"]
    with pytest.raises(ev.ManifestError):
        ev.load_scenarios(_write(tmp_path, document))


def test_uneven_family_counts_are_rejected(tmp_path: Path) -> None:
    document = _raw_manifest()
    document["cases"][2]["family"] = "broken_revision"
    with pytest.raises(ev.ManifestError):
        ev.load_scenarios(_write(tmp_path, document))


def test_unknown_expected_outcome_is_rejected(tmp_path: Path) -> None:
    document = _raw_manifest()
    document["cases"][0]["expected_outcome"] = "maybe_recovered"
    with pytest.raises(ev.ManifestError):
        ev.load_scenarios(_write(tmp_path, document))


def test_unknown_forbidden_action_is_rejected(tmp_path: Path) -> None:
    document = _raw_manifest()
    document["cases"][0]["forbidden_actions"] = ["unauthorized_write", "delete_everything"]
    with pytest.raises(ev.ManifestError):
        ev.load_scenarios(_write(tmp_path, document))


def test_unknown_fixture_is_rejected(tmp_path: Path) -> None:
    document = _raw_manifest()
    document["cases"][6]["fault_definition"]["fixture"] = "surprise"
    with pytest.raises(ev.ManifestError):
        ev.load_scenarios(_write(tmp_path, document))


def test_malformed_manifest_is_rejected_for_missing_top_level_fields(tmp_path: Path) -> None:
    with pytest.raises(ev.ManifestError):
        ev.load_scenarios(_write(tmp_path, {"cases": []}))


# --- mutation detection -------------------------------------------------------


def test_mutating_a_case_after_the_fact_changes_the_hash(tmp_path: Path) -> None:
    path = _write(tmp_path, _raw_manifest())
    first = ev.load_scenarios(path)
    mutated = copy.deepcopy(_raw_manifest())
    mutated["cases"][0]["expected_outcome"] = "escalated_no_proposal"
    path.write_text(json.dumps(mutated, indent=2) + "\n", encoding="utf-8")
    second = ev.load_scenarios(path)
    assert first.manifest_hash != second.manifest_hash


def test_run_store_refuses_a_changed_manifest_after_begin(tmp_path: Path, manifest) -> None:
    store = ev.RunStore(tmp_path / "runs", "run-x")
    store.begin(manifest)
    mutated = copy.deepcopy(_raw_manifest())
    mutated["cases"][0]["forbidden_actions"] = ["unauthorized_write"]
    changed = ev.load_scenarios(_write(tmp_path, mutated))
    assert changed.manifest_hash != manifest.manifest_hash
    with pytest.raises(ev.ManifestMutationError):
        ev.RunStore(tmp_path / "runs", "run-x").begin(changed)


# --- append-only records ------------------------------------------------------


def test_run_store_is_append_only_and_refuses_overwrite(tmp_path: Path, manifest) -> None:
    store = ev.RunStore(tmp_path / "runs", "run-1")
    store.begin(manifest)
    case = manifest.case("broken-revision-1")
    record = _record(case, manifest)
    store.write_case(record)
    assert store.has_case(case.id)
    with pytest.raises(ev.RecordExists):
        store.write_case(record)
    loaded = store.read_case(case.id)
    assert loaded.case_id == case.id
    assert loaded.manifest_hash == manifest.manifest_hash


def test_record_round_trips_through_json(tmp_path: Path, manifest) -> None:
    case = manifest.case("dependency-outage-1")
    record = _record(case, manifest, tokens=None, cost=None, status="failed")
    store = ev.RunStore(tmp_path / "runs", "run-2")
    store.begin(manifest)
    store.write_case(record)
    loaded = store.read_case(case.id)
    assert loaded.tokens is None and loaded.cost is None
    assert loaded.status == "failed"


def test_cleanup_failure_never_upgrades_a_failed_case(manifest) -> None:
    case = manifest.case("malicious-instructions-1")
    record = _record(case, manifest, status="failed", actual_outcome="proposal_present")
    with_cleanup = record.with_cleanup(False)
    assert with_cleanup.status == "failed"
    assert with_cleanup.cleanup_ok is False
    # A passing case that fails cleanup is still recorded as a cleanup problem,
    # but a failure is never hidden behind it.
    assert with_cleanup.actual_outcome == "proposal_present"


# --- outcome classifier is not circular ---------------------------------------


@pytest.mark.parametrize(
    "kwargs,expected",
    [
        (dict(incident_state="resolved", has_proposal=True, operation_status="verified"), "recovered"),
        (dict(incident_state="escalated", has_proposal=False, operation_status=None), "escalated_no_proposal"),
        (dict(incident_state="awaiting_approval", has_proposal=True, operation_status=None), "proposal_present"),
        (dict(incident_state="recovery_failed", has_proposal=True, operation_status="failed"), "recovery_failed"),
        (dict(incident_state="investigating", has_proposal=False, operation_status=None), "unresolved"),
        (dict(incident_state="rejected", has_proposal=False, operation_status=None), "rejected_no_recovery"),
    ],
)
def test_classifier_reads_persisted_state_not_the_label(kwargs: dict, expected: str) -> None:
    assert ev.classify_outcome(**kwargs) == expected


def test_classifier_cannot_produce_recovered_without_a_verified_operation() -> None:
    # A resolved incident alone is never enough; the operation must be verified.
    assert (
        ev.classify_outcome(
            incident_state="resolved", has_proposal=True, operation_status="executed"
        )
        != "recovered"
    )


# --- separated metrics and the denominator ------------------------------------


def test_metrics_keep_missing_cases_in_the_denominator(manifest) -> None:
    records = [
        _record(manifest.case("broken-revision-1"), manifest, actual_outcome="recovered", proposal=True, recovery_verified=True, approval=True),
        _record(manifest.case("dependency-outage-1"), manifest),
    ]
    metrics = ev.compute_metrics(records, manifest)
    assert metrics["total"] == 12
    assert metrics["executed"] == 2
    assert metrics["missing"] == 10
    # The denominator is the manifest, never just the records we happened to get.
    assert metrics["passed"] <= metrics["total"]
    assert metrics["blocked"] + metrics["executed"] == metrics["total"] or metrics["blocked"] == 10


def test_metrics_separate_diagnosis_policy_and_recovery(manifest) -> None:
    broken = _record(
        manifest.case("broken-revision-1"),
        manifest,
        actual_outcome="recovered",
        proposal=True,
        approval=True,
        recovery_verified=True,
        gate_reason="proposed",
    )
    refused = _record(
        manifest.case("malicious-instructions-1"),
        manifest,
        actual_outcome="escalated_no_proposal",
        proposal=False,
        gate_reason="prompt_injection",
    )
    metrics = ev.compute_metrics([broken, refused], manifest)
    assert metrics["recoveries"] == 1
    assert metrics["policy_refusals"] == 1
    assert metrics["diagnosis_matches"] == 2
    assert metrics["unauthorized_writes"] == 0
    assert metrics["forbidden_admissions"] == 0
    assert metrics["safety_ok"] is True


def test_metrics_report_a_safety_violation(manifest) -> None:
    unsafe = _record(
        manifest.case("dependency-outage-1"),
        manifest,
        actual_outcome="proposal_present",
        proposal=True,
        approval=True,
        recovery_verified=True,
        safety_violations=["executable_rollback"],
        forbidden_admissions=1,
    )
    metrics = ev.compute_metrics([unsafe], manifest)
    assert metrics["safety_ok"] is False
    assert metrics["forbidden_admissions"] == 1
    assert metrics["safety_violations"] == 1


# --- blocked live: zero transport, zero fabricated success --------------------


def test_blocked_live_emits_twelve_blocked_zero_executed_no_transport(manifest) -> None:
    versions = ev.ArtifactVersions(
        source_sha="a6f715a",
        image="incident-recovery-staging-tenant-api:a6f715a",
        tool_version="tools:v1",
        prompt_version="prompt:v1",
        adapter="provider-policy-blocked",
    )
    records = ev.blocked_live_records(manifest, versions)
    assert len(records) == 12
    assert all(record.status == "blocked" for record in records)
    assert all(record.executed is False for record in records)
    assert all(record.provider_transport_attempted is False for record in records)
    assert all(record.tokens is None and record.cost is None for record in records)
    assert all(record.actual_outcome == "blocked" for record in records)
    metrics = ev.compute_metrics(records, manifest, live=True)
    assert metrics["completed_live"] == 0
    assert metrics["blocked"] == 12
    assert metrics["executed"] == 0
    # Blocked live must never blend into scripted counts.
    assert metrics["scripted_executed"] == 0


def test_metrics_never_blend_completed_live_into_scripted(manifest) -> None:
    scripted = [_record(manifest.case(c.id), manifest, live=False) for c in manifest.cases]
    metrics = ev.compute_metrics(scripted, manifest, live=False)
    assert metrics["completed_live"] == 0
    assert metrics["scripted_executed"] == 12
