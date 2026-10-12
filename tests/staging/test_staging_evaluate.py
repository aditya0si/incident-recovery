"""Evaluator driver behaviour: blocked live is real, append-only, no transport.

These tests import the driver directly and exercise its Docker-free paths.  They
never touch a provider, a credential, or a container: ``--live`` must produce a
complete blocked artifact while attempting zero provider requests, and a replay
must reuse (never duplicate) the recorded cases.
"""

from __future__ import annotations

import json
from pathlib import Path

from incident_recovery.staging import evaluation as ev
import staging_evaluate as script

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "staging" / "scenarios.json"


def _manifest() -> ev.ScenarioManifest:
    return ev.load_scenarios(MANIFEST_PATH)


def test_live_mode_emits_blocked_artifact_with_zero_transport(tmp_path: Path) -> None:
    manifest = _manifest()
    store = ev.RunStore(tmp_path / "runs", "live-1")
    payload = script.run_live_blocked(manifest, store, run_id="live-1")

    assert payload["status"] == "blocked"
    live = payload["live"]
    assert live["completed_live"] == 0
    assert live["provider_transport_attempted"] is False
    assert live["attempted_provider_requests"] == 0
    assert live["accuracy_claimed"] is False
    assert live["cost_claimed"] is False

    records = [store.read_case(case.id) for case in manifest.cases]
    assert len(records) == 12
    assert all(record.status == "blocked" for record in records)
    assert all(record.executed is False for record in records)
    assert all(record.provider_transport_attempted is False for record in records)
    assert all(record.tokens is None and record.cost is None for record in records)

    report = json.loads((store.run_dir / "report.json").read_text(encoding="utf-8"))
    assert report["metrics"]["total"] == 12
    assert report["metrics"]["blocked"] == 12
    assert report["metrics"]["executed"] == 0
    assert report["metrics"]["completed_live"] == 0


def test_live_replay_does_not_duplicate_cases(tmp_path: Path) -> None:
    manifest = _manifest()
    store = ev.RunStore(tmp_path / "runs", "live-2")
    script.run_live_blocked(manifest, store, run_id="live-2")
    # A second invocation over the same run must reuse, not append.
    payload = script.run_live_blocked(manifest, store, run_id="live-2")
    assert len(list((store.run_dir / "cases").glob("*.json"))) == 12
    assert payload["metrics"]["total"] == 12
    assert payload["metrics"]["blocked"] == 12


def test_cli_live_returns_zero_and_writes_run_directory(tmp_path: Path) -> None:
    code = script.main(
        ["--live", "--evidence-dir", str(tmp_path), "--run-id", "cli-live"]
    )
    assert code == 0
    run_dir = tmp_path / "runs" / "cli-live"
    assert (run_dir / "manifest.json").is_file()
    assert (run_dir / "report.json").is_file()
    assert len(list((run_dir / "cases").glob("*.json"))) == 12


def test_manifest_mutation_is_refused_after_a_run_begins(tmp_path: Path) -> None:
    manifest = _manifest()
    store = ev.RunStore(tmp_path / "runs", "guarded")
    store.begin(manifest)
    # Simulate a post-freeze label edit.
    mutated_doc = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    mutated_doc["cases"][0]["expected_outcome"] = "escalated_no_proposal"
    mutated_path = tmp_path / "scenarios.json"
    mutated_path.write_text(json.dumps(mutated_doc, indent=2) + "\n", encoding="utf-8")
    mutated = ev.load_scenarios(mutated_path)
    assert mutated.manifest_hash != manifest.manifest_hash
    try:
        ev.RunStore(tmp_path / "runs", "guarded").begin(mutated)
    except ev.ManifestMutationError:
        pass
    else:  # pragma: no cover - the refusal is the point of the test
        raise AssertionError("a mutated manifest must be refused")


def test_live_payload_marks_safety_not_established(tmp_path: Path) -> None:
    manifest = _manifest()
    store = ev.RunStore(tmp_path / "runs", "live-safety")
    payload = script.run_live_blocked(manifest, store, run_id="live-safety")
    assert payload["live"]["safety_ok"] is None
    assert payload["live"]["safety_established"] is False
    metrics = payload["metrics"]
    assert metrics["safety_ok"] is None
    assert metrics["safety_established"] is False
    assert metrics["scripted_executed"] == 0
    assert metrics["executed"] == 0
    summary = (store.run_dir / "summary.log").read_text(encoding="utf-8")
    assert "NOT established" in summary


def test_manifest_versions_derive_source_sha_from_the_pinned_manifest() -> None:
    import staging_source

    manifest = _manifest()
    versions = script._manifest_versions(manifest)
    pinned = staging_source.load_manifest(staging_source.DEFAULT_MANIFEST)
    assert versions.source_sha == pinned["source_sha"]
    assert versions.source_sha != ""
    assert versions.image.endswith(pinned["source_sha"][:7])

