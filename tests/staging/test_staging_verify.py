"""Staging verification driver: pure gate and evidence-honesty tests.

These exercise ``scripts/staging_verify.py`` without Docker.  They pin the two
properties the driver exists to protect:

* a required test suite that skipped or did not execute cannot be reported as a
  pass (the opt-in E2E skip is the one declared exception and is run separately);
* the live-readiness evidence check refuses a vacuous ``safety_ok=True`` produced
  from zero executed cases, and refuses any report whose recorded source SHA does
  not match the actually-executed pinned source.
"""

from __future__ import annotations

from pathlib import Path

import staging_verify as sv


# --- pytest gate --------------------------------------------------------------


def test_pytest_gate_rejects_a_skipped_required_suite() -> None:
    ok, detail = sv.pytest_gate({"passed": 9, "skipped": 1})
    assert ok is False
    assert "skipped" in detail


def test_pytest_gate_allows_only_the_declared_opt_in_skip() -> None:
    ok, detail = sv.pytest_gate({"passed": 140, "skipped": 1}, allowed_opt_in_skips=1)
    assert ok is True
    assert "opt-in" in detail


def test_pytest_gate_rejects_two_skips_even_when_one_is_opt_in() -> None:
    ok, _ = sv.pytest_gate({"passed": 5, "skipped": 2}, allowed_opt_in_skips=1)
    assert ok is False


def test_pytest_gate_rejects_no_tests_and_deselected_and_xfail() -> None:
    assert sv.pytest_gate({"no_tests_ran": 1})[0] is False
    assert sv.pytest_gate({"passed": 3, "deselected": 1})[0] is False
    assert sv.pytest_gate({"passed": 3, "xfailed": 1})[0] is False
    assert sv.pytest_gate({"passed": 0})[0] is False


def test_pytest_counts_parses_a_summary_line() -> None:
    counts = sv.pytest_counts("141 passed, 1 skipped in 12.34s")
    assert counts["passed"] == 141
    assert counts["skipped"] == 1


# --- evidence honesty ---------------------------------------------------------


def _pinned() -> dict:
    return {
        "source_sha": "a6f715aac1d4e46b2ef30e12fb42d4719672f7f5",
        "fault_patch_sha256": "patchhash",
        "manifest_hash": "manifesthash",
    }


def _baseline() -> dict:
    return {"status": "passed", "source_sha": _pinned()["source_sha"], "checks": [{"status": "passed"}], "failed_checks": []}


def _recovery() -> dict:
    return {
        "status": "passed",
        "source_sha": _pinned()["source_sha"],
        "patch_sha256": "patchhash",
        "checks": [{"status": "passed"}],
        "live_provider": "blocked",
    }


def _scripted() -> dict:
    return {
        "status": "passed",
        "mode": "scripted",
        "source_sha": _pinned()["source_sha"],
        "manifest_hash": "manifesthash",
        "adapter_identity": "scripted:tenant-api-staging",
        "metrics": {
            "total": 12,
            "passed": 12,
            "missing": 0,
            "executed": 12,
            "completed_live": 0,
            "safety_established": True,
            "safety_ok": True,
            "utility_scope": "orchestration",
            "orchestration_utility_ok": True,
            "recoveries": 2,
            "policy_refusals": 10,
            "unauthorized_writes": 0,
            "forbidden_admissions": 0,
        },
    }


def _live() -> dict:
    return {
        "status": "blocked",
        "mode": "live",
        "metrics": {
            "total": 12,
            "blocked": 12,
            "executed": 0,
            "completed_live": 0,
            "safety_established": False,
            "safety_ok": None,
        },
        "live": {
            "provider_transport_attempted": False,
            "attempted_provider_requests": 0,
            "accuracy_claimed": False,
            "cost_claimed": False,
            "safety_ok": None,
        },
    }


def _results(*, baseline=None, recovery=None, scripted=None, live=None):
    return dict(
        baseline=_baseline() if baseline is None else baseline,
        recovery=_recovery() if recovery is None else recovery,
        scripted=_scripted() if scripted is None else scripted,
        live=_live() if live is None else live,
    )


def _find(results, name):
    for n, ok, detail in results:
        if n == name:
            return ok, detail
    raise AssertionError(f"missing evidence result {name}")


def test_all_evidence_passes_for_a_consistent_run() -> None:
    results = sv.evaluate_evidence(**_results(), pinned=_pinned())
    assert all(ok for _, ok, _ in results), results


def test_live_evidence_refuses_vacuous_safety_true() -> None:
    live = _live()
    live["metrics"]["safety_ok"] = True  # the old vacuous claim
    live["live"]["safety_ok"] = True
    results = sv.evaluate_evidence(**_results(live=live), pinned=_pinned())
    ok, _ = _find(results, "evidence_live_blocked")
    assert ok is False


def test_live_evidence_refuses_any_executed_live_case() -> None:
    live = _live()
    live["metrics"]["executed"] = 1
    live["metrics"]["blocked"] = 11
    results = sv.evaluate_evidence(**_results(live=live), pinned=_pinned())
    ok, _ = _find(results, "evidence_live_blocked")
    assert ok is False


def test_scripted_evidence_rejects_a_stale_source_sha() -> None:
    scripted = _scripted()
    scripted["source_sha"] = "0" * 40
    results = sv.evaluate_evidence(**_results(scripted=scripted), pinned=_pinned())
    ok, _ = _find(results, "evidence_scripted_evaluation")
    assert ok is False


def test_recovery_evidence_rejects_a_wrong_patch_hash() -> None:
    recovery = _recovery()
    recovery["patch_sha256"] = "different"
    results = sv.evaluate_evidence(**_results(recovery=recovery), pinned=_pinned())
    ok, _ = _find(results, "evidence_recovery_report")
    assert ok is False


def test_missing_report_is_reported_not_silently_skipped() -> None:
    results = sv.evaluate_evidence(
        baseline=None, recovery=None, scripted=None, live=None, pinned=_pinned()
    )
    assert all(ok is False for _, ok, _ in results)


def test_scripted_evidence_requires_orchestration_utility_scope() -> None:
    scripted = _scripted()
    scripted["metrics"]["utility_scope"] = "live_agent"
    results = sv.evaluate_evidence(**_results(scripted=scripted), pinned=_pinned())
    ok, _ = _find(results, "evidence_scripted_evaluation")
    assert ok is False


# --- per-case contract --------------------------------------------------------


def _case(case_id: str, *, live: bool) -> dict:
    return {
        "case_id": case_id,
        "status": "blocked" if live else "passed",
        "executed": not live,
        "provider_transport_attempted": False,
        "tokens": None,
        "cost": None,
    }


def test_case_contract_honors_blocked_live_and_executed_scripted() -> None:
    live = [_case(f"c{i}", live=True) for i in range(12)]
    scripted = [_case(f"c{i}", live=False) for i in range(12)]
    assert sv.evaluate_case_records(live, live=True)[0] is True
    assert sv.evaluate_case_records(scripted, live=False)[0] is True


def test_case_contract_rejects_fabricated_usage_and_transport() -> None:
    live = [_case(f"c{i}", live=True) for i in range(12)]
    live[0]["tokens"] = {"total_tokens": 10}
    assert sv.evaluate_case_records(live, live=True)[0] is False
    live = [_case(f"c{i}", live=True) for i in range(12)]
    live[0]["provider_transport_attempted"] = True
    assert sv.evaluate_case_records(live, live=True)[0] is False


def test_case_contract_rejects_wrong_count_and_executed_live() -> None:
    assert sv.evaluate_case_records([_case("c0", live=True)], live=True)[0] is False
    live = [_case(f"c{i}", live=True) for i in range(12)]
    live[3]["executed"] = True
    live[3]["status"] = "passed"
    assert sv.evaluate_case_records(live, live=True)[0] is False
