"""Bounded regression for the whole-stack verification driver's pytest gate.

Finding 7: a subprocess that exits 0 with ``5 skipped in 0.01s`` was reported as
``passed``.  Required test suites must execute at least one passing test and
reject skips, zero-test runs, and collection errors.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "verify.py"
_SPEC = importlib.util.spec_from_file_location("verify_runner_under_test", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
verify = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = verify
_SPEC.loader.exec_module(verify)


def test_pytest_gate_rejects_skipped_only_run() -> None:
    counts = verify._pytest_counts("5 skipped in 0.01s")
    ok, detail = verify._pytest_gate(counts)
    assert ok is False
    assert "skipped" in detail


def test_pytest_gate_rejects_zero_test_run() -> None:
    for output in ("no tests ran in 0.01s", "collected 0 items", ""):
        counts = verify._pytest_counts(output)
        assert verify._pytest_gate(counts)[0] is False, output


def test_pytest_gate_rejects_failures_and_errors() -> None:
    assert verify._pytest_gate(verify._pytest_counts("1 failed, 37 passed in 2.0s"))[0] is False
    assert verify._pytest_gate(verify._pytest_counts("2 errors in 0.5s"))[0] is False


def test_pytest_gate_rejects_mixed_skip() -> None:
    assert verify._pytest_gate(verify._pytest_counts("37 passed, 1 skipped in 2.0s"))[0] is False


def test_pytest_gate_accepts_real_passing_run() -> None:
    counts = verify._pytest_counts("38 passed in 1.23s")
    ok, detail = verify._pytest_gate(counts)
    assert ok is True
    assert "38" in detail


_VITEST_OUTPUT = """
 Test Files  5 passed (5)
      Tests  31 passed (31)
   Duration  2.34s
"""


def test_vitest_counts_parses_tests_line_not_files_line() -> None:
    counts = verify._vitest_counts(_VITEST_OUTPUT)
    assert counts["passed"] == 31


def test_vitest_gate_rejects_zero_skipped_and_failing() -> None:
    assert verify._test_gate(verify._vitest_counts("      Tests  0 passed (0)"))[0] is False
    assert verify._test_gate(verify._vitest_counts("      Tests  2 skipped (2)"))[0] is False
    assert (
        verify._test_gate(verify._vitest_counts("      Tests  1 failed | 30 passed (31)"))[0]
        is False
    )


def test_vitest_gate_accepts_real_passing_run() -> None:
    counts = verify._vitest_counts(_VITEST_OUTPUT)
    ok, detail = verify._test_gate(counts)
    assert ok is True
    assert "31" in detail
