"""Durable, restart-persistent paid-call accounting for the staging provider.

Task 2 tests for :class:`incident_recovery.provider_policy.JsonBudgetLedger` and
its integration with the bounded staging adapter.  The ledger is a
staging-specific durable JSON file, never a module global, so a new process (or
a new ``JsonBudgetLedger`` over the same path) resumes the *same* counters and
cannot reset a paid limit by restarting.

No real provider call is made and no real credential is used; the single secret
under test is a clearly synthetic token.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from incident_recovery import provider_policy as policy
from incident_recovery.contracts import InvestigationContext
from incident_recovery.model_adapter import OpenAICompatibleAdapter

BASE_URL = "http://provider.test/v1"
SYNTHETIC_KEY = "sk-staging-SYNTHETIC-0123456789abcdef"


async def _noop_sleep(_seconds: float) -> None:
    return None


def _reviewed_eligibility() -> policy.ProviderEligibility:
    return policy.ProviderEligibility(
        provider=policy.GO_PROVIDER,
        scope=policy.GO_RUNTIME_SCOPE,
        status=policy.EligibilityStatus.VERIFIED.value,
        source=policy.OFFICIAL_DOC_URL,
        checked_at=datetime(2026, 10, 12, tzinfo=timezone.utc),
        evidence=policy.EligibilityEvidence(
            scope=policy.GO_RUNTIME_SCOPE,
            reviewer="parent-reviewer",
            reference="reviewed scoped eligibility",
            reviewed_at=datetime(2026, 10, 12, tzinfo=timezone.utc),
        ),
    )


def _ledger(tmp_path: Path, **overrides) -> policy.JsonBudgetLedger:
    limits = replace(policy.ProviderLimits(), **overrides) if overrides else policy.ProviderLimits()
    return policy.JsonBudgetLedger(tmp_path / "provider_budget.json", limits=limits)


def _context(incident_id=None, *, huge_observations: int = 0) -> InvestigationContext:
    from incident_recovery.contracts import ToolObservation

    observations = []
    for index in range(huge_observations):
        observations.append(
            ToolObservation(
                evidence_id=uuid4(),
                tool="logs",
                observed_at=datetime(2026, 10, 12, tzinfo=timezone.utc),
                summary={"line": "x" * 2000, "index": index},
            )
        )
    return InvestigationContext(
        incident_id=incident_id or uuid4(),
        service_id="demo-api",
        epoch=1,
        step=0,
        tool_calls_used=0,
        max_tool_calls=12,
        seconds_remaining=120.0,
        observations=observations,
        adapter_identity="openai-compatible:deepseek-v4.1-flash",
    )


# --- ledger boundaries --------------------------------------------------------


def test_batch_admission_cap_is_twelve(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    for index in range(12):
        key = f"incident-{index}"
        decision = ledger.admit_investigation(key)
        assert decision.allowed, decision.reason
        ledger.release_investigation(key)
    refused = ledger.admit_investigation("incident-13")
    assert refused.allowed is False
    assert refused.reason == "batch_limit"
    assert refused.remaining == 0


def test_smoke_call_cap_is_one(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    assert ledger.admit_smoke().allowed is True
    second = ledger.admit_smoke()
    assert second.allowed is False
    assert second.reason == "smoke_limit"


def test_turn_cap_is_eight(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    for _ in range(8):
        assert ledger.begin_turn("a").allowed is True
    assert ledger.begin_turn("a").allowed is False
    assert ledger.begin_turn("a").reason == "turn_limit"


def test_smoke_turn_key_is_separate_from_incidents(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    assert ledger.begin_turn(None).allowed is True
    assert ledger.begin_turn("a").allowed is True
    snapshot = ledger.snapshot()
    assert snapshot["turns"][policy.SMOKE_KEY] == 1
    assert snapshot["turns"]["a"] == 1


def test_attempts_are_counted_separately_from_turns(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    assert ledger.begin_turn("a").allowed is True
    for _ in range(3):
        assert ledger.begin_attempt("a").allowed is True
    snapshot = ledger.snapshot()
    assert snapshot["turns"]["a"] == 1
    assert snapshot["attempts"]["a"] == 3


def test_attempts_cannot_exceed_the_paid_limit(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path, max_attempts_per_incident=2)
    assert ledger.begin_attempt("a").allowed is True
    assert ledger.begin_attempt("a").allowed is True
    refused = ledger.begin_attempt("a")
    assert refused.allowed is False
    assert refused.reason == "attempt_limit"


def test_input_character_limit_is_enforced(tmp_path: Path) -> None:
    limits = policy.ProviderLimits()
    assert limits.max_input_chars == 20000
    ledger = _ledger(tmp_path)
    decision = ledger.record_input("a", limits.max_input_chars + 1)
    assert decision.allowed is False
    assert decision.reason == "input_limit"
    assert ledger.record_input("a", limits.max_input_chars).allowed is True


def test_output_token_limit_is_enforced(tmp_path: Path) -> None:
    limits = policy.ProviderLimits()
    assert limits.max_output_tokens == 4096
    ledger = _ledger(tmp_path)
    assert ledger.record_output("a", output_tokens=limits.max_output_tokens).allowed is True
    denied = ledger.record_output("a", output_tokens=limits.max_output_tokens + 1)
    assert denied.allowed is False
    assert denied.reason == "output_limit"


def test_counters_persist_across_ledger_instances(tmp_path: Path) -> None:
    path = tmp_path / "provider_budget.json"
    first = policy.JsonBudgetLedger(path, limits=replace(policy.ProviderLimits(), max_investigations=2))
    assert first.admit_investigation("a").allowed
    first.release_investigation("a")
    assert first.begin_turn("a").allowed
    assert first.record_input("a", 1000).allowed

    resumed = policy.JsonBudgetLedger(path, limits=replace(policy.ProviderLimits(), max_investigations=2))
    snapshot = resumed.snapshot()
    assert snapshot["turns"]["a"] == 1
    assert snapshot["input_chars"]["a"] == 1000
    # A restart must not reset the paid admission/turn budget.
    assert resumed.admit_investigation("b").allowed
    resumed.release_investigation("b")
    assert resumed.admit_investigation("c").allowed is False
    assert resumed.admit_investigation("c").reason == "batch_limit"
    for _ in range(7):
        assert resumed.begin_turn("a").allowed
    assert resumed.begin_turn("a").allowed is False


def test_concurrent_admission_is_refused_while_another_is_active(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    assert ledger.admit_investigation("a").allowed is True
    blocked = ledger.admit_investigation("b")
    assert blocked.allowed is False
    assert blocked.reason == "concurrency_limit"
    ledger.release_investigation("a")
    assert ledger.admit_investigation("b").allowed is True
    # Re-admitting the same active incident is idempotent, not a conflict.
    assert ledger.admit_investigation("b").allowed is True


# --- usage honesty ------------------------------------------------------------


def test_unknown_usage_and_cost_are_none_not_zero() -> None:
    usage = policy.ProviderUsage.from_payload({})
    assert usage.input_tokens is None
    assert usage.output_tokens is None
    assert usage.total_tokens is None
    assert usage.cost is None
    assert usage.cost != 0


def test_actual_usage_is_validated_and_stored(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    decision = ledger.record_output("a", output_tokens=17, cost=0.0004)
    assert decision.allowed is True
    usage = ledger.snapshot()["usage"]["a"]
    assert usage["output_tokens"] == 17
    assert usage["cost"] == 0.0004
    # Invalid provider usage is treated as unknown, never coerced to zero.
    ledger.record_output("b", output_tokens=-5, cost=-1.0)
    usage_b = ledger.snapshot()["usage"]["b"]
    assert usage_b["output_tokens"] is None
    assert usage_b["cost"] is None


def test_usage_from_payload_parses_known_fields() -> None:
    usage = policy.ProviderUsage.from_payload(
        {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}
    )
    assert (usage.input_tokens, usage.output_tokens, usage.total_tokens) == (3, 4, 7)
    assert usage.cost is None


def test_snapshot_is_inspectable_and_contains_no_secret_material(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    ledger.begin_turn("a")
    encoded = json.dumps(ledger.snapshot())
    assert "sk-" not in encoded
    assert "Bearer" not in encoded
    assert "api_key" not in encoded


# --- adapter enforcement ------------------------------------------------------


def _ok_handler(calls: list[httpx.Request]):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        content = json.dumps({"tool": "health", "reason": "check"})
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": content}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 9, "total_tokens": 14},
            },
        )

    return handler


def _adapter(tmp_path: Path, handler, *, ledger: policy.JsonBudgetLedger, max_retries: int = 0, max_tokens: int = 4096):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=BASE_URL)
    provider_policy = policy.StagingProviderPolicy(
        eligibility=_reviewed_eligibility(), ledger=ledger
    )
    return OpenAICompatibleAdapter(
        base_url=BASE_URL,
        model="deepseek-v4.1-flash",
        api_key=SYNTHETIC_KEY,
        client=client,
        max_retries=max_retries,
        max_tokens=max_tokens,
        sleep=_noop_sleep,
        policy=provider_policy,
    ), provider_policy


async def test_adapter_refuses_once_turn_budget_is_exhausted(tmp_path: Path) -> None:
    calls: list[httpx.Request] = []
    ledger = _ledger(tmp_path, max_turns_per_incident=1)
    adapter, provider_policy = _adapter(tmp_path, _ok_handler(calls), ledger=ledger)
    incident_id = uuid4()
    provider_policy.admit_investigation(incident_id)
    await adapter.next_step(_context(incident_id))
    with pytest.raises(policy.ProviderBudgetExceeded):
        await adapter.next_step(_context(incident_id))
    assert len(calls) == 1
    await adapter.aclose()


async def test_retries_are_counted_and_cannot_exceed_the_paid_cap(tmp_path: Path) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, json={"error": "busy"})

    ledger = _ledger(tmp_path, max_turns_per_incident=1, max_attempts_per_incident=2)
    adapter, provider_policy = _adapter(tmp_path, handler, ledger=ledger, max_retries=5)
    incident_id = uuid4()
    provider_policy.admit_investigation(incident_id)
    with pytest.raises(policy.ProviderBudgetExceeded):
        await adapter.next_step(_context(incident_id))
    assert calls["n"] == 2, "retries must stop at the paid attempt cap"
    await adapter.aclose()


async def test_staging_request_is_bounded_to_input_and_output_limits(tmp_path: Path) -> None:
    calls: list[httpx.Request] = []
    ledger = _ledger(tmp_path)
    adapter, provider_policy = _adapter(tmp_path, _ok_handler(calls), ledger=ledger, max_tokens=4096)
    context = _context(huge_observations=40)
    provider_policy.admit_investigation(context.incident_id)
    await adapter.next_step(context)
    assert len(calls) == 1
    body = json.loads(calls[0].content)
    assert body["max_tokens"] == 4096
    total_chars = sum(len(message["content"]) for message in body["messages"])
    assert total_chars <= policy.ProviderLimits().max_input_chars
    await adapter.aclose()


async def test_usage_recorded_and_ledger_file_has_no_secret(tmp_path: Path) -> None:
    calls: list[httpx.Request] = []
    ledger_path = tmp_path / "provider_budget.json"
    ledger = policy.JsonBudgetLedger(ledger_path)
    adapter, provider_policy = _adapter(tmp_path, _ok_handler(calls), ledger=ledger)
    context = _context(uuid4())
    provider_policy.admit_investigation(context.incident_id)
    await adapter.next_step(context)
    snapshot = provider_policy.snapshot()
    recorded = [usage for usage in snapshot["usage"].values()]
    assert recorded and recorded[-1]["output_tokens"] == 9
    raw = ledger_path.read_text(encoding="utf-8")
    assert SYNTHETIC_KEY not in raw
    assert "Bearer" not in raw
    await adapter.aclose()


# --- cross-instance / cross-process integrity ---------------------------------


def test_two_preloaded_instances_do_not_both_admit(tmp_path: Path) -> None:
    """Two instances over the same path must not both act on a stale snapshot."""

    path = tmp_path / "provider_budget.json"
    limits = replace(policy.ProviderLimits(), max_investigations=1)
    first = policy.JsonBudgetLedger(path, limits=limits)
    second = policy.JsonBudgetLedger(path, limits=limits)
    # Both were constructed (preloaded) before either admits.
    assert first.admit_investigation("a").allowed is True
    blocked = second.admit_investigation("b")
    assert blocked.allowed is False
    assert blocked.reason == "concurrency_limit"
    # The disk state retains the *winner*, never a divergent second snapshot.
    snapshot = policy.JsonBudgetLedger(path, limits=limits).snapshot()
    assert snapshot["admitted"] == ["a"]
    assert snapshot["active_investigation"] == "a"


def test_two_instances_share_a_single_batch_cap(tmp_path: Path) -> None:
    path = tmp_path / "provider_budget.json"
    limits = replace(policy.ProviderLimits(), max_investigations=2)
    first = policy.JsonBudgetLedger(path, limits=limits)
    second = policy.JsonBudgetLedger(path, limits=limits)
    assert first.admit_investigation("a").allowed
    first.release_investigation("a")
    assert second.admit_investigation("b").allowed
    second.release_investigation("b")
    # A third admission through either instance sees both prior admissions.
    assert first.admit_investigation("c").allowed is False
    assert first.admit_investigation("c").reason == "batch_limit"
    assert second.admit_investigation("d").allowed is False


def test_billing_latch_persists_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "provider_budget.json"
    first = policy.JsonBudgetLedger(path)
    assert first.billing_refused() is False
    first.mark_billing_refused("provider_billing_refusal_402")
    second = policy.JsonBudgetLedger(path)
    assert second.billing_refused() is True
    assert second.billing_reason() == "provider_billing_refusal_402"
    # Latched billing never resets by constructing a new ledger.
    assert policy.JsonBudgetLedger(path).billing_refused() is True


def test_malformed_existing_ledger_refuses_to_load(tmp_path: Path) -> None:
    path = tmp_path / "provider_budget.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(policy.ProviderPolicyError):
        policy.JsonBudgetLedger(path)


def test_multiprocess_concurrent_admission_is_serialized(tmp_path: Path) -> None:
    """Two real OS processes racing to admit must yield exactly one admission."""

    import subprocess
    import sys

    path = tmp_path / "provider_budget.json"
    code = (
        "import sys, json\n"
        "from dataclasses import replace\n"
        "from incident_recovery import provider_policy as p\n"
        "led = p.JsonBudgetLedger(sys.argv[1], limits=replace(p.ProviderLimits(), max_investigations=1))\n"
        "d = led.admit_investigation(sys.argv[2])\n"
        "print(json.dumps({'allowed': d.allowed, 'reason': d.reason}))\n"
    )
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(path), incident],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for incident in ("a", "b")
    ]
    results = []
    for proc in procs:
        out, err = proc.communicate(timeout=60)
        assert proc.returncode == 0, err
        results.append(json.loads(out.strip().splitlines()[-1]))
    assert sum(1 for r in results if r["allowed"]) == 1, results
    limits = replace(policy.ProviderLimits(), max_investigations=1)
    snapshot = policy.JsonBudgetLedger(path, limits=limits).snapshot()
    assert len(snapshot["admitted"]) == 1
    assert snapshot["active_investigation"] == snapshot["admitted"][0]

