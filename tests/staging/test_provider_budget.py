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
from incident_recovery.models import ModelUnavailable

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


# --- round2: one-shot smoke admission -----------------------------------------


def test_smoke_admission_is_single_use(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    assert ledger.admit_smoke().allowed is True
    assert ledger.consume_smoke().allowed is True
    second = ledger.consume_smoke()
    assert second.allowed is False
    assert second.reason == "smoke_already_consumed"


def test_smoke_consume_before_admit_is_refused(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    refused = ledger.consume_smoke()
    assert refused.allowed is False
    assert refused.reason == "smoke_not_admitted"


def test_smoke_turns_and_attempts_are_capped_at_one(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    assert ledger.begin_turn(None).allowed is True
    second_turn = ledger.begin_turn(None)
    assert second_turn.allowed is False
    assert second_turn.reason == "turn_limit"
    assert ledger.begin_attempt(None).allowed is True
    second_attempt = ledger.begin_attempt(None)
    assert second_attempt.allowed is False
    assert second_attempt.reason == "attempt_limit"


async def test_one_admitted_smoke_permits_exactly_one_transport(tmp_path: Path) -> None:
    calls: list[httpx.Request] = []
    ledger = _ledger(tmp_path)
    adapter, provider_policy = _adapter(tmp_path, _ok_handler(calls), ledger=ledger)
    assert provider_policy.admit_smoke().allowed is True
    await adapter.next_step(None)
    assert len(calls) == 1
    # Two further attempts (the parent's reproduced shape) must not reach transport.
    for _ in range(2):
        with pytest.raises(policy.ProviderBudgetExceeded):
            await adapter.next_step(None)
    assert len(calls) == 1, "one smoke admission may authorize at most one transport"
    snapshot = provider_policy.snapshot()
    assert snapshot["smoke_calls"] == 1
    assert snapshot["turns"][policy.SMOKE_KEY] == 1
    assert snapshot["attempts"][policy.SMOKE_KEY] == 1
    await adapter.aclose()


async def test_consumed_smoke_permission_is_not_reusable_across_instances(
    tmp_path: Path,
) -> None:
    path = tmp_path / "provider_budget.json"
    first = policy.JsonBudgetLedger(path)
    adapter_a, policy_a = _adapter(tmp_path, _ok_handler([]), ledger=first)
    assert policy_a.admit_smoke().allowed is True
    await adapter_a.next_step(None)
    await adapter_a.aclose()

    # A fresh "process" over the same durable ledger must see the permission is
    # already consumed and refuse before transport.
    resumed_calls: list[httpx.Request] = []
    second = policy.JsonBudgetLedger(path)
    adapter_b, _ = _adapter(tmp_path, _ok_handler(resumed_calls), ledger=second)
    with pytest.raises(policy.ProviderBudgetExceeded):
        await adapter_b.next_step(None)
    assert resumed_calls == []
    await adapter_b.aclose()


async def test_smoke_is_never_retried(tmp_path: Path) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, json={"error": "busy"})

    ledger = _ledger(tmp_path)
    adapter, provider_policy = _adapter(tmp_path, handler, ledger=ledger, max_retries=5)
    provider_policy.admit_smoke()
    with pytest.raises(ModelUnavailable):
        await adapter.next_step(None)
    assert calls["n"] == 1, "a smoke call must never be retried automatically"
    await adapter.aclose()


# --- round2: billing latch rechecked inside each attempt -----------------------


async def test_billing_latch_between_attempts_refuses_before_second_request(
    tmp_path: Path,
) -> None:
    path = tmp_path / "provider_budget.json"
    ledger = policy.JsonBudgetLedger(path)
    # A *different* ledger instance (as another process would hold) latches the
    # refusal while this adapter is sleeping between attempts.
    other_instance = policy.JsonBudgetLedger(path)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(500, json={"error": "server"})

    async def sleep(_seconds: float) -> None:
        other_instance.mark_billing_refused("provider_billing_refusal_402")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=BASE_URL)
    provider_policy = policy.StagingProviderPolicy(
        eligibility=_reviewed_eligibility(), ledger=ledger
    )
    adapter = OpenAICompatibleAdapter(
        base_url=BASE_URL,
        model="deepseek-v4.1-flash",
        api_key=SYNTHETIC_KEY,
        client=client,
        max_retries=3,
        sleep=sleep,
        policy=provider_policy,
    )
    incident_id = uuid4()
    provider_policy.admit_investigation(incident_id)
    with pytest.raises(policy.ProviderBillingRefusal):
        await adapter.next_step(_context(incident_id))
    assert calls["n"] == 1, "a latch applied between attempts must stop the retry"
    await adapter.aclose()


def test_multiprocess_transport_is_serialized(tmp_path: Path) -> None:
    """Two real OS processes must hold the cross-process transport lock serially."""

    import subprocess
    import sys

    path = tmp_path / "provider_budget.json"
    log = tmp_path / "transport.log"
    incident = "11111111-1111-1111-1111-111111111111"
    code = (
        "import sys, json, time, asyncio, httpx\n"
        "from datetime import datetime, timezone\n"
        "from uuid import UUID\n"
        "from incident_recovery import provider_policy as p\n"
        "from incident_recovery.model_adapter import OpenAICompatibleAdapter\n"
        "from incident_recovery.contracts import InvestigationContext\n"
        "path, log = sys.argv[1], sys.argv[2]\n"
        "elig = p.ProviderEligibility(provider=p.GO_PROVIDER, scope=p.GO_RUNTIME_SCOPE,\n"
        "    status='verified', source=p.OFFICIAL_DOC_URL,\n"
        "    checked_at=datetime(2026,10,12,tzinfo=timezone.utc),\n"
        "    evidence=p.EligibilityEvidence(scope=p.GO_RUNTIME_SCOPE, reviewer='r',\n"
        "        reference='ref', reviewed_at=datetime(2026,10,12,tzinfo=timezone.utc)))\n"
        "led = p.JsonBudgetLedger(path)\n"
        "pol = p.StagingProviderPolicy(eligibility=elig, ledger=led)\n"
        "inc = UUID(sys.argv[3])\n"
        "pol.admit_investigation(inc)\n"
        "def handler(request):\n"
        "    with open(log, 'a') as f:\n"
        "        f.write('enter %s\\n' % time.time())\n"
        "    time.sleep(0.6)\n"
        "    with open(log, 'a') as f:\n"
        "        f.write('exit %s\\n' % time.time())\n"
        "    content = json.dumps({'tool': 'health', 'reason': 'check'})\n"
        "    return httpx.Response(200, json={'choices': [{'message': {'content': content}}]})\n"
        "client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url='http://provider.test/v1')\n"
        "ad = OpenAICompatibleAdapter(base_url='http://provider.test/v1', model='m', api_key='k',\n"
        "    client=client, max_retries=0, policy=pol)\n"
        "ctx = InvestigationContext(incident_id=inc, service_id='demo-api', epoch=1, step=0,\n"
        "    tool_calls_used=0, max_tool_calls=12, seconds_remaining=120.0, observations=[],\n"
        "    adapter_identity='m')\n"
        "async def main():\n"
        "    await ad.next_step(ctx)\n"
        "asyncio.run(main())\n"
    )
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(path), str(log), incident],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    for proc in procs:
        _, err = proc.communicate(timeout=90)
        assert proc.returncode == 0, err
    events = [line.split() for line in log.read_text(encoding="utf-8").splitlines()]
    assert len(events) == 4, events
    # Serialized: strictly enter, exit, enter, exit with no overlapping window.
    assert events[0][0] == "enter" and events[1][0] == "exit"
    assert events[2][0] == "enter" and events[3][0] == "exit"
    first_exit = float(events[1][1])
    second_enter = float(events[2][1])
    assert second_enter >= first_exit, "cross-process transport calls overlapped"


# --- round2: fail-closed validation of an existing ledger ----------------------


def _valid_state(**overrides) -> dict:
    state = policy._empty_state()
    state["smoke_calls"] = 1
    state["smoke_pending"] = False
    state["admitted"] = ["a"]
    state["active_investigation"] = "a"
    state["turns"] = {"a": 2}
    state["attempts"] = {"a": 3}
    state["input_chars"] = {"a": 1000}
    state["usage"] = {
        "a": {"input_tokens": 5, "output_tokens": 7, "total_tokens": 12, "cost": 0.0004}
    }
    state.update(overrides)
    return state


def _write_raw(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    return path.read_text(encoding="utf-8")


def test_valid_current_ledger_loads_and_retains_usage(tmp_path: Path) -> None:
    path = tmp_path / "provider_budget.json"
    path.write_text(json.dumps(_valid_state()), encoding="utf-8")
    snapshot = policy.JsonBudgetLedger(path).snapshot()
    assert snapshot["smoke_calls"] == 1
    assert snapshot["turns"]["a"] == 2
    assert snapshot["attempts"]["a"] == 3
    assert snapshot["input_chars"]["a"] == 1000
    assert snapshot["usage"]["a"]["output_tokens"] == 7


def test_supported_v2_ledger_migrates_and_retains_usage(tmp_path: Path) -> None:
    path = tmp_path / "provider_budget.json"
    legacy = _valid_state()
    legacy.pop("smoke_pending")
    legacy["schema"] = 2
    path.write_text(json.dumps(legacy), encoding="utf-8")
    ledger = policy.JsonBudgetLedger(path)
    snapshot = ledger.snapshot()
    assert snapshot["turns"]["a"] == 2
    assert snapshot["usage"]["a"]["total_tokens"] == 12
    # A mutation upgrades the record without resetting any counter.
    assert ledger.begin_turn("a").allowed is True
    upgraded = json.loads(path.read_text(encoding="utf-8"))
    assert upgraded["schema"] == policy.LEDGER_SCHEMA
    assert upgraded["turns"]["a"] == 3
    assert upgraded["usage"]["a"]["total_tokens"] == 12


@pytest.mark.parametrize(
    "payload",
    [
        "null",
        "{}",
        "[]",
        '{"schema": 3, "scope": "runtime:incident-investigation"',
        json.dumps(_valid_state(smoke_calls=-100)),
        json.dumps(_valid_state(smoke_calls=True)),
        json.dumps(_valid_state(smoke_calls=10**9)),
        json.dumps(_valid_state(scope="some-other-scope")),
        json.dumps(_valid_state(admitted=["a", "a"])),
        json.dumps({**_valid_state(), "unexpected": 1}),
        json.dumps(_valid_state(schema=99)),
        json.dumps(_valid_state(turns={"a": -1})),
        json.dumps(_valid_state(billing_refused="yes")),
    ],
)
def test_corrupt_existing_ledger_fails_closed_without_overwrite(
    tmp_path: Path, payload: str
) -> None:
    path = tmp_path / "provider_budget.json"
    original = _write_raw(path, payload)
    with pytest.raises(policy.ProviderPolicyError):
        policy.JsonBudgetLedger(path)
    assert path.read_text(encoding="utf-8") == original


def test_missing_ledger_initializes_a_new_batch_and_can_admit(tmp_path: Path) -> None:
    path = tmp_path / "provider_budget.json"
    ledger = policy.JsonBudgetLedger(path)
    assert ledger.snapshot()["smoke_calls"] == 0
    assert ledger.admit_smoke().allowed is True
    assert path.is_file()

