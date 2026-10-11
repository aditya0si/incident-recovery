"""Provider eligibility gate, truthful client/session contract, and error handling.

Task 2 tests for :mod:`incident_recovery.provider_policy` and the bounded staging
path of :class:`incident_recovery.model_adapter.OpenAICompatibleAdapter`.

These tests never make a real provider call: every transport is an
``httpx.MockTransport`` and every credential is a clearly synthetic token.  The
central property under test is that a *blocked* eligibility gate prevents **any**
network request, that a fake/unsupported eligibility cannot turn it on, and that
the adapter tells the truth about who it is and which incident session it holds.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from incident_recovery import provider_policy as policy
from incident_recovery.model_adapter import OpenAICompatibleAdapter
from incident_recovery.models import ModelProtocolError, ModelUnavailable

REPO_ROOT = Path(__file__).resolve().parents[2]
READINESS_DOC = REPO_ROOT / "docs" / "staging-readiness.md"

SYNTHETIC_KEY = "sk-staging-SYNTHETIC-0123456789abcdef"
BASE_URL = "http://provider.test/v1"


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
            reference="reviewed scoped eligibility for runtime:incident-investigation",
            reviewed_at=datetime(2026, 10, 12, tzinfo=timezone.utc),
        ),
    )


def _ledger(tmp_path: Path) -> policy.JsonBudgetLedger:
    return policy.JsonBudgetLedger(tmp_path / "provider_budget.json")


def _policy(
    tmp_path: Path, eligibility: policy.ProviderEligibility | None = None
) -> policy.StagingProviderPolicy:
    return policy.StagingProviderPolicy(
        eligibility=eligibility or policy.default_go_runtime_eligibility(),
        ledger=_ledger(tmp_path),
    )


def _staging_adapter(
    tmp_path: Path,
    handler,
    *,
    eligibility: policy.ProviderEligibility | None = None,
    max_retries: int = 0,
    max_tokens: int = 4096,
) -> tuple[OpenAICompatibleAdapter, policy.StagingProviderPolicy]:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url=BASE_URL
    )
    provider_policy = _policy(tmp_path, eligibility)
    adapter = OpenAICompatibleAdapter(
        base_url=BASE_URL,
        model="deepseek-v4.1-flash",
        api_key=SYNTHETIC_KEY,
        client=client,
        max_retries=max_retries,
        max_tokens=max_tokens,
        sleep=_noop_sleep,
        policy=provider_policy,
    )
    return adapter, provider_policy


def _ok_handler(record: list[httpx.Request]):
    def handler(request: httpx.Request) -> httpx.Response:
        record.append(request)
        content = json.dumps({"tool": "health", "reason": "check"})
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": content}}],
                "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
            },
        )

    return handler


# --- eligibility gate ---------------------------------------------------------


def test_default_go_runtime_eligibility_is_blocked_with_official_source() -> None:
    eligibility = policy.default_go_runtime_eligibility()
    assert eligibility.status == policy.EligibilityStatus.BLOCKED.value
    assert eligibility.scope == policy.GO_RUNTIME_SCOPE
    assert eligibility.provider == policy.GO_PROVIDER
    assert eligibility.source == policy.OFFICIAL_DOC_URL
    assert eligibility.evidence is None
    assert policy.go_runtime_eligible(eligibility) is False


async def test_blocked_eligibility_prevents_any_transport_call(tmp_path: Path) -> None:
    record: list[httpx.Request] = []
    adapter, _ = _staging_adapter(tmp_path, _ok_handler(record))
    with pytest.raises(policy.ProviderNotEligible):
        await adapter.next_step(None)
    assert record == [], "blocked eligibility must never reach the transport"
    await adapter.aclose()


@pytest.mark.parametrize(
    "fake",
    [
        # status claims verified but there is no reviewed evidence at all
        dict(status="verified"),
        # a boolean-ish / wordy status is not the reviewed evidence enum
        dict(status="approved"),
        dict(status=True),
        # verified with evidence but the wrong provider
        dict(status="verified", provider="some-other"),
        # verified but the scope is not the reviewed runtime scope
        dict(status="verified", scope="coding"),
        # evidence present but its own scope does not match
        dict(status="verified", evidence_scope="coding"),
        # evidence present but reviewer empty
        dict(status="verified", reviewer=""),
        # evidence present but reference empty
        dict(status="verified", reference=""),
    ],
)
def test_fake_or_unsupported_eligibility_cannot_enable(fake: dict) -> None:
    kwargs = dict(
        provider=policy.GO_PROVIDER,
        scope=policy.GO_RUNTIME_SCOPE,
        status="blocked",
        source=policy.OFFICIAL_DOC_URL,
        checked_at=datetime(2026, 10, 12, tzinfo=timezone.utc),
        evidence=None,
    )
    kwargs.update({k: v for k, v in fake.items() if k not in ("evidence_scope", "reviewer", "reference")})
    if any(k in fake for k in ("evidence_scope", "reviewer", "reference")):
        kwargs["evidence"] = policy.EligibilityEvidence(
            scope=fake.get("evidence_scope", policy.GO_RUNTIME_SCOPE),
            reviewer=fake.get("reviewer", "parent-reviewer"),
            reference=fake.get("reference", "reviewed evidence"),
            reviewed_at=datetime(2026, 10, 12, tzinfo=timezone.utc),
        )
    eligibility = policy.ProviderEligibility(**kwargs)
    assert policy.go_runtime_eligible(eligibility) is False


def test_reviewed_scoped_eligibility_enables() -> None:
    assert policy.go_runtime_eligible(_reviewed_eligibility()) is True


async def test_reviewed_eligibility_allows_the_transport_call(tmp_path: Path) -> None:
    record: list[httpx.Request] = []
    adapter, _ = _staging_adapter(
        tmp_path, _ok_handler(record), eligibility=_reviewed_eligibility()
    )
    step = await adapter.next_step(None)
    assert step is not None
    assert len(record) == 1
    await adapter.aclose()


def test_load_eligibility_defaults_to_blocked() -> None:
    assert policy.go_runtime_eligible(policy.load_go_runtime_eligibility({})) is False


def test_load_eligibility_reads_reviewed_document(tmp_path: Path) -> None:
    doc = tmp_path / "eligibility.json"
    doc.write_text(
        json.dumps(
            {
                "provider": policy.GO_PROVIDER,
                "scope": policy.GO_RUNTIME_SCOPE,
                "status": "verified",
                "source": policy.OFFICIAL_DOC_URL,
                "reviewer": "parent-reviewer",
                "reference": "reviewed scoped eligibility",
                "reviewed_at": "2026-10-12T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    eligibility = policy.load_go_runtime_eligibility(
        {"OPENCODE_GO_RUNTIME_ELIGIBILITY": str(doc)}
    )
    assert policy.go_runtime_eligible(eligibility) is True


def test_load_eligibility_missing_document_stays_blocked(tmp_path: Path) -> None:
    eligibility = policy.load_go_runtime_eligibility(
        {"OPENCODE_GO_RUNTIME_ELIGIBILITY": str(tmp_path / "absent.json")}
    )
    assert policy.go_runtime_eligible(eligibility) is False


# --- session contract ---------------------------------------------------------


def test_session_is_stable_per_incident_and_distinct_across_incidents() -> None:
    first = uuid4()
    second = uuid4()
    assert policy.session_for_incident(first) == policy.session_for_incident(first)
    assert policy.session_for_incident(first) != policy.session_for_incident(second)
    assert policy.session_for_incident(first) != policy.SMOKE_SESSION


def test_session_survives_adapter_rebuild(tmp_path: Path) -> None:
    incident_id = uuid4()
    adapter_a, _ = _staging_adapter(tmp_path, _ok_handler([]), eligibility=_reviewed_eligibility())
    adapter_b, _ = _staging_adapter(tmp_path, _ok_handler([]), eligibility=_reviewed_eligibility())
    assert adapter_a.session_for(incident_id) == adapter_b.session_for(incident_id)
    assert adapter_a.session_for(None) == policy.SMOKE_SESSION


async def test_request_carries_truthful_user_agent_and_stable_session(tmp_path: Path) -> None:
    from incident_recovery.contracts import InvestigationContext

    record: list[httpx.Request] = []
    adapter, _ = _staging_adapter(
        tmp_path, _ok_handler(record), eligibility=_reviewed_eligibility()
    )
    incident_id = uuid4()
    context = InvestigationContext(
        incident_id=incident_id,
        service_id="demo-api",
        epoch=1,
        step=0,
        tool_calls_used=0,
        max_tool_calls=12,
        seconds_remaining=120.0,
        observations=[],
        adapter_identity="openai-compatible:deepseek-v4.1-flash",
    )
    await adapter.next_step(context)
    await adapter.next_step(context)
    assert len(record) == 2
    expected_session = policy.session_for_incident(incident_id)
    for request in record:
        assert request.headers["User-Agent"] == policy.USER_AGENT
        assert request.headers["x-opencode-session"] == expected_session
        assert request.headers["Authorization"] == f"Bearer {SYNTHETIC_KEY}"
    # Same turn session on every retry/call, not a process-global value.
    assert record[0].headers["x-opencode-session"] == record[1].headers["x-opencode-session"]
    await adapter.aclose()


# --- failure handling and redaction -------------------------------------------


async def test_malformed_provider_json_is_a_protocol_error(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "not json"}}]})

    adapter, _ = _staging_adapter(
        tmp_path, handler, eligibility=_reviewed_eligibility()
    )
    with pytest.raises(ModelProtocolError):
        await adapter.next_step(None)
    await adapter.aclose()


async def test_provider_401_is_unavailable_and_not_retried(tmp_path: Path) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(401, json={"error": "invalid api key"})

    adapter, _ = _staging_adapter(
        tmp_path, handler, eligibility=_reviewed_eligibility(), max_retries=2
    )
    with pytest.raises(ModelUnavailable):
        await adapter.next_step(None)
    assert calls["n"] == 1, "authentication failures must not be retried"
    await adapter.aclose()


async def test_billing_refusal_stops_without_model_substitution(tmp_path: Path) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(402, json={"error": "insufficient credit balance"})

    adapter, _ = _staging_adapter(
        tmp_path, handler, eligibility=_reviewed_eligibility(), max_retries=3
    )
    with pytest.raises(policy.ProviderBillingRefusal):
        await adapter.next_step(None)
    assert calls["n"] == 1, "billing refusal must stop immediately, never retry"
    assert "deepseek-v4.1-flash" in adapter.identity
    await adapter.aclose()


async def test_timeout_is_reported_as_unavailable(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    adapter, _ = _staging_adapter(
        tmp_path, handler, eligibility=_reviewed_eligibility(), max_retries=1
    )
    with pytest.raises(ModelUnavailable):
        await adapter.next_step(None)
    await adapter.aclose()


async def test_secret_is_never_exposed_in_errors_or_evidence(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "server error"})

    adapter, provider_policy = _staging_adapter(
        tmp_path, handler, eligibility=_reviewed_eligibility(), max_retries=0
    )
    with pytest.raises(ModelUnavailable) as excinfo:
        await adapter.next_step(None)
    assert SYNTHETIC_KEY not in str(excinfo.value)
    assert SYNTHETIC_KEY not in repr(excinfo.value)
    snapshot = json.dumps(provider_policy.snapshot())
    assert SYNTHETIC_KEY not in snapshot
    assert "Authorization" not in snapshot
    await adapter.aclose()


# --- default behavior is preserved --------------------------------------------


async def test_adapter_without_policy_is_unchanged(tmp_path: Path) -> None:
    record: list[httpx.Request] = []
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(_ok_handler(record)), base_url=BASE_URL
    )
    adapter = OpenAICompatibleAdapter(
        base_url=BASE_URL, model="m", api_key="k", client=client, max_retries=0
    )
    step = await adapter.next_step(None)
    assert step is not None
    assert len(record) == 1
    assert policy.USER_AGENT not in record[0].headers.get("user-agent", "")
    assert "x-opencode-session" not in record[0].headers
    await adapter.aclose()


# --- public docs record the blocked live gate ---------------------------------


def test_readiness_doc_records_blocked_live_provider_gate() -> None:
    text = READINESS_DOC.read_text(encoding="utf-8")
    lowered = text.lower()
    assert policy.OFFICIAL_DOC_URL in text
    assert "eligibility remains blocked" in lowered
    # It must record that no live call happened, not imply live compatibility.
    assert "no live provider call was made" in lowered
