"""Unit tests for byte-bounded, redacted tool observations.

Finding 3 (adversarial repair): ``_bounded_json`` must *always* return a payload
whose canonical JSON encoding fits the byte budget, including a single-element
list holding one huge string, deep nesting, multibyte characters, and tiny
budgets.  The previous implementation halved the largest list, so a list with a
single element never shrank and the oversized payload was returned unchanged.
"""

from __future__ import annotations

import asyncio
import json

import httpx

from incident_recovery.contracts import ToolRequest
from incident_recovery.tools import (
    MAX_RESPONSE_BYTES,
    ToolRunner,
    _bounded_json,
    redact_secrets,
    redact_structure,
)

SENTINEL = "SYNTHETIC_SENTINEL"


def _size(payload) -> int:
    return len(json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8"))


def _sentinel_payload() -> dict:
    return {
        "password": SENTINEL,
        "nested": {"deeper": {"password": SENTINEL}},
        "list": [{"token": SENTINEL}],
    }


# --- the exact reported defect ------------------------------------------------


def test_single_huge_entry_is_byte_bounded() -> None:
    payload = {"lines": [{"message": "x" * 20000}]}
    assert _size(payload) > MAX_RESPONSE_BYTES
    result = _bounded_json(payload, MAX_RESPONSE_BYTES)
    assert _size(result) <= MAX_RESPONSE_BYTES
    assert isinstance(result, dict)
    assert result.get("truncated") is True
    # The original mapping was not mutated.
    assert _size(payload) > MAX_RESPONSE_BYTES


def test_multiple_entries_are_byte_bounded() -> None:
    payload = {"lines": [{"message": "y" * 900} for _ in range(200)]}
    result = _bounded_json(payload, MAX_RESPONSE_BYTES)
    assert _size(result) <= MAX_RESPONSE_BYTES
    assert result.get("truncated") is True


def test_nested_structures_are_byte_bounded() -> None:
    payload = {
        "a": {"b": {"c": [{"message": "z" * 5000} for _ in range(50)]}},
        "d": [{"deep": {"deeper": {"deepest": "q" * 8000}}}],
    }
    result = _bounded_json(payload, MAX_RESPONSE_BYTES)
    assert _size(result) <= MAX_RESPONSE_BYTES
    assert result.get("truncated") is True


def test_multibyte_characters_are_byte_bounded() -> None:
    # Multibyte content expands to \uXXXX escapes in canonical JSON.
    payload = {"lines": [{"message": "\u00e9\u00e9\U0001f600" * 4000}]}
    assert _size(payload) > MAX_RESPONSE_BYTES
    result = _bounded_json(payload, MAX_RESPONSE_BYTES)
    assert _size(result) <= MAX_RESPONSE_BYTES


def test_tiny_budgets_are_never_oversized() -> None:
    payload = {"lines": [{"message": "x" * 20000}], "other": {"deep": ["y" * 100, "z" * 100]}}
    for budget in (2, 3, 8, 16, 64, 256):
        result = _bounded_json(payload, budget)
        assert isinstance(result, dict)
        assert _size(result) <= budget, (budget, _size(result))


def test_exact_budget_is_respected() -> None:
    payload = {"tool": "logs", "count": 1, "lines": [{"message": "ok"}]}
    exact = _size(payload)
    unchanged = _bounded_json(payload, exact)
    assert unchanged == payload
    shrunk = _bounded_json(payload, exact - 1)
    assert _size(shrunk) <= exact - 1


def test_small_payload_within_budget_is_untouched() -> None:
    payload = {"tool": "health", "http_status": 200, "functional_ok": True}
    assert _bounded_json(payload, MAX_RESPONSE_BYTES) == payload


def test_bounded_observation_keeps_useful_prefix() -> None:
    payload = {"tool": "logs", "http_status": 200, "count": 3,
               "lines": [{"message": "first"}, {"message": "x" * 20000}, {"message": "last"}]}
    result = _bounded_json(payload, MAX_RESPONSE_BYTES)
    assert _size(result) <= MAX_RESPONSE_BYTES
    assert result.get("tool") == "logs"
    assert result.get("http_status") == 200


# --- recursive secret redaction (Finding 4) -----------------------------------


def test_redact_structure_redacts_secret_keys_recursively() -> None:
    result = redact_structure(_sentinel_payload())
    assert SENTINEL not in json.dumps(result)
    assert result["password"] == "[REDACTED]"
    assert result["nested"]["deeper"]["password"] == "[REDACTED]"
    assert result["list"][0]["token"] == "[REDACTED]"


def test_redact_structure_preserves_nonsecret_controls() -> None:
    payload = {
        "tool": "metrics",
        "revision": "broken-v2",
        "generation": 2,
        "http_status": 503,
        "uptime_seconds": 12.5,
        "message": "functional failure",
    }
    assert redact_structure(payload) == payload


def test_redact_structure_covers_case_and_key_variants() -> None:
    payload = {
        "API_KEY": SENTINEL,
        "Api-Key": SENTINEL,
        "Authorization": SENTINEL,
        "passwd": SENTINEL,
        "credential": SENTINEL,
        "operator_token": SENTINEL,
        "model_api_key": SENTINEL,
        "INTERNAL_TOKEN": SENTINEL,
        "note": "safe",
    }
    result = redact_structure(payload)
    assert SENTINEL not in json.dumps(result)
    for key in payload:
        if key != "note":
            assert result[key] == "[REDACTED]", key
    assert result["note"] == "safe"


def test_redact_structure_redacts_assignment_text_in_values() -> None:
    payload = {
        "message": "Authorization: Bearer synthetic-bearer-token",
        "detail": "api_key=syntheticvalue123",
    }
    result = redact_structure(payload)
    assert "synthetic-bearer-token" not in json.dumps(result)
    assert "syntheticvalue123" not in json.dumps(result)
    assert result["message"].count("[REDACTED]") >= 1


def test_tool_runner_observe_metrics_redacts_nested_secrets() -> None:
    """Finding 4: metrics observation must not retain nested/list secrets."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/metrics"
        body = _sentinel_payload()
        body["revision"] = "broken-v2"
        body["http_status"] = 200
        return httpx.Response(200, json=body)

    async def run() -> None:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://gateway.test"
        )
        runner = ToolRunner(repo=None, gateway_url="http://gateway.test", client=client)
        try:
            observation = await runner.observe(ToolRequest(tool="metrics"))
        finally:
            await client.aclose()
        blob = json.dumps(observation.summary)
        assert SENTINEL not in blob
        assert observation.summary["nested"]["deeper"]["password"] == "[REDACTED]"
        assert observation.summary["list"][0]["token"] == "[REDACTED]"
        # Nonsecret controls survive so the observation stays useful.
        assert observation.summary["revision"] == "broken-v2"

    asyncio.run(run())


def test_tool_runner_observe_logs_redacts_nested_secret_keys() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/logs"
        return httpx.Response(
            200,
            json={"lines": [{"message": "ok", "meta": {"token": SENTINEL}}]},
        )

    async def run() -> None:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://gateway.test"
        )
        runner = ToolRunner(repo=None, gateway_url="http://gateway.test", client=client)
        try:
            observation = await runner.observe(ToolRequest(tool="logs", lines=5))
        finally:
            await client.aclose()
        assert SENTINEL not in json.dumps(observation.summary)

    asyncio.run(run())


# --- Finding 1 (round 2): structured/quoted secret text in log strings --------


def test_redact_secrets_redacts_json_encoded_line() -> None:
    """The exact reproduced defect: ``json.dumps({'password': ...})`` survives."""

    text = json.dumps({"password": SENTINEL})
    result = redact_secrets(text)
    assert SENTINEL not in result
    assert "password" in result
    assert "[REDACTED]" in result


def test_redact_secrets_redacts_quoted_key_and_value_variants() -> None:
    for text in (
        json.dumps({"password": SENTINEL}),
        json.dumps({"api_key": SENTINEL}),
        '{"Authorization": "' + SENTINEL + '"}',
        "password: " + SENTINEL,
        "PASSWORD=" + SENTINEL,
        "Api-Key:'" + SENTINEL + "'",
    ):
        assert SENTINEL not in redact_secrets(text), text


def test_redact_secrets_redacts_quoted_value_with_spaces() -> None:
    """A quoted multi-word value must not leak its trailing words."""

    result = redact_secrets('password="synthetic alpha bravo"')
    for word in ("synthetic", "alpha", "bravo"):
        assert word not in result
    assert "[REDACTED]" in result


def test_redact_secrets_redacts_nested_json_and_lists() -> None:
    text = json.dumps(
        {"entries": [{"api_key": SENTINEL}, {"token": SENTINEL}], "ok": 1}
    )
    result = redact_secrets(text)
    assert SENTINEL not in result
    assert '"ok"' in result


def test_redact_secrets_redacts_escaped_quoted_value() -> None:
    text = 'password="pa\\"ss ' + SENTINEL + '"'
    result = redact_secrets(text)
    assert SENTINEL not in result


def test_redact_secrets_redacts_header_and_scheme_forms() -> None:
    text = "Authorization: Basic basiccredential123"
    assert "basiccredential123" not in redact_secrets(text)
    assert SENTINEL not in redact_secrets("X-Internal-Token: " + SENTINEL)
    assert SENTINEL not in redact_secrets("operator_token=" + SENTINEL)


def test_redact_secrets_preserves_nonsecret_text_controls() -> None:
    text = "http_status: 503 revision=broken-v2 message=functional_failure"
    assert redact_secrets(text) == text


def test_tool_runner_logs_redacts_json_secret_before_truncation() -> None:
    secret_line = json.dumps({"password": SENTINEL})

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"lines": [{"message": secret_line + " " + "x" * 20000}]},
        )

    async def run() -> None:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://gateway.test"
        )
        runner = ToolRunner(repo=None, gateway_url="http://gateway.test", client=client)
        try:
            observation = await runner.observe(ToolRequest(tool="logs", lines=5))
        finally:
            await client.aclose()
        blob = json.dumps(observation.summary)
        assert SENTINEL not in blob
        assert len(observation.summary.__repr__()) < 9000

    asyncio.run(run())


def test_tool_runner_logs_redacts_quoted_trailing_words() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"lines": [{"message": 'password="synthetic alpha bravo"'}]},
        )

    async def run() -> None:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://gateway.test"
        )
        runner = ToolRunner(repo=None, gateway_url="http://gateway.test", client=client)
        try:
            observation = await runner.observe(ToolRequest(tool="logs", lines=5))
        finally:
            await client.aclose()
        blob = json.dumps(observation.summary)
        for word in ("synthetic", "alpha", "bravo"):
            assert word not in blob

    asyncio.run(run())


# --- Round 3: structural JSON container secret values ------------------------
#
# The round-3 probe shapes, reproduced verbatim.  ``redact_secrets`` on a
# JSON-encoded string must structurally redact a secret key's *entire* value,
# whatever its type (scalar, list, or nested object), rather than matching the
# single opening bracket of a container and leaking the elements after it.

_ROUND3_JSON_SENTINEL = "SYNTHETIC alpha beta"
_ROUND3_SECOND_SENTINEL = "SECOND_SENTINEL"


def test_redact_secrets_redacts_json_list_valued_secret() -> None:
    """The exact reported defect: a list-valued secret leaked both elements."""

    text = json.dumps({"password": [_ROUND3_JSON_SENTINEL, _ROUND3_SECOND_SENTINEL]})
    result = redact_secrets(text)
    assert _ROUND3_JSON_SENTINEL not in result
    assert _ROUND3_SECOND_SENTINEL not in result
    assert "[REDACTED]" in result
    assert "password" in result


def test_redact_secrets_redacts_json_object_valued_secret() -> None:
    text = json.dumps({"password": {"value": _ROUND3_JSON_SENTINEL}})
    result = redact_secrets(text)
    assert _ROUND3_JSON_SENTINEL not in result
    assert "[REDACTED]" in result


def test_redact_structure_redacts_container_valued_secret_keys() -> None:
    payload = {
        "password": [_ROUND3_JSON_SENTINEL, _ROUND3_SECOND_SENTINEL],
        "token": {"nested": [_ROUND3_JSON_SENTINEL]},
        "note": "safe",
    }
    result = redact_structure(payload)
    assert result["password"] == "[REDACTED]"
    assert result["token"] == "[REDACTED]"
    assert result["note"] == "safe"
    blob = json.dumps(result)
    assert _ROUND3_JSON_SENTINEL not in blob
    assert _ROUND3_SECOND_SENTINEL not in blob


def test_redact_secrets_redacts_nested_nonsensitive_containers() -> None:
    text = json.dumps(
        {
            "config": {"database": {"password": [_ROUND3_JSON_SENTINEL, _ROUND3_SECOND_SENTINEL]}},
            "ok": 1,
        }
    )
    result = redact_secrets(text)
    assert _ROUND3_JSON_SENTINEL not in result
    assert _ROUND3_SECOND_SENTINEL not in result
    reparsed = json.loads(result)
    assert reparsed["config"]["database"]["password"] == "[REDACTED]"
    assert reparsed["ok"] == 1


def test_redact_secrets_redacts_json_fragment_with_prefix_and_suffix() -> None:
    fragment = json.dumps({"password": [_ROUND3_JSON_SENTINEL, _ROUND3_SECOND_SENTINEL]})
    text = "INFO payload=" + fragment + " done"
    result = redact_secrets(text)
    assert _ROUND3_JSON_SENTINEL not in result
    assert _ROUND3_SECOND_SENTINEL not in result
    assert result.startswith("INFO payload=")
    assert result.endswith(" done")


def test_redact_secrets_fails_closed_on_malformed_sensitive_container() -> None:
    for text in (
        'password: ["' + _ROUND3_JSON_SENTINEL + '", "' + _ROUND3_SECOND_SENTINEL + '"',
        '{"password": ["' + _ROUND3_JSON_SENTINEL + '", "' + _ROUND3_SECOND_SENTINEL + '"',
    ):
        result = redact_secrets(text)
        assert _ROUND3_JSON_SENTINEL not in result, text
        assert _ROUND3_SECOND_SENTINEL not in result, text


def test_redact_secrets_preserves_ordinary_json_control() -> None:
    text = json.dumps({"count": 5, "revision": "broken-v2", "nested": {"ok": True}})
    assert redact_secrets(text) == text
    compact = json.dumps({"count": 5, "revision": "broken-v2"}, separators=(",", ":"))
    assert redact_secrets(compact) == compact


def test_redact_secrets_preserves_unicode_ordinary_json() -> None:
    text = json.dumps({"note": "caf\u00e9 \U0001f600"}, ensure_ascii=False)
    assert redact_secrets(text) == text


def test_redact_secrets_redacts_error_render_with_json_container() -> None:
    text = (
        'rollback failed: {"password": ['
        + json.dumps(_ROUND3_JSON_SENTINEL)
        + ", "
        + json.dumps(_ROUND3_SECOND_SENTINEL)
        + "]}"
    )
    result = redact_secrets(text)
    assert _ROUND3_JSON_SENTINEL not in result
    assert _ROUND3_SECOND_SENTINEL not in result
    assert result.startswith("rollback failed: ")


def test_tool_runner_observe_logs_redacts_json_container_secret() -> None:
    """The reproduced real sink: a JSON-encoded log line with a list secret."""

    secret_line = json.dumps({"password": [_ROUND3_JSON_SENTINEL, _ROUND3_SECOND_SENTINEL]})

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/logs"
        return httpx.Response(200, json={"lines": [{"message": secret_line}]})

    async def run() -> None:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://gateway.test"
        )
        runner = ToolRunner(repo=None, gateway_url="http://gateway.test", client=client)
        try:
            observation = await runner.observe(ToolRequest(tool="logs", lines=5))
        finally:
            await client.aclose()
        blob = json.dumps(observation.summary)
        assert _ROUND3_JSON_SENTINEL not in blob
        assert _ROUND3_SECOND_SENTINEL not in blob

    asyncio.run(run())


def test_provider_errors_do_not_leak_api_key() -> None:
    from incident_recovery.model_adapter import OpenAICompatibleAdapter
    from incident_recovery.models import ModelUnavailable

    secret = "sk-synthetic-provider-credential-123456"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    async def run() -> None:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://model.test/v1"
        )
        adapter = OpenAICompatibleAdapter(
            base_url="http://model.test/v1", model="m", api_key=secret,
            client=client, max_retries=0,
        )
        try:
            try:
                await adapter.next_step(None)
            except ModelUnavailable as exc:
                assert secret not in str(exc)
                assert secret not in repr(exc)
            else:  # pragma: no cover - must raise
                raise AssertionError("expected ModelUnavailable")
        finally:
            await client.aclose()

    asyncio.run(run())
