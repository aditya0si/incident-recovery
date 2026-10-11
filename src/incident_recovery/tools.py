"""Bounded, read-only investigation tools.

Exactly four tools are exposed: ``health``, ``logs``, ``metrics`` and
``deployments``.  A tool call can never carry a URL, filesystem path, container
identifier, or shell command - the :class:`~incident_recovery.contracts.ToolRequest`
schema forbids every field except the fixed tool name and an optional bounded
line count.  Log and metric text is treated as untrusted data: it is redacted for
secret-shaped values, size-limited, and stored as evidence only.

``collect`` persists one immutable evidence record bound to the incident and the
current investigation epoch, guarded by the caller's lease, so a stale worker can
never write observations.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Iterable, Optional
from uuid import uuid4

import httpx

from .contracts import ToolObservation, ToolRequest
from .models import Evidence, EvidenceType, utcnow

MAX_RESPONSE_BYTES = 8192
DEFAULT_MAX_LINES = 200
_REDACTED = "[REDACTED]"

_SENSITIVE_KEY = (
    r"api[_-]?key|password|passwd|secret|token|authorization|credential|"
    r"model[_-]?api[_-]?key|internal[_-]?token|operator[_-]?token"
)

# A quoted value may contain spaces and backslash escapes; an unquoted value ends
# at whitespace, a quote, a comma, or a semicolon.  Both are supported so a
# ``password="two word secret"`` assignment cannot leak its trailing words.
_QUOTED_OR_BARE_VALUE = (
    r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s\"',;]+"
)


def _redact_scheme(match: "re.Match[str]") -> str:
    return f"{match.group(1)}{_REDACTED}"


def _redact_assignment(match: "re.Match[str]") -> str:
    key, key_quote, separator, value = match.groups()
    if value[:1] in ("'", '"'):
        marker = value[0] + _REDACTED + value[0]
    else:
        marker = _REDACTED
    return f"{key}{key_quote}{separator}{marker}"


_SECRET_PATTERNS = (
    (
        re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)\S+"),
        _redact_scheme,
    ),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{6,}"), _redact_scheme),
    # ``key``/``"key"`` followed by ``:`` or ``=`` and a quoted or bare value.
    # The leading quote of a JSON key is outside the match, so ``"password": ...``
    # is still recognised.  The value keeps its quotes so redacted JSON stays
    # well-formed.  Scope: best-effort pattern redaction, not a DLP guarantee.
    (
        re.compile(
            rf"(?i)({_SENSITIVE_KEY})([\"']?)(\s*[:=]\s*)({_QUOTED_OR_BARE_VALUE})"
        ),
        _redact_assignment,
    ),
)

_SENSITIVE_ENV_VARS = (
    "INTERNAL_TOKEN",
    "OPERATOR_TOKEN",
    "MODEL_API_KEY",
    "POSTGRES_PASSWORD",
)


def redact_secrets(text: str, *, extra: Iterable[str] = ()) -> str:
    """Redact bearer/basic tokens, credential assignments, and known values.

    Scope (best effort, **not** a DLP guarantee): it recognises bearer/basic/token
    authorization headers, standalone bearer tokens, and ``key``/``"key"``
    assignments for secret-shaped names followed by a quoted (spaces/escapes
    allowed) or bare value, including JSON-encoded text and nested JSON/list
    payloads embedded in a string.  It also replaces any configured secret value
    verbatim.  It deliberately does **not** claim to catch arbitrary obfuscation.
    """

    redacted = text
    for pattern, repl in _SECRET_PATTERNS:
        redacted = pattern.sub(repl, redacted)
    values = list(extra)
    for name in _SENSITIVE_ENV_VARS:
        value = os.environ.get(name)
        if value and len(value) >= 4:
            values.append(value)
    for value in values:
        if value and len(value) >= 4:
            redacted = redacted.replace(value, _REDACTED)
    return redacted


def _is_sensitive_key(key: str) -> bool:
    """True when a mapping key names a secret-shaped field (case/variant aware)."""

    return re.search(_SENSITIVE_KEY, key, re.IGNORECASE) is not None


def redact_structure(value, *, extra: Iterable[str] = ()):
    """Recursively redact secret-shaped keys and secret values in a JSON tree.

    A mapping key that names a secret (``password``, ``api_key``, ``token``, ...)
    has its *entire* value replaced by the redaction marker, whatever the value
    type.  String values and keys are additionally passed through
    :func:`redact_secrets` so assignment-like text and configured secret values
    are removed too.  Lists and nested mappings are walked recursively; other
    scalars are preserved.  The input is never mutated.
    """

    if isinstance(value, dict):
        cleaned: dict = {}
        for key, item in value.items():
            key_text = redact_secrets(str(key), extra=extra)
            if _is_sensitive_key(str(key)):
                cleaned[key_text] = _REDACTED
            else:
                cleaned[key_text] = redact_structure(item, extra=extra)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [redact_structure(item, extra=extra) for item in value]
    if isinstance(value, str):
        return redact_secrets(value, extra=extra)
    return value


def _encoded_size(payload) -> int:
    return len(json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8"))


def _truncate_string_within(value: str, budget: int) -> Optional[str]:
    """Return the longest prefix of ``value`` (plus a marker) that fits ``budget``."""

    if _encoded_size(value) <= budget:
        return value
    for suffix in ("[truncated]", ""):
        low, high, best = 0, len(value), None
        while low <= high:
            mid = (low + high) // 2
            candidate = value[:mid] + suffix
            if _encoded_size(candidate) <= budget:
                best = candidate
                low = mid + 1
            else:
                high = mid - 1
        if best is not None:
            return best
    return None


def _fit(value, budget: int):
    """Return a JSON-serializable copy of ``value`` within ``budget`` bytes.

    Returns ``None`` only when even the smallest representation cannot fit, which
    callers treat as "omit this entry".  Guaranteed to make progress: every
    recursive call receives a strictly smaller budget.
    """

    if budget < 2:
        return None
    if _encoded_size(value) <= budget:
        return value
    if isinstance(value, dict):
        return _fit_mapping(value, budget)
    if isinstance(value, list):
        return _fit_list(value, budget)
    if isinstance(value, str):
        return _truncate_string_within(value, budget)
    return _truncate_string_within(str(value), budget)


def _fit_mapping(value: dict, budget: int) -> dict:
    result: dict = {}
    used = 2  # braces
    dropped = False
    for key, item in value.items():
        key_text = str(key)
        entry_overhead = _encoded_size(key_text) + 1 + (1 if result else 0)
        available = budget - used - entry_overhead
        if available < 2:
            dropped = True
            break
        fitted = _fit(item, available)
        if fitted is None:
            dropped = True
            break
        cost = _encoded_size(fitted)
        if used + entry_overhead + cost > budget:
            dropped = True
            break
        result[key_text] = fitted
        used += entry_overhead + cost
    if dropped:
        marker_overhead = _encoded_size("truncated") + 1 + _encoded_size(True) + (1 if result else 0)
        if used + marker_overhead <= budget:
            result["truncated"] = True
    while _encoded_size(result) > budget and result:
        result.popitem()
    return result


def _fit_list(value: list, budget: int) -> list:
    result: list = []
    used = 2  # brackets
    dropped = False
    for item in value:
        sep = 1 if result else 0
        available = budget - used - sep
        if available < 2:
            dropped = True
            break
        fitted = _fit(item, available)
        if fitted is None:
            dropped = True
            break
        cost = _encoded_size(fitted)
        if used + sep + cost > budget:
            dropped = True
            break
        result.append(fitted)
        used += sep + cost
    if dropped:
        marker = "[truncated]"
        marker_cost = _encoded_size(marker) + (1 if result else 0)
        if used + marker_cost <= budget:
            result.append(marker)
    while _encoded_size(result) > budget and result:
        result.pop()
    return result


def _bounded_json(payload: dict, max_bytes: int = MAX_RESPONSE_BYTES) -> dict:
    """Return a copy of ``payload`` whose JSON encoding never exceeds ``max_bytes``.

    A hostile workload can return an arbitrarily large log list, a single huge
    nested string, deep nesting, or multibyte values.  This shrinks the payload
    deterministically and *always* returns something that fits the budget (for any
    budget large enough to hold ``{}``): it walks the tree, truncating strings,
    dropping list/mapping entries, and marking the result ``truncated``.  The
    original mapping is never mutated.  A payload that already fits is returned
    unchanged.
    """

    if _encoded_size(payload) <= max_bytes:
        return payload

    # Reserve room for a top-level ``truncated`` marker so callers can tell the
    # observation was reduced; drop it only when even that cannot fit.
    marker_overhead = _encoded_size({"truncated": True}) - 1  # inner + comma
    inner_budget = max_bytes - marker_overhead
    fitted = _fit(payload, inner_budget) if inner_budget >= 2 else None
    if not isinstance(fitted, dict):
        fitted = {}
    marked = dict(fitted)
    marked["truncated"] = True
    if _encoded_size(marked) <= max_bytes:
        fitted = marked
    # Final hard guarantee: never return a silently oversized payload.
    if _encoded_size(fitted) > max_bytes:
        fitted = _fit(payload, max_bytes)
        if not isinstance(fitted, dict):
            fitted = {}
    if _encoded_size(fitted) > max_bytes:
        fitted = {}
    return fitted


class ToolRunner:
    def __init__(
        self,
        repo,
        gateway_url: str,
        *,
        client: Optional[httpx.AsyncClient] = None,
        timeout: float = 5.0,
        max_lines: int = DEFAULT_MAX_LINES,
        max_bytes: int = MAX_RESPONSE_BYTES,
        clock=utcnow,
    ) -> None:
        self._repo = repo
        self._base = gateway_url.rstrip("/")
        self._client = client
        self._owns_client = client is None
        self._timeout = timeout
        self._max_lines = max_lines
        self._max_bytes = max_bytes
        self._clock = clock

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def observe(self, request: ToolRequest) -> ToolObservation:
        """Perform one bounded read-only observation (no persistence)."""

        if request.tool == "health":
            payload = await self._observe_health()
        elif request.tool == "logs":
            payload = await self._observe_logs(request.lines or 50)
        elif request.tool == "metrics":
            payload = await self._observe_metrics()
        elif request.tool == "deployments":
            payload = await self._observe_deployments()
        else:  # pragma: no cover - schema already restricts the tool name
            raise ValueError(f"unsupported tool {request.tool!r}")
        return ToolObservation(
            evidence_id=uuid4(),
            tool=request.tool,
            observed_at=self._clock(),
            summary=_bounded_json(redact_structure(payload), self._max_bytes),
        )

    async def collect(
        self,
        request: ToolRequest,
        incident_id,
        epoch: int,
        *,
        worker_id: str,
        now: Optional[datetime] = None,
    ) -> Evidence:
        """Observe and persist one immutable, lease-guarded evidence record."""

        observation = await self.observe(request)
        evidence_type = {
            "health": EvidenceType.HEALTH,
            "logs": EvidenceType.LOG,
            "metrics": EvidenceType.METRIC,
            "deployments": EvidenceType.DEPLOYMENT,
        }[request.tool]
        return await self._repo.append_investigation_evidence(
            incident_id,
            epoch,
            f"tool:{request.tool}",
            evidence_type,
            observation.summary,
            worker_id=worker_id,
            now=now or self._clock(),
        )

    # --- individual fixed observations ------------------------------------

    async def _get_json(self, path: str, params: Optional[dict] = None) -> tuple[int, dict]:
        client = self._client
        owns = False
        if client is None:
            client = httpx.AsyncClient(base_url=self._base, timeout=self._timeout)
            owns = True
        try:
            response = await client.get(path, params=params, timeout=self._timeout)
        finally:
            if owns:
                await client.aclose()
        try:
            body = response.json()
        except ValueError:
            body = {}
        return response.status_code, body

    async def _observe_health(self) -> dict:
        snapshot_status, snapshot = await self._get_json("/snapshot")
        health_status, health = await self._get_json("/api/health")
        functional_ok = health_status == 200 and health.get("status") == "pass"
        return {
            "tool": "health",
            "revision": snapshot.get("revision") or health.get("revision"),
            "generation": snapshot.get("generation"),
            "http_status": health_status,
            "functional_ok": functional_ok,
            "detail": "functional_pass" if functional_ok else f"functional_fail:{health_status}",
        }

    async def _observe_logs(self, lines: int) -> dict:
        bounded_lines = max(1, min(int(lines), self._max_lines))
        status, body = await self._get_json("/api/logs", {"lines": bounded_lines})
        raw = body.get("lines", []) if isinstance(body, dict) else []
        rendered: list[dict] = []
        for entry in raw[:bounded_lines]:
            if isinstance(entry, dict):
                # Preserve nested structure so recursive redaction can walk it;
                # redaction happens centrally in ``observe`` before bounding.
                rendered.append(dict(entry))
            else:
                rendered.append({"message": str(entry)})
        return {
            "tool": "logs",
            "http_status": status,
            "count": len(rendered),
            "lines": rendered,
        }

    async def _observe_metrics(self) -> dict:
        status, body = await self._get_json("/api/metrics")
        if not isinstance(body, dict):
            body = {}
        cleaned = {}
        for key, value in body.items():
            if isinstance(value, str):
                cleaned[key] = redact_secrets(value)
            elif isinstance(value, dict):
                cleaned[key] = {
                    str(k): (redact_secrets(str(v)) if isinstance(v, str) else v)
                    for k, v in value.items()
                }
            else:
                cleaned[key] = value
        cleaned["http_status"] = status
        cleaned["tool"] = "metrics"
        return cleaned

    async def _observe_deployments(self) -> dict:
        snapshot = await self._repo.get_deployment_snapshot()
        history = await self._repo.list_deployment_history(limit=20)
        return {
            "tool": "deployments",
            "service_id": snapshot.service_id,
            "current_revision": snapshot.revision,
            "generation": snapshot.generation,
            "predecessor": snapshot.predecessor,
            "history": [
                {
                    "from_revision": row.get("from_revision"),
                    "to_revision": row.get("to_revision"),
                    "generation": row.get("generation"),
                }
                for row in history
            ],
        }
