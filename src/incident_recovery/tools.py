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

_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)\S+"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{6,}"),
    re.compile(rf"(?i)({_SENSITIVE_KEY})\s*[:=]\s*[\"']?([^\s\"',;]+)"),
)

_SENSITIVE_ENV_VARS = (
    "INTERNAL_TOKEN",
    "OPERATOR_TOKEN",
    "MODEL_API_KEY",
    "POSTGRES_PASSWORD",
)


def redact_secrets(text: str, *, extra: Iterable[str] = ()) -> str:
    """Redact bearer tokens, credential assignments, and known secret values."""

    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(
            lambda match: (
                f"{match.group(1)}{_REDACTED}"
                if match.lastindex == 1
                else f"{match.group(1)}={_REDACTED}"
            ),
            redacted,
        )
    values = list(extra)
    for name in _SENSITIVE_ENV_VARS:
        value = os.environ.get(name)
        if value and len(value) >= 4:
            values.append(value)
    for value in values:
        if value and len(value) >= 4:
            redacted = redacted.replace(value, _REDACTED)
    return redacted


def _bounded_json(payload: dict, max_bytes: int = MAX_RESPONSE_BYTES) -> dict:
    encoded = json.dumps(payload, separators=(",", ":"), default=str)
    if len(encoded.encode("utf-8")) <= max_bytes:
        return payload
    # Drop the largest list-valued field first, then hard-truncate a blob.
    trimmed = dict(payload)
    for key, value in list(trimmed.items()):
        if isinstance(value, list) and len(value) > 1:
            trimmed[key] = value[: max(1, len(value) // 2)]
            trimmed["truncated"] = True
            if len(json.dumps(trimmed, default=str).encode("utf-8")) <= max_bytes:
                return trimmed
    trimmed["truncated"] = True
    return trimmed


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
            summary=_bounded_json(payload, self._max_bytes),
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
                rendered.append(
                    {key: redact_secrets(str(value)) for key, value in entry.items()}
                )
            else:
                rendered.append({"message": redact_secrets(str(entry))})
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
