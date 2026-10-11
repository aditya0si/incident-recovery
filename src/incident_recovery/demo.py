"""Predefined demo workload deployed as healthy-v1 and broken-v2.

The two demo services use the same image with a different ``DEMO_REVISION``.
``healthy-v1`` produces a correct functional result; ``broken-v2`` contains a
genuine functional regression. Process liveness (``/livez``) stays up on both,
so liveness is never confused with functional health.

The workload also exposes *real* bounded observations for the investigation
tools: an in-memory structured log ring buffer (``/logs``) and actual runtime
request counters (``/metrics``).  These are derived from real handled requests,
not fabricated monitoring values.
"""

from __future__ import annotations

import os
import time
from collections import deque
from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse

MAX_LOG_LINES = 200


class FunctionalRegression(RuntimeError):
    """Raised by the broken revision to model a real application failure."""


def compute_result(revision: str) -> int:
    """Return the demo's functional result, or raise for the broken revision."""

    if revision == "healthy-v1":
        return 42
    if revision == "broken-v2":
        raise FunctionalRegression("upstream dependency contract mismatch in broken-v2")
    raise FunctionalRegression(f"unknown demo revision: {revision!r}")


def create_demo_app(revision: str) -> FastAPI:
    app = FastAPI(title=f"demo-api ({revision})", docs_url=None, redoc_url=None)

    started_at = time.time()
    counters = {"requests_total": 0, "requests_failed": 0, "by_revision": {}}
    logs: deque[dict] = deque(maxlen=MAX_LOG_LINES)

    @app.middleware("http")
    async def _observe(request: Request, call_next):
        counters["requests_total"] += 1
        response = await call_next(request)
        status = response.status_code
        if status >= 500:
            counters["requests_failed"] += 1
        counters["by_revision"][revision] = counters["by_revision"].get(revision, 0) + 1
        logs.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "level": "error" if status >= 500 else "info",
                "path": request.url.path,
                "status": status,
                "revision": revision,
                "message": f"{request.method} {request.url.path} -> {status}",
            }
        )
        return response

    @app.get("/livez")
    async def livez() -> dict:
        # Process liveness only; deliberately independent of functionality.
        return {"live": True, "revision": revision}

    @app.get("/work")
    async def work():
        try:
            result = compute_result(revision)
        except FunctionalRegression as exc:
            return JSONResponse(
                status_code=500,
                content={"ok": False, "revision": revision, "error": str(exc)},
            )
        return {"ok": True, "revision": revision, "result": result}

    @app.get("/health")
    async def health():
        # Functional health: succeeds only when the workload actually works.
        try:
            compute_result(revision)
        except FunctionalRegression as exc:
            return JSONResponse(
                status_code=503,
                content={"status": "fail", "revision": revision, "error": str(exc)},
            )
        return {"status": "pass", "revision": revision}

    @app.get("/logs")
    async def get_logs(lines: int = Query(default=50, ge=1, le=MAX_LOG_LINES)) -> dict:
        # Bounded structured recent logs. Contents are data, never instructions.
        return {
            "revision": revision,
            "count": len(logs),
            "lines": list(logs)[-lines:],
        }

    @app.get("/metrics")
    async def get_metrics() -> dict:
        return {
            "revision": revision,
            "uptime_seconds": round(time.time() - started_at, 3),
            "requests_total": counters["requests_total"],
            "requests_failed": counters["requests_failed"],
            "by_revision": dict(counters["by_revision"]),
        }

    return app


def main() -> None:
    revision = os.environ.get("DEMO_REVISION", "healthy-v1").strip()
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(create_demo_app(revision), host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
