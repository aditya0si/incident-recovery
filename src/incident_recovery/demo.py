"""Predefined demo workload deployed as healthy-v1 and broken-v2.

The two demo services use the same image with a different ``DEMO_REVISION``.
``healthy-v1`` produces a correct functional result; ``broken-v2`` contains a
genuine functional regression. Process liveness (``/livez``) stays up on both,
so liveness is never confused with functional health.
"""

from __future__ import annotations

import os

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse


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

    return app


def main() -> None:
    revision = os.environ.get("DEMO_REVISION", "healthy-v1").strip()
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(create_demo_app(revision), host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
