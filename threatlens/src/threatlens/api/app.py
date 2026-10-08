"""FastAPI application factory."""

from __future__ import annotations

import re
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from redis.asyncio import Redis

from threatlens import __version__
from threatlens.db import make_engine, ping
from threatlens.health import Check, run_checks
from threatlens.logs import configure_logging, get_logger
from threatlens.settings import Environment, Settings, get_settings

log = get_logger("threatlens.api")

# A caller-supplied request ID is echoed only if it is short and boring;
# otherwise it could inject content into logs or response headers.
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}
# Swagger UI needs scripts and styles from its CDN; relax CSP only on /docs.
_DOCS_CSP = (
    "default-src 'none'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "connect-src 'self'; frame-ancestors 'none'"
)


def create_app(settings: Settings | None = None, checks: dict[str, Check] | None = None) -> FastAPI:
    """Build the app. ``checks`` overrides the readiness probes (tests)."""
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_json)
    dev = settings.env != Environment.PROD

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if checks is not None:
            app.state.checks = checks
            yield
            return
        engine = make_engine(settings.database_url.get_secret_value())
        redis: Redis = Redis.from_url(settings.redis_url.get_secret_value())

        async def redis_ping() -> None:
            await redis.ping()

        app.state.checks = {"postgres": lambda: ping(engine), "redis": redis_ping}
        log.info("api.startup", version=__version__, env=settings.env.value)
        try:
            yield
        finally:
            await redis.aclose()
            await engine.dispose()
            log.info("api.shutdown")

    app = FastAPI(
        title="ThreatLens",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if dev else None,
        redoc_url=None,
        openapi_url="/openapi.json" if dev else None,
    )

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        rid = request.headers.get("x-request-id", "")
        if not _SAFE_REQUEST_ID.match(rid):
            rid = uuid.uuid4().hex
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=rid)
        start = time.perf_counter()
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.path == "/docs":
            response.headers["Content-Security-Policy"] = _DOCS_CSP
        log.info(
            "http.request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=round((time.perf_counter() - start) * 1000, 1),
        )
        return response

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", tags=["ops"])
    async def readyz(request: Request) -> JSONResponse:
        results = await run_checks(request.app.state.checks, settings.readiness_timeout_s)
        ready = all(r.ok for r in results)
        body = {
            "status": "ready" if ready else "not_ready",
            "checks": {
                r.name: {"ok": r.ok, "latency_ms": r.latency_ms, **({"error": r.error} if r.error else {})}
                for r in results
            },
        }
        return JSONResponse(body, status_code=200 if ready else 503)

    return app
