"""SignalForge HTTP API.

A thin layer over :mod:`signalforge`: ingestion, search, the detection
registry, incident case management, response approval and the supply-chain
views.  Everything is tenant-scoped from the caller's token.
"""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from signalforge.auth import AuthError
from signalforge.config import get_settings
from signalforge.incidents import IncidentError, IncidentPermissionError, TeamError
from signalforge.logging_setup import configure_logging
from signalforge.response import ResponseError
from signalforge.sbom import SbomParseError
from signalforge.sigma.errors import SigmaError
from signalforge.telemetry import API_LATENCY, CONTENT_TYPE_LATEST, render_metrics, setup_tracing

from .routers import (
    alerts,
    auth,
    detections,
    events,
    health,
    incidents,
    intel,
    lab,
    response,
    routing,
    sbom,
    stats,
    teams,
)
from .state import build_state

log = logging.getLogger("signalforge.api")

API_PREFIX = "/api/v1"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level, service="api")
    setup_tracing("signalforge-api", settings)
    app.state.sf = build_state(settings)
    try:
        yield
    finally:
        await app.state.sf.bus.stop()
        app.state.sf.event_store.close()


def create_app() -> FastAPI:
    app = FastAPI(
        title="SignalForge API",
        version="0.1.0",
        description=(
            "Detection & response platform: OCSF normalization, Sigma detections, "
            "behavioural correlation, incident case management and approval-gated "
            "response playbooks."
        ),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next: Any) -> Any:
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            API_LATENCY.labels(method=request.method, route=request.url.path, status="500").observe(
                time.perf_counter() - started
            )
            raise
        elapsed = time.perf_counter() - started
        route = request.scope.get("route")
        API_LATENCY.labels(
            method=request.method,
            route=getattr(route, "path", request.url.path),
            status=str(response.status_code),
        ).observe(elapsed)
        response.headers["x-request-id"] = request_id
        response.headers["x-response-time-ms"] = "%.2f" % (elapsed * 1000)
        return response

    # -- error handling ---------------------------------------------------
    @app.exception_handler(AuthError)
    async def _auth_error(request: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": str(exc)},
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(IncidentError)
    async def _incident_error(request: Request, exc: IncidentError) -> JSONResponse:
        message = str(exc)
        code = (
            status.HTTP_404_NOT_FOUND if message.startswith("unknown") else status.HTTP_409_CONFLICT
        )
        return JSONResponse(status_code=code, content={"detail": message})

    # Registered after the base class so the more specific handler wins: being
    # refused a transition is a 403, not a 409.
    @app.exception_handler(IncidentPermissionError)
    async def _incident_permission_error(
        request: Request, exc: IncidentPermissionError
    ) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": str(exc)})

    @app.exception_handler(TeamError)
    async def _team_error(request: Request, exc: TeamError) -> JSONResponse:
        message = str(exc)
        code = (
            status.HTTP_404_NOT_FOUND if message.startswith("no such") else status.HTTP_409_CONFLICT
        )
        return JSONResponse(status_code=code, content={"detail": message})

    @app.exception_handler(ResponseError)
    async def _response_error(request: Request, exc: ResponseError) -> JSONResponse:
        message = str(exc)
        code = (
            status.HTTP_404_NOT_FOUND if message.startswith("unknown") else status.HTTP_409_CONFLICT
        )
        return JSONResponse(status_code=code, content={"detail": message})

    @app.exception_handler(SbomParseError)
    async def _sbom_error(request: Request, exc: SbomParseError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": str(exc)}
        )

    @app.exception_handler(SigmaError)
    async def _sigma_error(request: Request, exc: SigmaError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": "invalid request", "errors": exc.errors()},
        )

    # -- metrics ----------------------------------------------------------
    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> PlainTextResponse:
        return PlainTextResponse(render_metrics().decode("utf-8"), media_type=CONTENT_TYPE_LATEST)

    @app.get("/", include_in_schema=False)
    async def root() -> Dict[str, Any]:
        return {
            "name": "SignalForge",
            "version": app.version,
            "docs": "/docs",
            "api": API_PREFIX,
        }

    # -- routers ----------------------------------------------------------
    app.include_router(health.router, prefix=API_PREFIX)
    app.include_router(auth.router, prefix=API_PREFIX)
    app.include_router(events.router, prefix=API_PREFIX)
    app.include_router(alerts.router, prefix=API_PREFIX)
    app.include_router(incidents.router, prefix=API_PREFIX)
    app.include_router(detections.router, prefix=API_PREFIX)
    app.include_router(intel.router, prefix=API_PREFIX)
    app.include_router(response.router, prefix=API_PREFIX)
    app.include_router(sbom.router, prefix=API_PREFIX)
    app.include_router(stats.router, prefix=API_PREFIX)
    app.include_router(teams.router, prefix=API_PREFIX)
    app.include_router(routing.router, prefix=API_PREFIX)
    app.include_router(lab.router, prefix=API_PREFIX)
    return app


app = create_app()
