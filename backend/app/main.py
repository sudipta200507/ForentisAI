"""ForentisAI FastAPI application (Steps 3-5).

The API composes the existing Step 1 extractor, Step 2 authentication,
Step 4 intelligence, and Step 5 AI model-evidence pipelines. It never
produces a final risk score, threat verdict, forensic report, or any
persistence; those belong to later project phases.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import errors
from app.api.json_response import SanitizingJSONResponse
from app.api.dependencies import require_api_key
from app.api.routes import analyses, analysis, correlation, health, reports
from app.core.constants import APP_VERSION, MAX_ANALYZE_REQUEST_BYTES
from app.core.security import REQUEST_ID_HEADER, sanitize_request_id

APP_TITLE = "ForentisAI API"
APP_DESCRIPTION = (
    "Email analysis API: upload an original .eml file and receive normalized "
    "email evidence (Step 1), authentication evidence from Rspamd (Step 2), "
    "infrastructure intelligence (Step 4), AI model evidence (Step 5), a "
    "deterministic risk assessment (Phase 3), and forensic transport-path "
    "evidence (Phase 5A). Model outputs and the risk assessment are evidence "
    "and policy thresholds only - never a legal or final security "
    "determination."
)





def create_app() -> FastAPI:
    """Build the configured FastAPI application."""

    from app.api.dependencies import get_api_settings

    app = FastAPI(
        title=APP_TITLE,
        description=APP_DESCRIPTION,
        version=APP_VERSION,
        # Serialization safety net: malformed Unicode from emails must never
        # turn a finished analysis into an HTTP 500 (unpaired surrogates in
        # extracted strings are replaced with U+FFFD at render time).
        default_response_class=SanitizingJSONResponse,
    )

    # CORS for local development. Origins come from the environment and the
    # list is never unrestricted; credentials are deliberately not enabled so
    # a wildcard misconfiguration cannot silently become dangerous.
    api_settings = get_api_settings()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(api_settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Routers. Analysis and reports are security-scoped (Phase 8): an API
    # key is required whenever keys are configured or the environment is
    # non-local. Health endpoints stay unauthenticated for liveness probes.
    app.include_router(health.router)
    app.include_router(analysis.router, dependencies=[Depends(require_api_key)])
    app.include_router(reports.router, dependencies=[Depends(require_api_key)])
    app.include_router(analyses.router, dependencies=[Depends(require_api_key)])
    app.include_router(correlation.router, dependencies=[Depends(require_api_key)])

    # Phase 8: every response carries a bounded request id (client-supplied
    # ids are sanitized to URL-safe characters or replaced by a UUID).
    @app.middleware("http")
    async def attach_request_id(request: Request, call_next):
        request_id = sanitize_request_id(request.headers.get(REQUEST_ID_HEADER))
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = request_id
        return response

    # Phase 6: create persistence tables at startup when persistence is
    # enabled (idempotent). A database outage must never block analysis
    # delivery, so failures here are contained.
    try:
        from app.core.config import load_database_settings
        from app.database.session import create_all as create_tables

        if load_database_settings().persist_enabled:
            create_tables()
    except Exception:  # noqa: BLE001 - startup persistence setup is best-effort
        pass

    # Transport-level guard against oversized multipart requests. The exact
    # Step 1 file limit is enforced in the route while reading the upload
    # part; this guard only bounds the total request size with a small
    # margin for multipart overhead. No second conflicting file limit exists.
    @app.middleware("http")
    async def limit_request_body(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if request.method == "POST" and content_length and content_length.isdigit():
            if int(content_length) > MAX_ANALYZE_REQUEST_BYTES:
                return errors.error_response("file_too_large")
        return await call_next(request)

    # Controlled error responses for domain and unexpected failures. Handlers
    # never leak stack traces, email content, or environment details.
    @app.exception_handler(errors.ApiError)
    async def handle_api_error(request: Request, exc: errors.ApiError) -> JSONResponse:
        return exc.to_response()

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        return errors.error_response("internal_error")

    return app


app = create_app()
