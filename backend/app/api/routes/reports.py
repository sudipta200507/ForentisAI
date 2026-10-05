"""Phase 7 report endpoints.

Two report paths, both privacy-first:

- ``POST /reports/generate``: generate a FULL report from an analysis
  response the caller already holds (the analysis runs once; reports are
  derived documents over its output).
- ``GET /reports/{analysis_id}``: reconstruct a PARTIAL report from the
  persisted derived record. The database never stores raw email content,
  so this report explicitly lists what was not retained.
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import HTMLResponse

from app.api import errors
from app.api.schemas import AnalysisResponse
from app.database.repositories import get_analysis_by_id
from app.database.session import create_all
from app.reports.report_generator import (
    build_report_payload,
    build_stored_report_payload,
    render_html_report,
)

router = APIRouter(prefix="/reports", tags=["reports"])

_FORMAT_VALUES = {"json", "html"}


def _require_format(format: str) -> str:
    value = (format or "").strip().casefold()
    if value not in _FORMAT_VALUES:
        raise errors.api_error("unsupported_report_format")
    return value


@router.post(
    "/generate",
    name="generate_report",
    summary="Generate a forensic report from an analysis response.",
)
async def generate_report(
    request: Request,
    format: str = Query("json", description="Report format: 'json' or 'html'."),
):

    requested = _require_format(format)
    try:
        analysis_response = AnalysisResponse.model_validate(await request.json())
    except Exception as error:
        raise errors.api_error(
            "invalid_file", detail="The analysis payload is not a valid analysis response."
        ) from error

    payload = build_report_payload(analysis_response)
    if requested == "html":
        return HTMLResponse(
            content=render_html_report(payload),
            media_type="text/html; charset=utf-8",
        )
    return Response(
        content=payload.model_dump_json(indent=2, by_alias=True),
        media_type="application/json",
    )


@router.get(
    "/{analysis_id}",
    name="get_report",
    summary="Reconstruct a report from the persisted analysis record.",
)
async def get_report(
    analysis_id: str,
    format: str = Query("json", description="Report format: 'json' or 'html'."),
):

    requested = _require_format(format)
    create_all()  # idempotent; keeps first-run behavior working
    analysis = get_analysis_by_id(analysis_id)
    if analysis is None:
        raise errors.api_error("not_found", detail="No stored analysis with that id.")

    payload = build_stored_report_payload(analysis)
    if requested == "html":
        return HTMLResponse(
            content=render_html_report(payload),
            media_type="text/html; charset=utf-8",
        )
    return Response(
        content=payload.model_dump_json(indent=2, by_alias=True),
        media_type="application/json",
    )


__all__ = ["router"]