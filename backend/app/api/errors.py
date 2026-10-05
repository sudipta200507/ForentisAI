"""Controlled, machine-readable API errors for Step 3.

Error responses never include stack traces, raw email content, email bodies,
credentials, internal paths, or environment variables. The ``code`` values are
stable, documented identifiers intended for client-side handling.
"""

from __future__ import annotations

from fastapi.responses import JSONResponse

from app.authentication.rspamd_client import (
    RspamdConnectionError,
    RspamdError,
    RspamdInvalidEmailError,
    RspamdInvalidResponseError,
    RspamdTimeoutError,
)
from app.extractor.email_parser import (
    EmailExtractionError,
    EmailParsingError,
    FileValidationError,
    UnsupportedEmailFormatError,
)


class ApiError(Exception):
    """An API-layer error with a stable ``code``, HTTP status, and headers."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = headers or {}

    def to_response(self) -> JSONResponse:
        return JSONResponse(
            status_code=self.status_code,
            content={"error": {"code": self.code, "message": self.message}},
            headers=self.headers or None,
        )


# Stable machine-readable codes mapped to (HTTP status, default message).
ERROR_DEFINITIONS: dict[str, tuple[int, str]] = {
    "invalid_file": (400, "The uploaded email could not be processed."),
    "unsupported_format": (415, "Only .eml files are supported."),
    "file_too_large": (413, "The uploaded email exceeds the size limit."),
    "empty_file": (400, "The uploaded email file is empty."),
    "malformed_email": (422, "The uploaded data is not a parseable email message."),
    "invalid_email": (400, "The email content is empty or invalid."),
    "rspamd_unavailable": (503, "The authentication service is currently unavailable."),
    "rspamd_timeout": (504, "The authentication service did not respond in time."),
    "rspamd_invalid_response": (
        502,
        "The authentication service returned an invalid response.",
    ),
    "not_found": (404, "The requested resource was not found."),
    "invalid_indicator_type": (
        400,
        "indicator_type must be one of: domain, hostname, ipv4, ipv6, url.",
    ),
    "unsupported_report_format": (
        400,
        "Only 'json' and 'html' report formats are supported.",
    ),
    "unauthorized": (
        401,
        "A valid API key is required (Authorization: Bearer <key> or X-API-Key).",
    ),
    "rate_limit_exceeded": (429, "Too many requests; retry later."),
    "internal_error": (500, "An unexpected internal error occurred."),
}


def error_response(code: str, *, detail: str | None = None) -> JSONResponse:
    """Build a controlled JSON error response for a stable error code."""

    status_code, default_message = ERROR_DEFINITIONS[code]
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": detail or default_message}},
    )


def api_error(code: str, *, detail: str | None = None) -> ApiError:
    """Build an :class:`ApiError` from a stable code."""

    status_code, default_message = ERROR_DEFINITIONS[code]
    return ApiError(status_code, code, detail or default_message)


def map_exception_to_api_error(exc: Exception) -> ApiError:
    """Map domain exceptions to controlled API errors (no content leakage)."""

    if isinstance(exc, RspamdInvalidEmailError):
        return api_error("invalid_email")
    if isinstance(exc, RspamdTimeoutError):
        return api_error("rspamd_timeout")
    if isinstance(exc, RspamdConnectionError):
        return api_error("rspamd_unavailable")
    if isinstance(exc, RspamdInvalidResponseError):
        return api_error("rspamd_invalid_response")
    if isinstance(exc, RspamdError):
        return api_error("internal_error")
    if isinstance(exc, EmailExtractionError):
        if isinstance(exc, UnsupportedEmailFormatError):
            return api_error("unsupported_format")
        if isinstance(exc, EmailParsingError):
            return api_error("malformed_email")
        if isinstance(exc, FileValidationError):
            message = exc.message.casefold()
            if "empty" in message:
                return api_error("empty_file")
            if "exceeds" in message:
                return api_error("file_too_large")
            return api_error("invalid_file")
    return api_error("internal_error")
