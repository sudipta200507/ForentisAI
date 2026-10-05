"""FastAPI dependency wiring for configuration and the Rspamd client."""

from __future__ import annotations

import hashlib
from functools import lru_cache

from fastapi import Depends, Request

from app.api.errors import ApiError, api_error
from app.authentication.rspamd_client import RspamdClient
from app.core.config import (
    ApiSettings,
    AISettings,
    AuthSettings,
    IntelligenceEnvSettings,
    RspamdSettings,
    load_ai_settings,
    load_api_settings,
    load_auth_settings,
    load_intelligence_env_settings,
    load_rspamd_settings,
    load_security_settings,
)
from app.core.security import (
    SecuritySettings,
    SlidingWindowRateLimiter,
    extract_presented_key,
    verify_api_key,
)


@lru_cache(maxsize=1)
def _cached_api_settings() -> ApiSettings:
    return load_api_settings()


@lru_cache(maxsize=1)
def _cached_rspamd_settings() -> RspamdSettings:
    return load_rspamd_settings()


@lru_cache(maxsize=1)
def _cached_auth_settings() -> AuthSettings:
    return load_auth_settings()


@lru_cache(maxsize=1)
def _cached_intelligence_settings() -> IntelligenceEnvSettings:
    return load_intelligence_env_settings()


@lru_cache(maxsize=1)
def _cached_ai_settings() -> AISettings:
    return load_ai_settings()


@lru_cache(maxsize=1)
def _cached_security_settings() -> SecuritySettings:
    return load_security_settings()


def get_api_settings() -> ApiSettings:
    """Return process-wide API settings (cached; refresh via ``restart``)."""

    return _cached_api_settings()


def get_rspamd_settings() -> RspamdSettings:
    """Return process-wide Rspamd settings (cached)."""

    return _cached_rspamd_settings()


def get_rspamd_client(
    settings: RspamdSettings = Depends(get_rspamd_settings),
) -> RspamdClient:
    """Provide a stateless Rspamd client bound to the configured settings."""

    return RspamdClient(settings)


def get_auth_settings() -> AuthSettings:
    """Return process-wide auth-mode settings (strict vs degraded; cached)."""

    return _cached_auth_settings()


def get_intelligence_settings() -> IntelligenceEnvSettings:
    """Return process-wide intelligence bounds (cached)."""

    return _cached_intelligence_settings()


def get_ai_settings() -> AISettings:
    """Return process-wide AI pipeline settings (cached)."""

    return _cached_ai_settings()


def get_max_upload_bytes() -> int:
    """Expose the single Step 1 upload limit to route handlers."""

    from app.core.constants import DEFAULT_MAX_UPLOAD_SIZE_BYTES

    return DEFAULT_MAX_UPLOAD_SIZE_BYTES


def get_security_settings() -> SecuritySettings:
    """Return process-wide security settings (cached)."""

    return _cached_security_settings()


# Phase 8: one limiter per process, reconfigured from cached settings.
# In-memory by design; a horizontal deployment puts a gateway limiter in
# front (documented in docs/security.md).
_RATE_LIMITER: SlidingWindowRateLimiter | None = None
_RATE_LIMITER_SIGNATURE: tuple[int, float] | None = None


def get_rate_limiter(
    settings: SecuritySettings = Depends(get_security_settings),
) -> SlidingWindowRateLimiter:
    """Return the process-wide rate limiter bound to configured bounds."""

    global _RATE_LIMITER, _RATE_LIMITER_SIGNATURE
    signature = (settings.rate_limit_requests, settings.rate_limit_window_seconds)
    if _RATE_LIMITER is None or _RATE_LIMITER_SIGNATURE != signature:
        _RATE_LIMITER = SlidingWindowRateLimiter(*signature)
        _RATE_LIMITER_SIGNATURE = signature
    return _RATE_LIMITER


def require_api_key(
    request: Request,
    settings: SecuritySettings = Depends(get_security_settings),
    limiter: SlidingWindowRateLimiter = Depends(get_rate_limiter),
) -> str:
    """Authenticate the request and enforce the per-identity rate limit.

    Returns a hashed, non-reversible identity string for rate limiting.
    Dev mode: no configured keys + local environment => anonymous access
    with the client IP as identity. Production: fail closed.
    """

    presented = extract_presented_key(
        request.headers.get("authorization"),
        request.headers.get("x-api-key"),
    )
    if settings.api_keys:
        if not verify_api_key(presented, settings):
            raise api_error("unauthorized")
        assert presented is not None
        identity = f"key:{hashlib.sha256(presented.encode('utf-8', 'replace')).hexdigest()}"
    elif settings.allows_anonymous:
        identity = f"ip:{request.client.host if request.client else 'unknown'}"
    else:
        # Fail closed: production requires configured keys.
        raise api_error(
            "unauthorized",
            detail=(
                "No API keys are configured and the environment is not local; "
                "set FORENTISAI_API_KEYS to enable authenticated access."
            ),
        )

    allowed, retry_after = limiter.check(identity)
    if not allowed:
        raise ApiError(
            429,
            "rate_limit_exceeded",
            "Too many requests; retry later.",
            headers={"Retry-After": str(max(1, int(retry_after + 0.5)))},
        )
    return identity


def reset_security_cache() -> None:
    """Drop cached security settings and limiter state (used by tests)."""

    _cached_security_settings.cache_clear()
    global _RATE_LIMITER, _RATE_LIMITER_SIGNATURE
    _RATE_LIMITER = None
    _RATE_LIMITER_SIGNATURE = None


def raise_api_error(request: Request, code: str) -> None:
    """Raise a controlled :class:`ApiError` (helper for routes)."""

    raise api_error(code)
