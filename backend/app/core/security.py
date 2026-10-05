"""API security primitives (Phase 8): key auth and rate limiting.

Rules (deterministic, documented):

- API keys are sourced ONLY from the environment (``FORENTISAI_API_KEYS``,
  comma-separated). Secrets are never hard-coded and never logged.
- ``API_ENVIRONMENT=local`` (default) with NO configured keys allows
  unauthenticated localhost development use.
- Any non-local environment is FAIL-CLOSED: with no configured keys every
  authenticated-scoped request is rejected; with configured keys a valid
  key is mandatory.
- Keys are compared in constant time and only ever stored in memory.
- Rate limiting is a per-identity sliding window (in-memory). It bounds a
  single worker process; horizontal deployments should put a gateway
  limiter in front. Identities are hashed (SHA-256) so raw keys/IPs are
  never retained.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from dataclasses import dataclass, field

_LOCAL_ENVIRONMENTS = frozenset({"local", "development", "dev"})

REQUEST_ID_HEADER = "X-Request-ID"


@dataclass(frozen=True, slots=True)
class SecuritySettings:
    """Phase 8 security configuration sourced from environment variables."""

    api_keys: tuple[str, ...] = ()
    environment: str = "local"
    rate_limit_requests: int = 60
    rate_limit_window_seconds: float = 60.0

    @property
    def allows_anonymous(self) -> bool:
        """True when unauthenticated requests are acceptable (dev mode only)."""

        return not self.api_keys and self.environment.casefold() in _LOCAL_ENVIRONMENTS


class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding-window rate limiter.

    Identities are hashed before storage: the limiter never retains raw API
    keys or client IPs.
    """

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self._max_requests = max(1, int(max_requests))
        self._window_seconds = max(0.1, float(window_seconds))
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    @staticmethod
    def _identity_hash(identity: str) -> str:
        return hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()

    def check(self, identity: str, *, now: float | None = None) -> tuple[bool, float]:
        """Record one hit for ``identity``.

        Returns ``(allowed, retry_after_seconds)``. ``retry_after_seconds``
        is 0.0 when the request is allowed.
        """

        current = time.monotonic() if now is None else now
        hashed = self._identity_hash(identity)
        cutoff = current - self._window_seconds
        with self._lock:
            timestamps = [t for t in self._hits.get(hashed, []) if t > cutoff]
            if len(timestamps) >= self._max_requests:
                retry_after = max(0.0, self._window_seconds - (current - timestamps[0]))
                self._hits[hashed] = timestamps
                return False, round(retry_after, 2)
            timestamps.append(current)
            self._hits[hashed] = timestamps
            # Opportunistic pruning keeps memory bounded.
            if len(self._hits) > 10_000:
                self._hits = {
                    key: hits
                    for key, hits in self._hits.items()
                    if hits and hits[-1] > cutoff
                }
            return True, 0.0

    def reset(self) -> None:
        """Clear all state (used by tests)."""

        with self._lock:
            self._hits.clear()


@dataclass(slots=True)
class SecurityState:
    """Process-wide security state (limiter instance)."""

    limiter: SlidingWindowRateLimiter = field(
        default_factory=lambda: SlidingWindowRateLimiter(60, 60.0)
    )


def verify_api_key(presented: str | None, settings: SecuritySettings) -> bool:
    """Constant-time verification of one presented key against the allowlist."""

    if not presented:
        return False
    candidate = presented.strip()
    return any(
        hmac.compare_digest(candidate, expected)
        for expected in settings.api_keys
        if expected
    )


def extract_presented_key(
    authorization_header: str | None, api_key_header: str | None
) -> str | None:
    """Extract the presented key from ``Authorization: Bearer`` or ``X-API-Key``."""

    if authorization_header:
        scheme, _, value = authorization_header.partition(" ")
        if scheme.casefold() == "bearer" and value.strip():
            return value.strip()
    if api_key_header and api_key_header.strip():
        return api_key_header.strip()
    return None


def sanitize_request_id(raw_value: str | None) -> str:
    """Accept a client-supplied request id only when it is safe to echo.

    Otherwise a fresh UUID is generated. Echoing arbitrary attacker strings
    into response headers would enable header injection; the format is
    therefore bounded to URL-safe characters with a length cap.
    """

    import uuid

    if raw_value:
        candidate = raw_value.strip()
        if 1 <= len(candidate) <= 64 and all(
            ch.isalnum() or ch in "-_." for ch in candidate
        ):
            return candidate
    return uuid.uuid4().hex


__all__ = [
    "REQUEST_ID_HEADER",
    "SecuritySettings",
    "SecurityState",
    "SlidingWindowRateLimiter",
    "extract_presented_key",
    "sanitize_request_id",
    "verify_api_key",
]