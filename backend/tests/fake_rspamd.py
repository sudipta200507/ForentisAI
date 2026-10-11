"""Shared deterministic Rspamd fake for the unit-test suite.

The suite's documented contract is that unit tests never require Docker:
Rspamd is always faked via a FastAPI dependency override, and only the
opt-in live integration files touch the real container. This module is the
single source of truth for that fake; ``tests/api/helpers.py`` re-exports it
for the Step 3 tests and ``tests/conftest.py`` installs it automatically.

The module lives directly under ``tests/`` because pytest's ``pythonpath``
setting (backend/pyproject.toml) puts that directory on ``sys.path`` for
every test run, making it importable from any test package.
"""

from __future__ import annotations

from app.authentication.rspamd_client import (
    RspamdConnectionError,
    RspamdTimeoutError,
)
from app.schemas.authentication import RspamdAnalysis, RspamdSymbol


SAMPLE_EML = (
    b"From: Alice Sender <alice@example.test>\r\n"
    b"To: Bob Recipient <bob@example.test>\r\n"
    b"Subject: API fixture\r\n"
    b"Date: Tue, 01 Apr 2025 10:30:00 +0000\r\n"
    b"Message-ID: <api-fixture@example.test>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Visit https://example.test/api-path for details.\r\n"
)


class FakeRspamdClient:
    """Deterministic stand-in for RspamdClient.scan_bytes."""

    def __init__(
        self,
        analysis: RspamdAnalysis | None = None,
        error: Exception | None = None,
        unexpected_error: Exception | None = None,
    ) -> None:
        self.analysis = analysis
        self.error = error
        self.unexpected_error = unexpected_error
        self.received: list[bytes] = []

    def scan_bytes(self, raw_email: bytes) -> RspamdAnalysis:
        self.received.append(bytes(raw_email))
        if self.unexpected_error is not None:
            raise self.unexpected_error
        if self.error is not None:
            raise self.error
        assert self.analysis is not None
        return self.analysis


def valid_analysis() -> RspamdAnalysis:
    """A benign, fully-scanned Rspamd reply with no authentication results."""

    return RspamdAnalysis(
        action="no action",
        score=0.1,
        required_score=15.0,
        symbols={
            "R_SPF_NA": RspamdSymbol(score=0.0, options=["no SPF record"]),
            "R_DKIM_NA": RspamdSymbol(score=0.0),
            "DMARC_NA": RspamdSymbol(score=0.0, options=["example.test"]),
        },
        message_id="<api-fixture@example.test>",
        scanned=True,
    )


def install_fake_rspamd(app) -> FakeRspamdClient:
    """Install the deterministic fake on one FastAPI app instance.

    A dependency override applies only to the app instance it is set on
    (and only to routers included by that instance), so tests that build a
    fresh app with ``create_app()`` must call this on the fresh instance —
    an override installed on the module-level ``app.main.app`` does not
    carry over. Returns the fake client so tests can assert on what it
    received.
    """

    from app.api import dependencies

    fake = FakeRspamdClient(analysis=valid_analysis())
    app.dependency_overrides.setdefault(dependencies.get_rspamd_client, lambda: fake)
    return fake


# Re-exported so tests can construct failures without importing internals.
connection_error = RspamdConnectionError
timeout_error = RspamdTimeoutError
