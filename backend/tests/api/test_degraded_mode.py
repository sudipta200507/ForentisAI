"""Phase 4 tests: Rspamd degraded mode (FORENTISAI_AUTH_STRICT=false).

Strict mode stays the default and keeps the controlled 503/504/502 behavior
(exercised in test_analysis.py). These tests prove that in DEGRADED mode a
Rspamd INFRASTRUCTURE failure becomes an explicit unavailable authentication
status, the analysis continues, and the failure is never converted into a
passing result.
"""

from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient

from app.api import dependencies
from app.authentication.rspamd_client import (
    RspamdConnectionError,
    RspamdInvalidEmailError,
    RspamdInvalidResponseError,
    RspamdTimeoutError,
)
from app.main import app as fastapi_app

from helpers import SAMPLE_EML


@pytest.fixture()
def degraded_mode():
    """Enable degraded mode for the duration of one test."""

    from app.core.config import AuthSettings

    fastapi_app.dependency_overrides[dependencies.get_auth_settings] = lambda: (
        AuthSettings(strict_mode=False)
    )
    yield
    fastapi_app.dependency_overrides.pop(dependencies.get_auth_settings, None)


@pytest.fixture()
def ai_disabled(tmp_path):
    """Point the AI pipeline at an empty model dir for fast, isolated runs."""

    from app.core.config import AISettings

    settings = AISettings(
        ai_enabled=True,
        model_dir=tmp_path / "models",
        technical_model_path=tmp_path / "models" / "technical_model.joblib",
        nlp_model_path=None,
    )
    fastapi_app.dependency_overrides[dependencies.get_ai_settings] = lambda: settings
    yield
    fastapi_app.dependency_overrides.pop(dependencies.get_ai_settings, None)


def _post_email(client: TestClient):
    return client.post(
        "/analyze-email",
        files={"upload": ("upload.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")},
    )


@pytest.mark.parametrize(
    "rspamd_error",
    [
        RspamdConnectionError("connection refused"),
        RspamdTimeoutError("timed out"),
        RspamdInvalidResponseError("bad JSON shape"),
    ],
    ids=["connection", "timeout", "invalid_response"],
)
def test_degraded_mode_continues_after_rspamd_infrastructure_failure(
    degraded_mode, ai_disabled, failing_rspamd, rspamd_error
) -> None:
    failing_rspamd(rspamd_error)
    with TestClient(fastapi_app) as client:
        response = _post_email(client)

    assert response.status_code == 200
    payload = response.json()

    # All evidence sections remain present (including Phases 3/5/5A output).
    assert set(payload) == {
        "schema_version",
        "analysis_id",
        "email",
        "authentication",
        "intelligence",
        "ai",
        "risk",
        "forensics",
        "metadata",
    }

    auth = payload["authentication"]
    # Explicit 'could not scan' status — NEVER a fabricated pass.
    assert auth["spf"]["result"] == "unknown"
    assert auth["spf"]["available"] == "unavailable"
    assert auth["dkim"]["result"] == "unknown"
    assert auth["dkim"]["available"] == "unavailable"
    assert auth["dmarc"]["result"] == "unknown"
    assert auth["dmarc"]["available"] == "unavailable"
    assert auth["rspamd"]["scanned"] is False
    assert auth["rspamd"]["error"].startswith("rspamd_scan_skipped:")

    # The rest of the pipeline still ran.
    assert payload["email"]["file"]["filename"] == "upload.eml"
    assert payload["ai"]["schema_version"] == "1.0"


def test_degraded_mode_still_rejects_invalid_email(
    degraded_mode, ai_disabled, failing_rspamd
) -> None:
    """An email-content failure is NOT an infrastructure failure."""

    failing_rspamd(RspamdInvalidEmailError("no content"))
    with TestClient(fastapi_app) as client:
        response = _post_email(client)

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_email"


def test_strict_mode_remains_the_default(failing_rspamd) -> None:
    """No override installed: default settings are strict → 503 stays."""

    failing_rspamd(RspamdConnectionError("connection refused"))
    with TestClient(fastapi_app) as client:
        response = _post_email(client)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "rspamd_unavailable"


def test_strict_mode_explicit_true_returns_503(failing_rspamd) -> None:
    from app.core.config import AuthSettings

    fastapi_app.dependency_overrides[dependencies.get_auth_settings] = lambda: (
        AuthSettings(strict_mode=True)
    )
    try:
        failing_rspamd(RspamdConnectionError("connection refused"))
        with TestClient(fastapi_app) as client:
            response = _post_email(client)
    finally:
        fastapi_app.dependency_overrides.pop(dependencies.get_auth_settings, None)

    assert response.status_code == 503


def test_degraded_mode_auth_unavailable_yields_no_authentication_points(
    degraded_mode, ai_disabled, failing_rspamd
) -> None:
    """Degraded auth must look identical to missing auth downstream."""

    failing_rspamd(RspamdConnectionError("connection refused"))
    with TestClient(fastapi_app) as client:
        response = _post_email(client)

    auth = response.json()["authentication"]
    for protocol in ("spf", "dkim", "dmarc"):
        assert auth[protocol]["available"] == "unavailable"
        assert auth[protocol]["result"] == "unknown"
