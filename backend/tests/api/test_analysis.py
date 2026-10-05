"""End-to-end API tests for POST /analyze-email (Rspamd fully mocked)."""

from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient

from app.api import dependencies
from app.authentication.rspamd_client import (
    RspamdConnectionError,
    RspamdInvalidResponseError,
    RspamdTimeoutError,
)
from app.main import app as fastapi_app

from helpers import SAMPLE_EML


def post_email(
    client: TestClient,
    content: bytes,
    filename: str = "upload.eml",
) -> TestClient.__class__:
    return client.post(
        "/analyze-email",
        files={"upload": (filename, io.BytesIO(content), "message/rfc822")},
    )


def test_valid_eml_returns_combined_evidence(client: TestClient, fake_rspamd) -> None:
    response = post_email(client, SAMPLE_EML)

    assert response.status_code == 200
    payload = response.json()
    # Step 5 adds ``ai`` (model evidence); Phases 3/5/5A add ``analysis_id``,
    # ``risk`` (risk engine), ``forensics`` (transport path), ``metadata``.
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

    email = payload["email"]
    assert email["file"]["filename"] == "upload.eml"
    assert email["message"]["subject"] == "API fixture"
    assert email["sender"]["address"] == "alice@example.test"
    assert email["recipients"]["to"][0]["address"] == "bob@example.test"
    assert "https://example.test/api-path" in [u["url"] for u in email["urls"]]
    assert email["headers"]["raw"]["From"] == ["Alice Sender <alice@example.test>"]

    auth = payload["authentication"]
    assert auth["spf"]["result"] == "none"
    assert auth["dkim"]["result"] == "none"
    assert auth["dmarc"]["result"] == "none"
    assert auth["rspamd"]["action"] == "no action"
    assert auth["rspamd"]["scanned"] is True

    intelligence = payload["intelligence"]
    assert intelligence["schema_version"] == "1.0"
    assert intelligence["counts"]["urls"] == 1
    assert intelligence["counts"]["domains"] == 1


def test_rspamd_receives_original_bytes_unchanged(
    client: TestClient, fake_rspamd
) -> None:
    original = bytes(SAMPLE_EML)
    response = post_email(client, original)

    assert response.status_code == 200
    assert fake_rspamd.received == [original]
    assert fake_rspamd.received[0] == SAMPLE_EML


def test_upload_filename_becomes_display_metadata_only(
    client: TestClient, fake_rspamd
) -> None:
    response = post_email(client, SAMPLE_EML, filename="..\r\n..\\weird name.eml")

    assert response.status_code == 200
    email = response.json()["email"]
    assert "/" not in email["file"]["filename"]
    assert "\\" not in email["file"]["filename"]
    assert email["file"]["filename"].endswith(".eml")


def test_unsupported_extension_rejected(client: TestClient) -> None:
    response = post_email(client, b"not an email", filename="notes.txt")

    assert response.status_code == 415
    error = response.json()["error"]
    assert error["code"] == "unsupported_format"
    assert "authentication" not in response.json()


def test_empty_file_rejected(client: TestClient, fake_rspamd) -> None:
    response = post_email(client, b"", filename="empty.eml")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "empty_file"
    # Nothing was sent to Rspamd for an empty upload.
    assert fake_rspamd.received == []


def test_oversized_file_rejected_before_extraction(
    client: TestClient, fake_rspamd, small_upload_limit
) -> None:
    big_email = b"Subject: big\r\n\r\n" + b"x" * 2048
    response = post_email(client, big_email, filename="big.eml")

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "file_too_large"
    assert fake_rspamd.received == []


def test_malformed_email_returns_controlled_error(client: TestClient, fake_rspamd) -> None:
    malformed = (
        b"From: a@example.test\r\n"
        b"Content-Type: multipart/mixed\r\n"
        b"\r\n"
        b"Missing MIME boundary"
    )
    response = post_email(client, malformed)

    assert response.status_code == 200
    payload = response.json()
    # Step 1 records the defect instead of failing the request.
    assert any(
        defect["source"] == "python-email" for defect in payload["email"]["parser_defects"]
    )


def test_rspamd_unavailable_returns_503(
    client: TestClient, failing_rspamd
) -> None:
    failing_rspamd(RspamdConnectionError("connection refused"))
    response = post_email(client, SAMPLE_EML)

    assert response.status_code == 503
    error = response.json()["error"]
    assert error["code"] == "rspamd_unavailable"
    # The failure is never converted into an authentication result.
    assert "authentication" not in response.json()
    assert "email" not in response.json()


def test_rspamd_timeout_returns_504(client: TestClient, failing_rspamd) -> None:
    failing_rspamd(RspamdTimeoutError("timed out"))
    response = post_email(client, SAMPLE_EML)

    assert response.status_code == 504
    assert response.json()["error"]["code"] == "rspamd_timeout"


def test_invalid_rspamd_response_returns_502(
    client: TestClient, failing_rspamd
) -> None:
    failing_rspamd(RspamdInvalidResponseError("bad JSON shape"))
    response = post_email(client, SAMPLE_EML)

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "rspamd_invalid_response"


def test_unexpected_internal_error_is_controlled(
    failing_rspamd,
) -> None:
    failing_rspamd(RuntimeError("boom"))
    # Starlette re-raises unhandled exceptions in tests by default; disable
    # that so the production exception-handler path is exercised instead.
    with TestClient(fastapi_app, raise_server_exceptions=False) as client:
        response = post_email(client, SAMPLE_EML)

    assert response.status_code == 500
    error = response.json()["error"]
    assert error["code"] == "internal_error"
    # No stack traces or internals in the response.
    assert "boom" not in response.text
    assert "Traceback" not in response.text


def test_error_responses_never_contain_email_content(
    client: TestClient, failing_rspamd
) -> None:
    failing_rspamd(RspamdConnectionError("connection refused"))
    response = post_email(client, SAMPLE_EML)

    text = response.text.casefold()
    assert "alice@example.test" not in text
    assert "api fixture" not in text
    assert "example.test/api-path" not in text


def test_no_risk_score_or_verdict_fields_in_success_response(
    client: TestClient, fake_rspamd
) -> None:
    response = post_email(client, SAMPLE_EML)

    assert response.status_code == 200
    payload = response.json()
    # Step 5 note: model ``confidence`` values inside the ``ai`` section are
    # legitimate model evidence (Phase B contract). A FINAL project risk
    # score, threat verdict, or AI-prediction verdict field must not exist
    # inside the EVIDENCE sections. The Phase 3 risk engine legitimately
    # owns ``risk`` (its own top-level section), and Phase 5A owns
    # ``forensics``; those are checked in test_product_response.py.
    evidence_sections = ("email", "authentication", "intelligence")
    for section_name in evidence_sections:
        section = payload[section_name]
        for forbidden_key in (
            "risk_score",
            "riskscore",
            "threat_type",
            "final_verdict",
            "ai_prediction",
            "is_safe",
            "verdict",
            "severity",
        ):
            assert forbidden_key not in section, (section_name, forbidden_key)

    ai = payload["ai"]
    for forbidden_key in (
        "risk_score",
        "riskscore",
        "threat_type",
        "final_verdict",
        "ai_prediction",
        "is_safe",
        "verdict",
        "severity",
        "forensic_report",
    ):
        assert forbidden_key not in ai


def test_cors_allows_configured_origin(client: TestClient) -> None:
    response = client.options(
        "/analyze-email",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert response.headers.get("access-control-allow-credentials") is None


def test_cors_rejects_unconfigured_origin(client: TestClient) -> None:
    response = client.options(
        "/analyze-email",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert "access-control-allow-origin" not in response.headers
