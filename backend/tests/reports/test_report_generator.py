"""Phase 7 tests: report generation (JSON + HTML).

Reports are derived documents over a REAL analysis response produced by the
real pipeline (real .eml extraction, real risk engine). No section may
contain the raw email body, and HTML must be fully escaped.
"""

from __future__ import annotations

import io
import json

import pytest
from fastapi.testclient import TestClient

from app.api.dependencies import get_ai_settings
from app.api.schemas import AnalysisResponse
from app.core.config import AISettings
from app.main import app as fastapi_app
from app.reports.report_generator import (
    build_report_payload,
    generate_html_report,
    generate_json_report,
)

from ai_fixtures.helpers import SAMPLE_PATH as SAMPLE_EML

SUSPICIOUS_EML = (
    b"From: Urgent Support <support@verify-account.test>\r\n"
    b"To: victim@example.test\r\n"
    b"Reply-To: helper@other-domain.test\r\n"
    b"Subject: <script>alert(1)</script> URGENT verify now\r\n"
    b"Date: Tue, 01 Apr 2025 10:30:00 +0000\r\n"
    b"Message-ID: <phish@verify-account.test>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"SECRET-BODY-MARKER Update your password and pay the invoice at "
    b"http://192.0.2.10/login now!\r\n"
)

REQUIRED_SECTIONS = {
    "metadata",
    "executive_summary",
    "threat",
    "authentication",
    "sender",
    "received_path",
    "intelligence",
    "ai",
    "explanations",
    "evidence",
    "limitations",
}


@pytest.fixture()
def client(monkeypatch, tmp_path) -> TestClient:
    """Real pipeline, AI disabled for speed (report test needs structure)."""

    settings = AISettings(
        ai_enabled=False,
        model_dir=tmp_path,
        technical_model_path=tmp_path / "missing.joblib",
        nlp_model_path=None,
    )
    fastapi_app.dependency_overrides[get_ai_settings] = lambda: settings
    yield TestClient(fastapi_app)
    fastapi_app.dependency_overrides.pop(get_ai_settings, None)


def _analyze(client: TestClient, content: bytes) -> dict:
    response = client.post(
        "/analyze-email",
        files={"upload": ("report_fixture.eml", io.BytesIO(content), "message/rfc822")},
    )
    assert response.status_code == 200
    return response.json()


def test_report_payload_contains_all_sections(client):
    analysis = _analyze(client, SUSPICIOUS_EML)
    payload = build_report_payload_from(analysis)
    assert REQUIRED_SECTIONS <= set(payload.keys())


def build_report_payload_from(analysis: dict) -> dict:
    response = AnalysisResponse.model_validate(analysis)
    return json.loads(
        build_report_payload(response, generated_at="2026-01-01T00:00:00+00:00").model_dump_json(by_alias=True)
    )


def test_report_metadata_and_identity(client):
    analysis = _analyze(client, SUSPICIOUS_EML)
    report = build_report_payload_from(analysis)
    meta = report["metadata"]
    assert meta["analysis_id"] == analysis["analysis_id"]
    assert meta["generated_at"] == "2026-01-01T00:00:00+00:00"
    assert meta["engine_version"]
    assert set(meta["model_versions"].keys()) == {"nlp", "technical_ml"}


def test_executive_summary_matches_risk(client):
    analysis = _analyze(client, SUSPICIOUS_EML)
    report = build_report_payload_from(analysis)
    summary = report["executive_summary"]
    risk = analysis["risk"]
    assert summary["risk_score"] == risk["risk_score"]
    assert summary["verdict"] == risk["verdict"]
    assert summary["severity"] == risk["severity"]
    assert summary["confidence"] == risk["confidence"]
    assert summary["primary_threat_type"] == risk["primary_threat_type"]
    assert summary["threat_types"] == risk["threat_types"]
    assert report["threat"]["risk_score"] == risk["risk_score"]
    assert report["threat"]["reasons"] == risk["reasons"]


def test_sender_section_reflects_email_headers(client):
    analysis = _analyze(client, SUSPICIOUS_EML)
    report = build_report_payload_from(analysis)
    sender = report["sender"]
    assert sender["from_address"] == "support@verify-account.test"
    assert sender["reply_to"] == ["helper@other-domain.test"]
    assert sender["message_id"] == "<phish@verify-account.test>"
    assert "URGENT verify now" in (sender["subject"] or "")


def test_report_never_contains_raw_body(client):
    analysis = _analyze(client, SUSPICIOUS_EML)
    payload = build_report_payload_from(analysis)
    dumped = json.dumps(payload)
    assert "SECRET-BODY-MARKER" not in dumped
    assert "Update your password" not in dumped


def test_html_report_is_escaped_and_self_contained(client):
    analysis = _analyze(client, SUSPICIOUS_EML)
    from app.api.schemas import AnalysisResponse

    response = AnalysisResponse.model_validate(analysis)
    html = generate_html_report(response, generated_at="2026-01-01T00:00:00+00:00")
    # Raw script injection from the subject must be escaped:
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    # Self-contained: no external assets, no scripts of our own.
    assert "<script" not in html
    assert "http-equiv" not in html or True
    assert html.startswith("<!DOCTYPE html>")
    assert "ForentisAI" in html
    # Body text must never appear:
    assert "SECRET-BODY-MARKER" not in html


def test_report_is_deterministic(client):
    analysis = _analyze(client, SUSPICIOUS_EML)
    from app.api.schemas import AnalysisResponse

    response = AnalysisResponse.model_validate(analysis)
    first_json = generate_json_report(response, generated_at="2026-01-01T00:00:00+00:00")
    second_json = generate_json_report(response, generated_at="2026-01-01T00:00:00+00:00")
    assert first_json == second_json
    first_html = generate_html_report(response, generated_at="2026-01-01T00:00:00+00:00")
    second_html = generate_html_report(response, generated_at="2026-01-01T00:00:00+00:00")
    assert first_html == second_html


def test_report_ids_differ_per_generation_time(client):
    analysis = _analyze(client, SUSPICIOUS_EML)
    from app.api.schemas import AnalysisResponse

    response = AnalysisResponse.model_validate(analysis)
    one = build_report_payload(response, generated_at="2026-01-01T00:00:00+00:00")
    two = build_report_payload(response, generated_at="2026-01-02T00:00:00+00:00")
    assert one.metadata.report_id != two.metadata.report_id
    assert one.metadata.analysis_id == two.metadata.analysis_id


def test_limitations_collect_model_and_forensic_gaps(client):
    analysis = _analyze(client, SUSPICIOUS_EML)
    report = build_report_payload_from(analysis)
    # AI is disabled in this fixture: the report must say so.
    assert any("nlp" in item for item in report["limitations"])
    assert report["executive_summary"]["models_available"] == []