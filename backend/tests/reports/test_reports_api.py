"""Phase 7 tests: report API endpoints.

- POST /reports/generate derives a full report from a real analysis response.
- GET /reports/{analysis_id} reconstructs a partial report from the
  privacy-first persisted record and states what was not retained.
"""

from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient

from app.api import dependencies
from app.api.schemas import AnalysisResponse
from app.core.config import AISettings
from app.database.session import create_all, reset_engine_cache
from app.main import app as fastapi_app

SAMPLE_EML = (
    b"From: Alice Sender <alice@example.test>\r\n"
    b"To: Bob Recipient <bob@example.test>\r\n"
    b"Reply-To: helper@other-domain.test\r\n"
    b"Subject: Report fixture\r\n"
    b"Date: Tue, 01 Apr 2025 10:30:00 +0000\r\n"
    b"Message-ID: <report-fixture@example.test>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"BODY-MARKER-REPORT Visit https://example.test/path for details.\r\n"
)


@pytest.fixture()
def client() -> TestClient:
    return TestClient(fastapi_app)


@pytest.fixture()
def no_ai(monkeypatch, tmp_path):
    settings = AISettings(
        ai_enabled=False,
        model_dir=tmp_path,
        technical_model_path=tmp_path / "missing.joblib",
        nlp_model_path=None,
    )
    fastapi_app.dependency_overrides[dependencies.get_ai_settings] = lambda: settings
    yield
    fastapi_app.dependency_overrides.pop(dependencies.get_ai_settings, None)


@pytest.fixture()
def db_env(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "FORENTISAI_DATABASE_URL", f"sqlite:///{(tmp_path / 'reports.db').as_posix()}"
    )
    monkeypatch.setenv("FORENTISAI_PERSIST_ENABLED", "true")
    monkeypatch.setenv("FORENTISAI_RETENTION_DAYS", "30")
    reset_engine_cache()
    create_all()
    yield
    reset_engine_cache()


def _analyze(client: TestClient) -> dict:
    response = client.post(
        "/analyze-email",
        files={"upload": ("reports_api.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")},
    )
    assert response.status_code == 200
    return response.json()


def test_generate_json_report_from_analysis_response(client, no_ai):
    analysis = _analyze(client)
    response = client.post("/reports/generate?format=json", json=analysis)
    assert response.status_code == 200
    report = response.json()
    assert report["metadata"]["analysis_id"] == analysis["analysis_id"]
    assert report["executive_summary"]["verdict"] == analysis["risk"]["verdict"]
    assert report["executive_summary"]["risk_score"] == analysis["risk"]["risk_score"]
    assert "BODY-MARKER-REPORT" not in response.text


def test_generate_html_report_from_analysis_response(client, no_ai):
    analysis = _analyze(client)
    response = client.post("/reports/generate?format=html", json=analysis)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.text.startswith("<!DOCTYPE html>")
    assert "Executive Summary" in response.text
    assert "BODY-MARKER-REPORT" not in response.text


def test_generate_report_rejects_unknown_format(client, no_ai):
    analysis = _analyze(client)
    response = client.post("/reports/generate?format=pdf", json=analysis)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "unsupported_report_format"


def test_generate_report_rejects_invalid_payload(client, no_ai):
    response = client.post("/reports/generate?format=json", json={"foo": "bar"})
    assert response.status_code == 400


def test_get_stored_report_after_analysis(client, no_ai, db_env):
    analysis = _analyze(client)
    response = client.get(f"/reports/{analysis['analysis_id']}")
    assert response.status_code == 200
    report = response.json()
    assert report["metadata"]["analysis_id"] == analysis["analysis_id"]
    assert report["executive_summary"]["verdict"] == analysis["risk"]["verdict"]
    # Privacy-first storage: body text was never persisted.
    assert "BODY-MARKER-REPORT" not in response.text
    # The reconstruction must state its limits honestly.
    assert any("reconstructed" in item for item in report["limitations"])
    assert report["intelligence"]["indicators"], "indicators must be persisted"


def test_get_stored_report_html(client, no_ai, db_env):
    analysis = _analyze(client)
    response = client.get(f"/reports/{analysis['analysis_id']}?format=html")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "ForentisAI" in response.text


def test_get_unknown_analysis_report_returns_404(client, no_ai, db_env):
    response = client.get("/reports/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_stored_report_roundtrip_matches_analysis_response(client, no_ai, db_env):
    """The stored report must carry the same top-line risk numbers."""

    analysis = _analyze(client)
    report = client.get(f"/reports/{analysis['analysis_id']}").json()
    risk = analysis["risk"]
    threat = report["threat"]
    assert threat["risk_score"] == risk["risk_score"]
    assert threat["verdict"] == risk["verdict"]
    assert threat["severity"] == risk["severity"]
    assert threat["confidence"] == risk["confidence"]
    assert threat["primary_threat_type"] == risk["primary_threat_type"]
    # The persisted model_status map must round-trip.
    stored_status = report["ai"]["model_status"]
    live_status = analysis["ai"]["fusion"]["model_status"]
    for name, status in live_status.items():
        if name in stored_status and status == "available":
            assert stored_status[name] == "available"