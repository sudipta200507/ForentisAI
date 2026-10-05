"""Tests for the Phase 15 stored-analysis endpoints (GET /analyses)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.database.session import reset_engine_cache

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SAMPLE_PATH = PROJECT_ROOT / "samples" / "safe" / "step1_synthetic.eml"


@pytest.fixture()
def seeded_analysis(monkeypatch, tmp_path):
    """Persist one real analysis through the API, then return its id."""
    monkeypatch.setenv("FORENTISAI_DATABASE_URL", f"sqlite:///{tmp_path / 'analyses.db'}")
    monkeypatch.setenv("FORENTISAI_PERSIST_ENABLED", "true")
    reset_engine_cache()

    from app.main import create_app

    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            "/analyze-email",
            files={
                "upload": (
                    "seed.eml",
                    SAMPLE_PATH.read_bytes(),
                    "message/rfc822",
                )
            },
        )
        assert response.status_code == 200
        yield response.json()


def test_list_analyses_returns_seeded_record(seeded_analysis):
    from app.main import create_app

    with TestClient(create_app()) as client:
        rows = client.get("/analyses").json()
    assert isinstance(rows, list)
    assert len(rows) >= 1
    top = rows[0]
    assert top["analysis_id"] == seeded_analysis["analysis_id"]
    assert top["verdict"] == seeded_analysis["risk"]["verdict"]
    assert abs(top["risk_score"] - seeded_analysis["risk"]["risk_score"]) < 0.01
    for key in ("created_at", "filename", "severity", "confidence", "model_status"):
        assert key in top


def test_list_analyses_respects_limit(seeded_analysis):
    from app.main import create_app

    with TestClient(create_app()) as client:
        rows = client.get("/analyses", params={"limit": 1}).json()
    assert len(rows) <= 1


def test_list_analyses_rejects_bad_limit():
    from app.main import create_app

    with TestClient(create_app()) as client:
        assert client.get("/analyses", params={"limit": 0}).status_code == 422
        assert client.get("/analyses", params={"limit": 500}).status_code == 422


def test_get_analysis_detail(seeded_analysis):
    from app.main import create_app

    with TestClient(create_app()) as client:
        detail = client.get(f"/analyses/{seeded_analysis['analysis_id']}").json()

    assert detail["analysis_id"] == seeded_analysis["analysis_id"]
    assert detail["email_sha256"] == seeded_analysis["email"]["file"]["sha256"]
    assert detail["threat_assessment"] is not None
    assessment = detail["threat_assessment"]
    assert assessment["verdict"] == seeded_analysis["risk"]["verdict"]
    assert isinstance(assessment["reasons"], list)
    assert isinstance(detail["indicators"], list)
    assert isinstance(detail["evidence"], list)
    # Privacy: derived data only — the raw email must never appear.
    serialized = str(detail)
    assert "Received:" not in serialized


def test_get_analysis_not_found():
    from app.main import create_app

    with TestClient(create_app()) as client:
        response = client.get("/analyses/00000000-0000-5000-8000-000000000000")
    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "not_found"


def test_get_analysis_rejects_malformed_id():
    from app.main import create_app

    with TestClient(create_app()) as client:
        response = client.get("/analyses/not%20a%20uuid%20with%20slashes/../etc")
    assert response.status_code in (404, 400)
