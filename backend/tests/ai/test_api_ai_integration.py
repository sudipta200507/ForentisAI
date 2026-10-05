"""API-level AI tests (Phase J/L): the ``ai`` field and failure isolation."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api import dependencies
from app.core.config import AISettings, DEFAULT_TECHNICAL_MODEL_FILENAME
from app.main import app as fastapi_app

from ai_fixtures.helpers import SAMPLE_PATH as SAMPLE_EML
from ai_fixtures.helpers import make_technical_bundle, save_bundle, zero_vector


@pytest.fixture()
def client() -> TestClient:
    return TestClient(fastapi_app)


def _post(client: TestClient):
    with open(SAMPLE_EML, "rb") as handle:
        return client.post(
            "/analyze-email",
            files={"upload": ("step1_synthetic.eml", handle, "message/rfc822")},
        )


def test_response_contains_all_four_sections(client):
    response = _post(client)
    assert response.status_code == 200
    body = response.json()
    # The four evidence sections plus the Phase 3/5/5A product sections.
    assert set(body.keys()) == {
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
    # Step 1-4 fields unchanged (still exactly their evidence shapes):
    assert body["email"]["schema_version"] == "1.0"
    assert body["authentication"]["schema_version"] == "1.0"
    assert body["intelligence"]["schema_version"] == "1.0"


def test_ai_section_unavailable_without_models(client, monkeypatch, tmp_path):
    fastapi_app.dependency_overrides[dependencies.get_ai_settings] = lambda: AISettings(
        ai_enabled=True,
        model_dir=tmp_path,
        technical_model_path=tmp_path / DEFAULT_TECHNICAL_MODEL_FILENAME,
        nlp_model_path=None,
    )
    try:
        response = _post(client)
        assert response.status_code == 200
        ai = response.json()["ai"]
        assert ai["status"] == "unavailable"
        assert ai["technical_ml"]["reason"] == "model_not_found"
        assert ai["nlp"]["reason"] == "model_not_found"
        assert ai["fusion"]["predicted_class"] == "unknown"
    finally:
        fastapi_app.dependency_overrides.pop(dependencies.get_ai_settings, None)


def test_ai_section_available_with_fixture_model(client, tmp_path):
    """With the pipeline-validation fixture model the ai section is available."""

    import numpy as np

    from app.ai.technical_ml.inference import vector_to_array
    from app.ai.technical_ml.model import build_pipeline

    model_path = tmp_path / DEFAULT_TECHNICAL_MODEL_FILENAME
    rng = np.random.default_rng(42)
    X = rng.normal(size=(60, len(vector_to_array(zero_vector())[0])))
    y = np.where(X[:, 0] > 0, "suspicious", "benign")
    pipeline = build_pipeline(n_estimators=10)
    pipeline.fit(X, y)
    save_bundle(make_technical_bundle(pipeline), model_path)

    fastapi_app.dependency_overrides[dependencies.get_ai_settings] = lambda: AISettings(
        ai_enabled=True,
        model_dir=tmp_path,
        technical_model_path=model_path,
        nlp_model_path=None,
    )
    try:
        response = _post(client)
        assert response.status_code == 200
        ai = response.json()["ai"]
        assert ai["status"] == "available"
        assert ai["technical_ml"]["available"] is True
        assert set(ai["technical_ml"]["probabilities"]) == {"benign", "suspicious"}
        assert ai["fusion"]["available"] is True
        assert ai["explainability"]["shap_available"] is True
    finally:
        fastapi_app.dependency_overrides.pop(dependencies.get_ai_settings, None)


def test_ai_disabled_via_config(client, monkeypatch, tmp_path):
    fastapi_app.dependency_overrides[dependencies.get_ai_settings] = lambda: AISettings(
        ai_enabled=False,
        model_dir=tmp_path,
        technical_model_path=tmp_path / DEFAULT_TECHNICAL_MODEL_FILENAME,
    )
    try:
        response = _post(client)
        assert response.status_code == 200
        ai = response.json()["ai"]
        assert ai["status"] == "unavailable"
        assert ai["nlp"]["reason"] == "not_enabled"
        # The rest of the analysis is unaffected:
        assert response.json()["email"]["schema_version"] == "1.0"
    finally:
        fastapi_app.dependency_overrides.pop(dependencies.get_ai_settings, None)


def test_no_risk_score_or_verdict_fields_in_ai(client):
    response = _post(client)
    body = response.json()
    ai = body["ai"]
    for forbidden_key in ("risk_score", "final_verdict", "severity", "forensic_report", "threat_type"):
        assert forbidden_key not in ai


def test_ai_failure_does_not_crash_api(client, monkeypatch):
    """A crashing AI orchestrator still returns 200 with valid Step 1-4 data."""

    import app.api.routes.analysis as analysis_module

    def _explode(*_args, **_kwargs):
        raise RuntimeError("AI subsystem down")

    monkeypatch.setattr(analysis_module, "build_ai_analysis", _explode)
    response = _post(client)
    assert response.status_code == 200
    body = response.json()
    assert body["email"]["schema_version"] == "1.0"
    assert body["authentication"]["schema_version"] == "1.0"
    assert body["ai"]["status"] == "unavailable"  # default AIAnalysis()


def test_no_email_content_logged_by_ai_path(client, caplog):
    """The AI path must not log raw email bodies, subjects, or headers."""

    import logging

    with caplog.at_level(logging.DEBUG):
        response = _post(client)
    assert response.status_code == 200
    email = response.json()["email"]
    secrets = [
        email["message"].get("subject") or "",
        (email["body"].get("plain_text") or "")[:200],
        email["file"]["sha256"],
    ]
    secrets = [secret for secret in secrets if secret]
    for record in caplog.records:
        for secret in secrets:
            assert secret not in record.getMessage()
