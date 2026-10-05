"""End-to-end test: real sample email → full API pipeline with the real model.

Runs the ACTUAL fine-tuned ForentisAI DeBERTa-v3 artifact inside the real
``POST /analyze-email`` pipeline:

    .eml → extraction (Step 1) → authentication (Step 2, Rspamd)
         → intelligence (Step 4, offline) → real DeBERTa inference (Step 5)
         → fusion → API response

The test verifies that the API no longer reports ``model_not_found`` or
``model_not_trained`` for the correctly configured local artifact. It makes
NO accuracy claim: the model was trained on the synthetic
ForentisAI_DeBERTa_Dataset_V2, and these assertions are pipeline-integration
checks only.

Skips when the artifact is absent (artifact is a local, git-ignored
deployment artifact) or when the Rspamd container is not running.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.ai import model_registry
from app.api import dependencies
from app.main import app as fastapi_app

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SAMPLE_EML = PROJECT_ROOT / "samples" / "safe" / "step1_synthetic.eml"
ARTIFACT_DIR = PROJECT_ROOT / "ai" / "models" / "nlp" / "forentisai_deberta_v3"

# Skip when the fine-tuned artifact is not installed locally.
pytestmark = pytest.mark.skipif(
    not ARTIFACT_DIR.is_dir() or not (ARTIFACT_DIR / "model.safetensors").is_file(),
    reason=f"Fine-tuned ForentisAI artifact not present at {ARTIFACT_DIR}",
)


@pytest.fixture()
def real_artifact_ai_settings():
    """AI settings pointing at the REAL fine-tuned artifact (AI enabled)."""

    model_registry.clear_caches()
    settings = dependencies.get_ai_settings()
    model_registry.clear_caches()
    return settings


@pytest.fixture()
def client(real_artifact_ai_settings):
    fastapi_app.dependency_overrides[dependencies.get_ai_settings] = (
        lambda: real_artifact_ai_settings
    )
    yield TestClient(fastapi_app)
    fastapi_app.dependency_overrides.pop(dependencies.get_ai_settings, None)
    model_registry.clear_caches()


def _post_sample(client: TestClient):
    with open(SAMPLE_EML, "rb") as handle:
        return client.post(
            "/analyze-email",
            files={"upload": ("step1_synthetic.eml", handle, "message/rfc822")},
        )


def _require_rspamd(client: TestClient) -> None:
    """Skip when the Rspamd container is unavailable (separate concern)."""

    probe = client.get("/health/rspamd")
    if probe.status_code != 200:
        pytest.skip("Rspamd container is not running (docker compose up -d rspamd)")


def test_real_email_end_to_end_pipeline(client):
    _require_rspamd(client)
    response = _post_sample(client)
    assert response.status_code == 200
    body = response.json()

    # Steps 1-4 sections remain intact and valid:
    assert body["email"]["schema_version"] == "1.0"
    assert body["authentication"]["schema_version"] == "1.0"
    assert body["intelligence"]["schema_version"] == "1.0"

    ai = body["ai"]
    nlp = ai["nlp"]

    # The real artifact is configured and loaded — the historical failure
    # modes must be gone:
    assert nlp["reason"] != "model_not_found"
    assert nlp["reason"] != "model_not_trained"
    assert nlp["available"] is True
    assert nlp["status"] == "available"
    assert nlp["model_kind"] == "fine_tuned"
    assert nlp["model_name"] == "microsoft/deberta-v3-base"

    # Evidence-only class contract (raw 'malicious' never surfaces):
    assert set(nlp["probabilities"]) == {"benign", "suspicious"}
    assert "malicious" not in nlp["probabilities"]
    for value in nlp["probabilities"].values():
        assert 0.0 <= value <= 1.0
    assert abs(sum(nlp["probabilities"].values()) - 1.0) < 1e-6
    assert nlp["predicted_class"] in {"benign", "suspicious"}

    # Fusion consumed the NLP evidence ('suspicious' probability key):
    assert ai["fusion"]["available"] is True
    signals = {signal["source"]: signal for signal in ai["fusion"]["signals"]}
    assert signals["nlp"]["contributed"] is True
    nlp_p = signals["nlp"]["suspicious_probability"]
    assert nlp_p is not None
    assert abs(nlp_p - nlp["probabilities"]["suspicious"]) < 1e-5

    # Model evidence only — never a verdict/risk-score vocabulary:
    for forbidden_key in ("risk_score", "final_verdict", "severity", "forensic_report", "threat_type"):
        assert forbidden_key not in ai


def test_real_artifact_no_model_not_found_state_without_rspamd(client):
    """Even with Step 2 faked, the NLP section must be genuinely available."""

    from app.schemas.authentication import RspamdAnalysis, RspamdSymbol

    class _StubRspamdClient:
        def scan_bytes(self, raw_email: bytes):
            return RspamdAnalysis(
                action="no action",
                score=0.1,
                required_score=15.0,
                symbols={
                    "R_SPF_NA": RspamdSymbol(score=0.0),
                    "R_DKIM_NA": RspamdSymbol(score=0.0),
                    "DMARC_NA": RspamdSymbol(score=0.0),
                },
                message_id="<step1-fixture@example.test>",
                scanned=True,
            )

    fastapi_app.dependency_overrides[dependencies.get_rspamd_client] = (
        lambda: _StubRspamdClient()
    )
    try:
        response = _post_sample(client)
    finally:
        fastapi_app.dependency_overrides.pop(dependencies.get_rspamd_client, None)

    assert response.status_code == 200
    nlp = response.json()["ai"]["nlp"]
    assert nlp["reason"] not in {"model_not_found", "model_not_trained"}
    assert nlp["available"] is True
    assert nlp["status"] == "available"
    assert nlp["model_kind"] == "fine_tuned"


def test_real_artifact_default_settings_resolve_to_trained_model():
    """load_ai_settings() resolves the default path to the REAL artifact."""

    from app.core.config import load_ai_settings

    settings = load_ai_settings()
    assert settings.ai_enabled is True
    assert settings.nlp_model_path is not None
    resolved = Path(settings.nlp_model_path)
    assert resolved.is_dir()
    assert (resolved / "forentisai_model.json").is_file()
    assert (resolved / "model.safetensors").is_file()
    assert resolved == ARTIFACT_DIR.resolve()
