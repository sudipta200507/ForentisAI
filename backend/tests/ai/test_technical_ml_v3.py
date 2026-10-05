"""Technical ML format-3 (production V1) artifact tests.

Covers the actual production artifact at ``ai/models/technical_model.joblib``
(format 3, dict, 28 model features, threshold 0.33) plus synthetic format-3
artifacts for controlled failure modes and threshold semantics.

Honesty note: these tests validate MECHANICS (loading, contract, threshold
application). They make no accuracy claim — V1 metrics are corpus metrics on
the project-supplied V1 dataset (see docs/training_report.json) and do not
establish real-world performance.
"""

from __future__ import annotations

import joblib
import numpy as np
import pytest
from pathlib import Path

from app.ai.explainability.shap_explainer import explain_technical_prediction
from app.ai.technical_ml.inference import (
    load_error_to_result,
    predict_technical,
    prediction_array,
    vector_to_array,
)
from app.ai.technical_ml.model import (
    TechnicalModelLoadError,
    TechnicalModelV3Bundle,
    load_technical_model,
)
from app.schemas.features import feature_names

from ai_fixtures.helpers import zero_vector

PROJECT_ROOT = Path(__file__).resolve().parents[3]
REAL_ARTIFACT = PROJECT_ROOT / "ai" / "models" / "technical_model.joblib"

pytestmark = pytest.mark.skipif(
    not REAL_ARTIFACT.is_file(),
    reason=f"Production technical artifact not present at {REAL_ARTIFACT}",
)


# ---------------------------------------------------------------------------
# Stub estimator for exact threshold-semantics tests (unit test double only)
# ---------------------------------------------------------------------------


class _StubForest:
    """Deterministic predict_proba double: benign=0.6, suspicious=0.4."""

    classes_ = np.array(["benign", "suspicious"])

    def predict_proba(self, _array):
        return np.array([[0.6, 0.4]])


class _StubHighSuspicion:
    """Deterministic predict_proba double: benign=0.2, suspicious=0.8."""

    classes_ = np.array(["benign", "suspicious"])

    def predict_proba(self, _array):
        return np.array([[0.2, 0.8]])


class _SmokePassingBrokenModel:
    """Passes the loader smoke test (zeros) but fails on real features."""

    classes_ = np.array([0, 1])

    def predict_proba(self, array):
        if np.any(array):
            raise RuntimeError("broken estimator on real input")
        return np.array([[0.5, 0.5]])


V3_NAMES: tuple[str, ...] = tuple(
    name
    for name in feature_names()
    if name.split(".", 1)[0] in {"text", "header", "url"}
)
assert len(V3_NAMES) == 28


def _v3_artifact_dict(model, threshold=0.33, names=V3_NAMES, **overrides) -> dict:
    artifact = {
        "artifact_format_version": 3,
        "model_type": "RandomForestClassifier",
        "dataset_name": "ForentisAI_TechnicalML_Dataset_V1",
        "feature_contract_version": "technical-30-eml-v1",
        "feature_names": list(names),
        "excluded_constant_features": [
            "intelligence.public_ip_count",
            "intelligence.non_public_ip_count",
        ],
        "model": model,
        "model_parameters": {"n_estimators": 200, "random_state": 42, "n_jobs": 1},
        "suspicious_threshold": threshold,
        "threshold_selection": {"method": "validation_f1"},
        "training": {"training_samples": 9145, "training_features": len(list(names))},
        "test_metrics": {"accuracy": 0.9758},
        "created_at": "2026-10-02T22:32:08+00:00",
        "limitations": ["unit-test artifact"],
    }
    artifact.update(overrides)
    return artifact


def _save_v3(tmp_path: Path, artifact: dict, name: str = "v3.joblib") -> Path:
    path = tmp_path / name
    joblib.dump(artifact, path)
    return path


# ---------------------------------------------------------------------------
# Real production artifact
# ---------------------------------------------------------------------------


def test_real_v3_artifact_loads():
    bundle = load_technical_model(REAL_ARTIFACT)
    assert isinstance(bundle, TechnicalModelV3Bundle)
    assert bundle.artifact_format_version == 3
    assert bundle.threshold == pytest.approx(0.33)
    assert bundle.dataset_name == "ForentisAI_TechnicalML_Dataset_V1"
    assert bundle.feature_contract_version == "technical-30-eml-v1"
    assert len(bundle.feature_names) == 28
    # The artifact contract is exactly the documented V1 30-feature set minus
    # the two constant Received-IP features.
    runtime = set(feature_names())
    assert all(name in runtime for name in bundle.feature_names)
    assert set(bundle.excluded_constant_features) == {
        "intelligence.public_ip_count",
        "intelligence.non_public_ip_count",
    }
    assert bundle.compatibility_note is not None  # sklearn 1.6.1 -> 1.8.0 warning captured
    assert "InconsistentVersionWarning" in bundle.compatibility_note or (
        "version" in bundle.compatibility_note
    )


def test_real_v3_artifact_predicts_with_threshold_metadata():
    bundle = load_technical_model(REAL_ARTIFACT)
    result = predict_technical(zero_vector(), bundle)
    assert result.available is True
    assert result.status == "available"
    assert result.predicted_class in {"benign", "suspicious"}
    assert set(result.probabilities) == {"benign", "suspicious"}
    assert sum(result.probabilities.values()) == pytest.approx(1.0, abs=1e-6)
    assert result.threshold == pytest.approx(0.33)
    assert result.artifact_format_version == 3
    assert result.feature_contract_version == "technical-30-eml-v1"
    assert result.dataset_name == "ForentisAI_TechnicalML_Dataset_V1"
    assert result.model_feature_count == 28
    # The decision must follow the artifact threshold, not the argmax rule.
    p_susp = result.probabilities["suspicious"]
    expected = "suspicious" if p_susp >= 0.33 else "benign"
    assert result.predicted_class == expected


def test_real_v3_artifact_deterministic():
    bundle = load_technical_model(REAL_ARTIFACT)
    first = predict_technical(zero_vector(), bundle)
    second = predict_technical(zero_vector(), bundle)
    assert first.model_dump_json() == second.model_dump_json()


def test_real_v3_prediction_array_uses_artifact_order():
    bundle = load_technical_model(REAL_ARTIFACT)
    vector = zero_vector()
    vector.text.subject_length = 42
    vector.url.url_count = 3
    array = prediction_array(vector, bundle)
    assert array.shape == (1, 28)
    # Deterministic order: subject_length is the first artifact feature.
    from app.schemas.features import feature_names as runtime_names

    full = vector_to_array(vector)
    assert full.shape == (1, len(runtime_names()))
    # Every value in the v3 array must equal the value at its runtime position.
    runtime_index = {name: i for i, name in enumerate(runtime_names())}
    for position, name in enumerate(bundle.feature_names):
        assert array[0][position] == full[0][runtime_index[name]]
    assert array[0][0] == 42.0


def test_real_v3_shap_contributions_use_artifact_names():
    bundle = load_technical_model(REAL_ARTIFACT)
    array = prediction_array(zero_vector(), bundle)
    explanation = explain_technical_prediction(bundle, array)
    assert explanation.shap_available is True
    for contribution in explanation.contributions:
        assert contribution.feature in bundle.feature_names


def test_real_v3_load_error_maps_to_incompatible():
    result = load_error_to_result(TechnicalModelLoadError("malformed_model"))
    assert result.reason == "incompatible_model"
    assert result.available is False


# ---------------------------------------------------------------------------
# Threshold semantics (exact, via stub estimator)
# ---------------------------------------------------------------------------


def test_v3_threshold_overrides_argmax(tmp_path):
    """p_suspicious=0.4 with threshold 0.33 must flag suspicious (argmax would not)."""

    path = _save_v3(tmp_path, _v3_artifact_dict(_StubForest()))
    bundle = load_technical_model(path)
    result = predict_technical(zero_vector(), bundle)
    assert result.available is True
    assert result.probabilities == {"benign": pytest.approx(0.6), "suspicious": pytest.approx(0.4)}
    assert result.predicted_class == "suspicious"  # 0.4 >= 0.33 threshold
    assert result.confidence == pytest.approx(0.4)  # probability of the predicted class
    assert result.threshold == pytest.approx(0.33)


def test_v3_threshold_keeps_benign_below_threshold(tmp_path):
    path = _save_v3(tmp_path, _v3_artifact_dict(_StubForest(), threshold=0.5))
    bundle = load_technical_model(path)
    result = predict_technical(zero_vector(), bundle)
    # 0.4 < 0.5 threshold → benign, and confidence is the benign probability.
    assert result.predicted_class == "benign"
    assert result.confidence == pytest.approx(0.6)


def test_v3_high_suspicion_flags_suspicious(tmp_path):
    path = _save_v3(tmp_path, _v3_artifact_dict(_StubHighSuspicion()))
    bundle = load_technical_model(path)
    result = predict_technical(zero_vector(), bundle)
    assert result.predicted_class == "suspicious"
    assert result.confidence == pytest.approx(0.8)


def test_v3_threshold_indicator_present(tmp_path):
    path = _save_v3(tmp_path, _v3_artifact_dict(_StubForest()))
    bundle = load_technical_model(path)
    result = predict_technical(zero_vector(), bundle)
    names = [indicator.name for indicator in result.indicators]
    assert "technical_threshold_decision" in names


# ---------------------------------------------------------------------------
# Malformed / incompatible v3 artifacts (controlled errors)
# ---------------------------------------------------------------------------


def test_v3_wrong_format_version_rejected(tmp_path):
    path = _save_v3(tmp_path, _v3_artifact_dict(_StubForest(), artifact_format_version=4))
    with pytest.raises(TechnicalModelLoadError) as excinfo:
        load_technical_model(path)
    assert excinfo.value.reason == "incompatible_model"


def test_v3_wrong_model_type_rejected(tmp_path):
    path = _save_v3(tmp_path, _v3_artifact_dict(_StubForest(), model_type="GradientBoosting"))
    with pytest.raises(TechnicalModelLoadError) as excinfo:
        load_technical_model(path)
    assert excinfo.value.reason == "incompatible_model"


def test_v3_missing_model_rejected(tmp_path):
    artifact = _v3_artifact_dict(_StubForest())
    del artifact["model"]
    path = _save_v3(tmp_path, artifact)
    with pytest.raises(TechnicalModelLoadError) as excinfo:
        load_technical_model(path)
    assert excinfo.value.reason == "incompatible_model"


def test_v3_unknown_feature_name_rejected(tmp_path):
    names = list(V3_NAMES)
    names[0] = "text.not_a_runtime_feature"
    path = _save_v3(tmp_path, _v3_artifact_dict(_StubForest(), names=names))
    with pytest.raises(TechnicalModelLoadError) as excinfo:
        load_technical_model(path)
    assert excinfo.value.reason == "incompatible_model"


def test_v3_duplicate_feature_names_rejected(tmp_path):
    names = list(V3_NAMES)
    names[1] = names[0]
    path = _save_v3(tmp_path, _v3_artifact_dict(_StubForest(), names=names))
    with pytest.raises(TechnicalModelLoadError) as excinfo:
        load_technical_model(path)
    assert excinfo.value.reason == "malformed_model"


def test_v3_empty_feature_names_rejected(tmp_path):
    path = _save_v3(tmp_path, _v3_artifact_dict(_StubForest(), names=[]))
    with pytest.raises(TechnicalModelLoadError) as excinfo:
        load_technical_model(path)
    assert excinfo.value.reason == "malformed_model"


def test_v3_threshold_out_of_range_rejected(tmp_path):
    path = _save_v3(tmp_path, _v3_artifact_dict(_StubForest(), threshold=1.5))
    with pytest.raises(TechnicalModelLoadError) as excinfo:
        load_technical_model(path)
    assert excinfo.value.reason == "malformed_model"


def test_v3_included_excluded_feature_rejected(tmp_path):
    names = list(V3_NAMES)
    names[0] = "intelligence.public_ip_count"  # declared excluded but present
    path = _save_v3(
        tmp_path,
        _v3_artifact_dict(_StubForest(), names=names),
    )
    with pytest.raises(TechnicalModelLoadError) as excinfo:
        load_technical_model(path)
    assert excinfo.value.reason == "incompatible_model"


def test_v3_arbitrary_dict_rejected(tmp_path):
    path = _save_v3(tmp_path, {"not": "a bundle"})
    with pytest.raises(TechnicalModelLoadError) as excinfo:
        load_technical_model(path)
    assert excinfo.value.reason == "incompatible_model"


def test_v3_predict_failure_is_error_state(tmp_path):
    path = _save_v3(tmp_path, _v3_artifact_dict(_SmokePassingBrokenModel()))
    bundle = load_technical_model(path)
    vector = zero_vector()
    vector.text.subject_length = 42  # non-zero input triggers the failure
    result = predict_technical(vector, bundle)
    assert result.available is False
    assert result.status == "error"
    assert result.reason == "incompatible_model"


# ---------------------------------------------------------------------------
# Orchestrator integration with the real production artifact
# ---------------------------------------------------------------------------


def test_real_v3_orchestrator_technical_available():
    """build_ai_analysis must report an available technical model (V1 artifact)."""

    from app.core.config import AISettings, load_ai_settings
    from app.extractor.email_parser import extract_email_from_bytes

    settings = load_ai_settings()
    sample = PROJECT_ROOT / "samples" / "safe" / "step1_synthetic.eml"
    evidence = extract_email_from_bytes(sample.read_bytes(), filename="step1_synthetic.eml")

    from app.ai import model_registry

    model_registry.clear_caches()
    try:
        from app.ai.orchestrator import build_ai_analysis

        analysis = build_ai_analysis(evidence, None, None, settings=settings)
    finally:
        model_registry.clear_caches()

    technical = analysis.technical_ml
    assert technical.available is True, technical.message
    assert technical.reason != "incompatible_model"
    assert technical.threshold == pytest.approx(0.33)
    assert technical.artifact_format_version == 3
    assert technical.model_feature_count == 28
    # Fusion must now combine BOTH models.
    assert analysis.fusion.available is True
    signals = {signal.source: signal for signal in analysis.fusion.signals}
    assert signals["technical_ml"].contributed is True


def test_v3_settings_resolve_to_real_artifact():
    from app.core.config import load_ai_settings

    settings = load_ai_settings()
    assert settings.technical_model_path == REAL_ARTIFACT
    assert settings.technical_model_path.is_file()
