"""Real-artifact NLP tests: the actual fine-tuned ForentisAI DeBERTa-v3 model.

These tests load the REAL artifact at
``ai/models/nlp/forentisai_deberta_v3`` (or ``$NLP_MODEL_PATH``) and run
genuine CPU inference. They are the integration counterpart to the stubbed
tests in ``test_nlp.py`` and skip (never fail) when the artifact has not
been placed locally.

Honesty rules encoded here:

- metrics from the synthetic V2 training/evaluation data must never be
  presented as real-world performance — these tests make NO accuracy claim;
- loading must be strictly local (``local_files_only=True``) and cached;
- raw class 0 ("benign") maps to backend "benign"; raw class 1
  ("malicious") maps to backend "suspicious" — the raw label never leaks.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from app.ai import model_registry
from app.ai.nlp.model import (
    DEFAULT_CLASS_LABELS,
    NLPModelLoadError,
    load_nlp_model,
)
from app.ai.nlp.inference import predict_nlp

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ARTIFACT = PROJECT_ROOT / "ai" / "models" / "nlp" / "forentisai_deberta_v3"

_raw_path = (os.environ.get("NLP_MODEL_PATH") or "").strip()
if _raw_path:
    candidate = Path(_raw_path)
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    ARTIFACT_DIR = candidate
else:
    ARTIFACT_DIR = DEFAULT_ARTIFACT

pytestmark = pytest.mark.skipif(
    not ARTIFACT_DIR.is_dir() or not (ARTIFACT_DIR / "model.safetensors").is_file(),
    reason=f"Fine-tuned ForentisAI artifact not present at {ARTIFACT_DIR}",
)


@pytest.fixture(scope="module")
def bundle():
    return load_nlp_model(
        ARTIFACT_DIR, model_name="microsoft/deberta-v3-base", max_length_tokens=256
    )


# ---------------------------------------------------------------------------
# Loading rules against the real artifact
# ---------------------------------------------------------------------------


def test_real_artifact_loads_with_correct_parameter_count(bundle):
    import torch  # noqa: F401 - loaded by the loader itself

    assert bundle is not None
    assert bundle.model_name == "microsoft/deberta-v3-base"
    total_params = sum(p.numel() for p in bundle.model.parameters())
    # The trained artifact contains exactly 184,423,682 parameters.
    assert total_params == 184_423_682


def test_real_artifact_backend_class_mapping(bundle):
    """Model class 0 -> backend 'benign'; model class 1 -> backend 'suspicious'."""

    assert bundle.class_labels == ("benign", "suspicious")
    assert bundle.class_labels == DEFAULT_CLASS_LABELS
    # The raw model labels stay benign/malicious inside the HF config:
    assert bundle.model.config.id2label == {0: "benign", 1: "malicious"}
    # The raw 'malicious' label must never leak into the backend tuple:
    assert "malicious" not in bundle.class_labels


def test_real_artifact_load_error_states_for_foreign_artifacts(tmp_path):
    """Foreign/invalid directories still map to controlled error states."""

    with pytest.raises(NLPModelLoadError) as missing:
        load_nlp_model(tmp_path / "does_not_exist")
    assert missing.value.reason == "model_not_found"

    # A complete HF artifact skeleton WITHOUT the ForentisAI manifest:
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    for filename in ("config.json", "tokenizer.json", "tokenizer_config.json"):
        (foreign / filename).write_text("{}", encoding="utf-8")
    (foreign / "model.safetensors").write_bytes(b"stub")
    with pytest.raises(NLPModelLoadError) as unmarked:
        load_nlp_model(foreign)
    assert unmarked.value.reason == "model_not_trained"


# ---------------------------------------------------------------------------
# Real inference semantics
# ---------------------------------------------------------------------------


def test_real_inference_result_shape_and_mapping(bundle):
    result = predict_nlp(
        "URGENT: your account will be suspended. Verify your password immediately.",
        bundle,
    )
    assert result.available is True
    assert result.status == "available"
    assert result.model_kind == "fine_tuned"
    assert result.predicted_class in {"benign", "suspicious"}
    assert set(result.probabilities) == {"benign", "suspicious"}
    for value in result.probabilities.values():
        assert 0.0 <= value <= 1.0
    assert abs(sum(result.probabilities.values()) - 1.0) < 1e-6
    assert result.confidence is not None
    assert 0.0 <= result.confidence <= 1.0


def test_real_inference_probabilities_sum_to_one_and_match_prediction(bundle):
    phishy = predict_nlp(
        "Final notice: wire the invoice amount via gift cards within 24 hours.",
        bundle,
    )
    benign = predict_nlp(
        "Hi team, the meeting notes from yesterday are attached for review.",
        bundle,
    )
    for result in (phishy, benign):
        assert result.available is True
        assert abs(sum(result.probabilities.values()) - 1.0) < 1e-6
        suspicious = result.probabilities["suspicious"]
        benign_prob = result.probabilities["benign"]
        expected = "suspicious" if suspicious >= benign_prob else "benign"
        assert result.predicted_class == expected
        assert result.confidence == pytest.approx(
            max(suspicious, benign_prob), abs=1e-9
        )
    # Raw model label must never surface in the public probabilities:
    assert "malicious" not in phishy.probabilities


def test_real_registry_caches_bundle_across_calls():
    """The registry must load the artifact once and reuse it per request."""

    model_registry.clear_caches()
    first, first_error = model_registry.get_nlp_bundle(
        ARTIFACT_DIR, model_name="microsoft/deberta-v3-base", max_length_tokens=256
    )
    assert first is not None
    assert first_error is None

    second, second_error = model_registry.get_nlp_bundle(
        ARTIFACT_DIR, model_name="microsoft/deberta-v3-base", max_length_tokens=256
    )
    assert second is first  # identical object: no reload
    assert second_error is None
    model_registry.clear_caches()


def test_real_inference_is_offline(monkeypatch, bundle):
    """Any network attempt during inference fails the test (no downloads)."""

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("NLP inference attempted a network operation")

    import socket

    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(socket.socket, "connect", _forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", _forbidden)
    result = predict_nlp("Please review the attached quarterly report.", bundle)
    assert result.available is True
    assert result.predicted_class in {"benign", "suspicious"}
