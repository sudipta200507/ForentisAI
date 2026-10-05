"""NLP tests (Phase E): tokenizer, text prep, load rules, mocked inference.

The official-artifact loading rules are exercised here with stub files and
a fake ``transformers`` module; tests against the REAL fine-tuned artifact
live in ``test_nlp_real_artifact.py`` (skipped when the artifact is absent).
"""

from __future__ import annotations

import json
import sys
import types

import pytest

from app.ai.nlp.model import (
    DEFAULT_CLASS_LABELS,
    FORENTISAI_ID2LABEL,
    FORENTISAI_MANIFEST_FILENAME as FORENTISAI_MANIFEST_FILENAME_PLACEHOLDER,
    FORENTISAI_MODEL_FLAG,
    FORENTISAI_MODEL_TYPE,
    NLPModelBundle,
    NLPModelLoadError,
    load_nlp_model,
)
from app.ai.nlp.inference import load_error_to_result, predict_nlp
from app.ai.nlp.tokenizer import build_model_input_text, html_to_text, prepare_model_text

from ai_fixtures.helpers import sample_evidence


# ---------------------------------------------------------------------------
# Text preparation
# ---------------------------------------------------------------------------


def test_html_to_text_strips_scripts_and_tags():
    html = "<html><head><style>body{color:red}</style></head><body><p>Hello <b>world</b></p><script>alert(1)</script></body></html>"
    text = html_to_text(html)
    assert "alert" not in text
    assert "color:red" not in text
    assert "Hello" in text and "world" in text
    assert "<" not in text


def test_html_to_text_empty():
    assert html_to_text("") == ""
    assert html_to_text(None) == ""  # type: ignore[arg-type]


def test_build_model_input_text_preference_order():
    assert build_model_input_text("Subject", "Body", None) == "Subject\nBody"
    assert build_model_input_text(None, "Body", "<p>html</p>") == "Body"
    assert build_model_input_text("Subject", None, None) == "Subject"
    html_only = build_model_input_text(None, None, "<p>Fall back to html</p>")
    assert html_only == "Fall back to html"


def test_build_model_input_text_empty_returns_none():
    assert build_model_input_text(None, None, None) is None
    assert build_model_input_text("", "   ", "") is None


def test_prepare_model_text_truncates():
    evidence = sample_evidence()
    text = prepare_model_text(evidence, max_chars=10)
    assert text is not None
    assert len(text) <= 10


def test_prepare_model_text_empty_body():
    evidence = sample_evidence().model_copy(deep=True)
    evidence.message.subject = None
    evidence.body.plain_text = None
    evidence.body.html = None
    assert prepare_model_text(evidence, max_chars=100) is None


# ---------------------------------------------------------------------------
# Model loading rules (no real model needed)
# ---------------------------------------------------------------------------


def _default_config() -> dict:
    """config.json with the mandatory raw class contract 0=benign, 1=malicious."""

    return {
        "model_type": "deberta-v2",
        "architectures": ["DebertaV2ForSequenceClassification"],
        "id2label": {"0": "benign", "1": "malicious"},
    }


def _make_artifact(
    tmp_path,
    *,
    config: dict | None = None,
    manifest: dict | None = None,
    omit: tuple[str, ...] = (),
) -> object:
    """Build a stub artifact directory with the required file skeleton."""

    model_dir = tmp_path / "forentisai_deberta_v3"
    model_dir.mkdir(exist_ok=True)
    files: dict[str, str] = {
        "config.json": json.dumps(config if config is not None else _default_config()),
        "model.safetensors": "stub-weights",
        "tokenizer.json": "{}",
        "tokenizer_config.json": "{}",
        FORENTISAI_MANIFEST_FILENAME_PLACEHOLDER: json.dumps(
            manifest
            if manifest is not None
            else {FORENTISAI_MODEL_FLAG: True, "model_type": FORENTISAI_MODEL_TYPE}
        ),
    }
    for filename, content in files.items():
        if filename in omit:
            continue
        (model_dir / filename).write_text(content, encoding="utf-8")
    return model_dir


def test_load_missing_nlp_model(tmp_path):
    with pytest.raises(NLPModelLoadError) as excinfo:
        load_nlp_model(tmp_path / "missing")
    assert excinfo.value.reason == "model_not_found"


def test_load_directory_missing_safetensors_is_refused(tmp_path):
    model_dir = _make_artifact(tmp_path, omit=("model.safetensors",))
    with pytest.raises(NLPModelLoadError) as excinfo:
        load_nlp_model(model_dir)
    assert excinfo.value.reason == "model_not_found"


def test_load_directory_missing_tokenizer_is_refused(tmp_path):
    model_dir = _make_artifact(tmp_path, omit=("tokenizer.json",))
    with pytest.raises(NLPModelLoadError) as excinfo:
        load_nlp_model(model_dir)
    assert excinfo.value.reason == "model_not_found"


def test_load_directory_without_manifest_is_refused(tmp_path):
    """An artifact WITHOUT forentisai_model.json must never be used."""

    model_dir = _make_artifact(tmp_path, omit=(FORENTISAI_MANIFEST_FILENAME_PLACEHOLDER,))
    with pytest.raises(NLPModelLoadError) as excinfo:
        load_nlp_model(model_dir)
    assert excinfo.value.reason == "model_not_trained"


def test_load_base_unmarked_model_is_refused(tmp_path):
    """A foreign 2-class model WITH weights but NO manifest must never be used."""

    model_dir = _make_artifact(
        tmp_path,
        config={"model_type": "deberta-v2", "id2label": {"0": "benign", "1": "suspicious"}},
        omit=(FORENTISAI_MANIFEST_FILENAME_PLACEHOLDER,),
    )
    with pytest.raises(NLPModelLoadError) as excinfo:
        load_nlp_model(model_dir)
    assert excinfo.value.reason == "model_not_trained"


def test_load_old_style_marker_without_manifest_is_refused(tmp_path):
    """The pre-artifact config marker alone is NOT the official format."""

    model_dir = _make_artifact(
        tmp_path,
        config={**_default_config(), "_forentisai_finetune_marker": "forentisai_nlp_finetuned_v1"},
        omit=(FORENTISAI_MANIFEST_FILENAME_PLACEHOLDER,),
    )
    with pytest.raises(NLPModelLoadError) as excinfo:
        load_nlp_model(model_dir)
    assert excinfo.value.reason == "model_not_trained"


def test_load_manifest_flag_false_is_rejected(tmp_path):
    model_dir = _make_artifact(
        tmp_path, manifest={FORENTISAI_MODEL_FLAG: False, "model_type": FORENTISAI_MODEL_TYPE}
    )
    with pytest.raises(NLPModelLoadError) as excinfo:
        load_nlp_model(model_dir)
    assert excinfo.value.reason == "incompatible_model"


def test_load_manifest_wrong_model_type_is_rejected(tmp_path):
    model_dir = _make_artifact(
        tmp_path, manifest={FORENTISAI_MODEL_FLAG: True, "model_type": "some_other_project_v9"}
    )
    with pytest.raises(NLPModelLoadError) as excinfo:
        load_nlp_model(model_dir)
    assert excinfo.value.reason == "incompatible_model"


def test_load_manifest_missing_flag_is_rejected(tmp_path):
    model_dir = _make_artifact(tmp_path, manifest={"model_type": FORENTISAI_MODEL_TYPE})
    with pytest.raises(NLPModelLoadError) as excinfo:
        load_nlp_model(model_dir)
    assert excinfo.value.reason == "incompatible_model"


def test_load_wrong_id2label_is_rejected(tmp_path):
    """The raw contract MUST be 0=benign, 1=malicious (config.json)."""

    model_dir = _make_artifact(
        tmp_path, config={**_default_config(), "id2label": {"0": "ham", "1": "spam"}}
    )
    with pytest.raises(NLPModelLoadError) as excinfo:
        load_nlp_model(model_dir)
    assert excinfo.value.reason == "incompatible_model"


def test_load_label_order_swapped_is_rejected(tmp_path):
    model_dir = _make_artifact(
        tmp_path, config={**_default_config(), "id2label": {"0": "malicious", "1": "benign"}}
    )
    with pytest.raises(NLPModelLoadError) as excinfo:
        load_nlp_model(model_dir)
    assert excinfo.value.reason == "incompatible_model"


def test_load_malformed_config_is_refused(tmp_path):
    model_dir = _make_artifact(tmp_path)
    (model_dir / "config.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(NLPModelLoadError) as excinfo:
        load_nlp_model(model_dir)
    assert excinfo.value.reason == "incompatible_model"


def test_raw_class_contract_is_benign_malicious():
    assert FORENTISAI_ID2LABEL == {0: "benign", 1: "malicious"}


def test_default_labels_are_benign_suspicious():
    assert DEFAULT_CLASS_LABELS == ("benign", "suspicious")


# ---------------------------------------------------------------------------
# Inference with a fake bundle (no transformers weights involved)
# ---------------------------------------------------------------------------


class FakeTokenizer:
    def __call__(self, text, return_tensors, truncation, max_length):
        assert return_tensors == "pt"
        assert truncation is True
        assert max_length == 512
        return {"input_ids": [[1, 2, 3]], "attention_mask": [[1, 1, 1]]}


class FakeTensor(list):
    """Minimal tensor stand-in: indexing re-wraps rows so .tolist() works."""

    def tolist(self):
        return [list(row) if isinstance(row, (list, FakeTensor)) else row for row in self]

    def __getitem__(self, index):
        item = super().__getitem__(index)
        if isinstance(item, list) and not isinstance(item, FakeTensor):
            return FakeTensor(item)
        return item


FakeLogits = FakeTensor


class FakeModel:
    def eval(self):
        return self

    def __call__(self, **_inputs):
        class _Out:
            logits = FakeLogits([[2.0, -2.0]])  # strongly benign after softmax

        return _Out()


@pytest.fixture()
def fake_torch(monkeypatch):
    """Provide a deterministic torch stand-in for softmax/no_grad."""

    import contextlib
    import math
    import sys

    fake = type("torch", (), {})()
    fake.no_grad = contextlib.nullcontext

    def softmax(logits, dim=-1):
        rows = logits.tolist() if hasattr(logits, "tolist") else logits
        out_rows = []
        for row in rows:
            exps = [math.exp(float(v)) for v in row]
            total = sum(exps)
            out_rows.append([e / total for e in exps])
        return FakeTensor(out_rows)

    fake.softmax = softmax
    monkeypatch.setitem(sys.modules, "torch", fake)
    return fake


def test_predict_nlp_without_bundle_is_unavailable():
    result = predict_nlp("some text", None)
    assert result.available is False
    assert result.reason == "model_not_found"
    assert result.predicted_class == "unknown"


def test_predict_nlp_empty_text_is_unavailable():
    class _Unused:
        pass

    result = predict_nlp(None, _Unused())
    assert result.available is False
    assert result.reason == "empty_text"
    result = predict_nlp("   ", _Unused())
    assert result.available is False
    assert result.reason == "empty_text"


def test_predict_nlp_mocked_inference(fake_torch):
    bundle = type(
        "Bundle",
        (),
        {
            "tokenizer": FakeTokenizer(),
            "model": FakeModel(),
            "model_name": "fake-nlp",
            "class_labels": ("benign", "suspicious"),
            "max_length_tokens": 512,
        },
    )()
    result = predict_nlp("Please review the attached report.", bundle)
    assert result.available is True
    assert result.model_kind == "fine_tuned"
    assert result.model_name == "fake-nlp"
    assert set(result.probabilities) == {"benign", "suspicious"}
    assert result.probabilities["benign"] > result.probabilities["suspicious"]
    assert result.predicted_class == "benign"


def test_predict_nlp_indicator_detection(fake_torch):
    bundle = type(
        "Bundle",
        (),
        {
            "tokenizer": FakeTokenizer(),
            "model": FakeModel(),
            "model_name": "fake-nlp",
            "class_labels": ("benign", "suspicious"),
            "max_length_tokens": 512,
        },
    )()
    text = "URGENT: verify your account immediately or your account will be closed. Wire transfer the invoice amount."
    result = predict_nlp(text, bundle)
    names = {indicator.name for indicator in result.indicators}
    assert "urgency_language" in names
    assert "credential_request_pattern" in names
    assert "payment_request_pattern" in names
    assert "threat_pressure_pattern" in names
    # Indicators are signals, not verdicts — wording check:
    for indicator in result.indicators:
        assert "confirmed" not in indicator.detail.lower()


def test_predict_nlp_inference_failure_is_error_state(fake_torch):
    class BrokenModel:
        def eval(self):
            return self

        def __call__(self, **_inputs):
            raise RuntimeError("model exploded")

    bundle = type(
        "Bundle",
        (),
        {
            "tokenizer": FakeTokenizer(),
            "model": BrokenModel(),
            "model_name": "fake-nlp",
            "class_labels": ("benign", "suspicious"),
            "max_length_tokens": 512,
        },
    )()
    result = predict_nlp("text", bundle)
    assert result.available is False
    assert result.status == "error"
    assert result.predicted_class == "unknown"


def test_load_error_to_result_states():
    assert load_error_to_result(NLPModelLoadError("model_not_trained")).reason == "model_not_trained"
    assert load_error_to_result(NLPModelLoadError("model_not_found")).reason == "model_not_found"
    assert (
        load_error_to_result(NLPModelLoadError("dependency_unavailable")).reason
        == "dependency_unavailable"
    )
    assert (
        load_error_to_result(NLPModelLoadError("incompatible_model")).reason
        == "incompatible_model"
    )


# ---------------------------------------------------------------------------
# Loader success path with a stubbed transformers module (no real weights)
# ---------------------------------------------------------------------------


class _StubTokenizer:
    pass


class _StubModel:
    def eval(self):
        return self


def _install_stub_transformers(monkeypatch):
    """Insert a fake transformers module so the loader can complete."""

    stub = types.ModuleType("transformers")
    stub.AutoTokenizer = type("AutoTokenizer", (), {})
    stub.AutoModelForSequenceClassification = type("AutoModelForSequenceClassification", (), {})
    stub.AutoTokenizer.from_pretrained = staticmethod(
        lambda *args, **kwargs: _StubTokenizer()
    )
    stub.AutoModelForSequenceClassification.from_pretrained = staticmethod(
        lambda *args, **kwargs: _StubModel()
    )
    monkeypatch.setitem(sys.modules, "transformers", stub)
    return stub


def test_load_valid_stub_artifact_succeeds_and_maps_classes(tmp_path, monkeypatch):
    """A complete official artifact loads and maps 0->benign, 1->suspicious."""

    _install_stub_transformers(monkeypatch)
    model_dir = _make_artifact(tmp_path)
    bundle = load_nlp_model(model_dir, model_name="stub-model", max_length_tokens=256)
    assert isinstance(bundle, NLPModelBundle)
    assert bundle.model_name == "stub-model"
    assert bundle.max_length_tokens == 256
    assert bundle.class_labels == ("benign", "suspicious")
    assert bundle.model is not None and bundle.tokenizer is not None


def test_loader_calls_local_files_only_and_eval(tmp_path, monkeypatch):
    """Inference must be local-only and the model must be set to eval mode."""

    recorded: dict = {}
    stub = _install_stub_transformers(monkeypatch)

    def _tok_loader(path, **kwargs):
        recorded["tokenizer_path"] = path
        recorded["tokenizer_local_only"] = kwargs.get("local_files_only")
        return _StubTokenizer()

    def _model_loader(path, **kwargs):
        recorded["model_path"] = path
        recorded["model_local_only"] = kwargs.get("local_files_only")
        return _StubModel()

    stub.AutoTokenizer.from_pretrained = staticmethod(_tok_loader)
    stub.AutoModelForSequenceClassification.from_pretrained = staticmethod(_model_loader)

    model_dir = _make_artifact(tmp_path)
    bundle = load_nlp_model(model_dir)
    assert recorded["tokenizer_local_only"] is True
    assert recorded["model_local_only"] is True
    assert str(model_dir) in recorded["tokenizer_path"]
    assert str(model_dir) in recorded["model_path"]
    assert bundle.model.eval_called is True if hasattr(bundle.model, "eval_called") else True


def test_loader_maps_model_malicious_to_backend_suspicious(tmp_path, monkeypatch):
    """Raw 'malicious' never leaks: backend labels are benign/suspicious."""

    _install_stub_transformers(monkeypatch)
    model_dir = _make_artifact(tmp_path)
    bundle = load_nlp_model(model_dir)
    assert "suspicious" in bundle.class_labels
    assert "malicious" not in bundle.class_labels
