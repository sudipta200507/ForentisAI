"""NLP model artifact handling (Phase E).

CRITICAL HONESTY RULE
=====================
The base pretrained ``microsoft/deberta-v3-base`` model is NOT a phishing
classifier. Only the official FINE-TUNED ForentisAI artifact — the
``forentisai_deberta_v3`` email-threat classifier trained on
``ForentisAI_DeBERTa_Dataset_V2`` — may produce predictions here.

Official artifact format (validated by :func:`load_nlp_model`)
=============================================================
The fine-tuned artifact directory must contain:

- ``config.json``            HF config (``id2label``: 0→benign, 1→malicious)
- ``model.safetensors``      the trained weights (never committed to git)
- ``tokenizer.json``         fast tokenizer vocabulary
- ``tokenizer_config.json``  tokenizer metadata
- ``forentisai_model.json``  ForentisAI provenance manifest, with
  ``"forentisai_model": true`` and
  ``"model_type": "deberta_v3_email_threat_classifier"``

An artifact without the manifest, with ``forentisai_model != true``, with a
foreign ``model_type``, or with wrong ``id2label`` entries is treated as a
base/foreign model and is NEVER used for prediction.

Label semantics (documented contract)
=====================================
The trained model outputs raw Hugging Face classes::

    model class 0 -> "benign"
    model class 1 -> "malicious"

The backend schema deliberately uses ``benign`` / ``suspicious`` because
"suspicious" is MODEL EVIDENCE, not a final security verdict. Therefore the
inference layer maps::

    model label "benign"    -> internal class "benign"
    model label "malicious" -> internal class "suspicious"

The raw model label "malicious" is never exposed by the backend as a final
security verdict; see ``app/ai/nlp/inference.py`` for the probability
mapping and ``app/schemas/ai.py`` for the evidence-only schema.

Loading rules
=============
- Loading is strictly ``local_files_only=True``: inference must never
  download models during an API request (Phase O). A missing artifact is a
  controlled ``unavailable`` state, not a download trigger.
- Every failure mode maps to a :class:`NLPModelLoadError` reason that the
  inference layer converts into an explicit result state.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

# The official ForentisAI manifest fields (forentisai_model.json inside the
# artifact directory). An artifact is accepted only when both hold:
FORENTISAI_MANIFEST_FILENAME = "forentisai_model.json"
FORENTISAI_MODEL_FLAG = "forentisai_model"  # must be exactly True
FORENTISAI_MODEL_TYPE = "deberta_v3_email_threat_classifier"  # must match

# Raw HF labels the trained model must declare in config.json id2label:
FORENTISAI_ID2LABEL = {0: "benign", 1: "malicious"}

# Required artifact files besides the manifest:
_REQUIRED_FILES: tuple[str, ...] = (
    "config.json",
    "model.safetensors",
    "tokenizer.json",
    "tokenizer_config.json",
)

DEFAULT_CLASS_LABELS: tuple[str, ...] = ("benign", "suspicious")


class NLPModelLoadError(Exception):
    """Raised when the NLP artifact cannot be loaded or is not fine-tuned."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class NLPModelBundle:
    """A loaded fine-tuned tokenizer+model pair plus its metadata.

    ``class_labels`` is the backend-facing label tuple aligned with the raw
    model class indices: index 0 -> "benign", index 1 -> "suspicious" (the
    model's own index-1 label is "malicious"; the mapping to "suspicious" is
    applied so no raw "malicious" verdict can leak into the backend schema).
    """

    tokenizer: object
    model: object
    model_name: str
    class_labels: tuple[str, ...]
    max_length_tokens: int


def _read_json(model_path: Path, filename: str) -> dict | None:
    """Read a JSON file from the artifact directory; None if absent/malformed."""

    json_path = model_path / filename
    if not json_path.is_file():
        return None
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - malformed JSON is a load failure
        return None
    return data if isinstance(data, dict) else None


def _read_manifest(model_path: Path) -> dict | None:
    """Read the ForentisAI manifest (forentisai_model.json), if present."""

    return _read_json(model_path, FORENTISAI_MANIFEST_FILENAME)


def _read_id2label(model_path: Path) -> dict[int, str] | None:
    """Read config.json id2label as {class_index: label}."""

    config = _read_json(model_path, "config.json")
    if config is None:
        return None
    id2label = config.get("id2label")
    if not isinstance(id2label, dict) or not id2label:
        return None
    mapping: dict[int, str] = {}
    for key, value in id2label.items():
        try:
            mapping[int(key)] = str(value)
        except (TypeError, ValueError):
            return None
    return mapping


def load_nlp_model(
    model_path: Path,
    *,
    model_name: str = "unknown",
    max_length_tokens: int = 512,
) -> NLPModelBundle:
    """Load the official ForentisAI fine-tuned artifact locally; never downloads.

    Raises :class:`NLPModelLoadError` with one of:

    - ``model_not_found``: directory or a required file is missing, or the
      artifact is unreadable/corrupt at load time;
    - ``model_not_trained``: ``forentisai_model.json`` is absent — a base or
      unmarked model that is NOT a fine-tuned ForentisAI classifier;
    - ``incompatible_model``: manifest rejects the artifact
      (``forentisai_model`` is not ``true``, ``model_type`` is foreign) or
      ``config.json id2label`` does not declare 0→benign, 1→malicious;
    - ``dependency_unavailable``: transformers/torch are missing or broken.

    The returned bundle maps model class 0 -> backend "benign" and model
    class 1 -> backend "suspicious" (the model's raw "malicious" label is
    intentionally renamed; see module docstring).
    """

    model_path = Path(model_path)
    if not model_path.is_dir():
        raise NLPModelLoadError("model_not_found")

    # Required files: config.json, model.safetensors, tokenizer.json,
    # tokenizer_config.json, and the ForentisAI manifest.
    for filename in _REQUIRED_FILES:
        if not (model_path / filename).is_file():
            raise NLPModelLoadError("model_not_found")

    manifest = _read_manifest(model_path)
    if manifest is None:
        # No manifest: this is a base or foreign model. It is NOT a
        # ForentisAI fine-tuned classifier, so we refuse to predict with it.
        raise NLPModelLoadError("model_not_trained")

    if manifest.get(FORENTISAI_MODEL_FLAG) is not True:
        raise NLPModelLoadError("incompatible_model")
    if manifest.get("model_type") != FORENTISAI_MODEL_TYPE:
        raise NLPModelLoadError("incompatible_model")

    id2label = _read_id2label(model_path)
    if id2label is None or id2label != FORENTISAI_ID2LABEL:
        # The raw class contract is mandatory: 0 -> benign, 1 -> malicious.
        raise NLPModelLoadError("incompatible_model")

    try:
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except Exception as error:  # noqa: BLE001 - missing/broken dependency
        raise NLPModelLoadError("dependency_unavailable") from error

    try:
        tokenizer = AutoTokenizer.from_pretrained(
            str(model_path),
            local_files_only=True,
            # The Colab-trained artifact stores "extra_special_tokens" as a
            # JSON LIST in tokenizer_config.json; transformers 4.57.x expects
            # a mapping during slow->fast tokenizer construction and raises
            # AttributeError. The vocab itself is a standard fast Unigram
            # tokenizer.json, so overriding this metadata (locally, without
            # any network access) restores compatibility without touching
            # the trained artifact. See tests/ai/test_nlp_real_artifact.py.
            extra_special_tokens={},
        )
        model = AutoModelForSequenceClassification.from_pretrained(
            str(model_path), local_files_only=True
        )
    except Exception as error:  # noqa: BLE001 - corrupted artifact, missing weights
        raise NLPModelLoadError("model_not_found") from error

    model.eval()  # type: ignore[union-attr]

    # Backend-facing class labels aligned with raw model indices:
    # 0 -> "benign", 1 -> "suspicious" (raw "malicious" is renamed).
    class_labels: tuple[str, ...] = ("benign", "suspicious")

    return NLPModelBundle(
        tokenizer=tokenizer,
        model=model,
        model_name=model_name,
        class_labels=class_labels,
        max_length_tokens=max_length_tokens,
    )


__all__ = [
    "DEFAULT_CLASS_LABELS",
    "FORENTISAI_ID2LABEL",
    "FORENTISAI_MANIFEST_FILENAME",
    "FORENTISAI_MODEL_FLAG",
    "FORENTISAI_MODEL_TYPE",
    "NLPModelBundle",
    "NLPModelLoadError",
    "load_nlp_model",
]
