"""Technical ML model artifacts (Phase D).

Two artifact formats are supported, explicitly:

Format 2 (legacy ``TechnicalModelBundle``)
==========================================
A joblib-pickled :class:`TechnicalModelBundle` dataclass wrapping a fitted
sklearn ``Pipeline`` plus :class:`ModelMetadata` that records the exact
runtime feature contract it was trained on. Used by the in-repo fixture and
training pipeline (``ai/training/train_technical_model.py``).

Format 3 (production dict artifact, V1 Colab training pipeline)
===============================================================
A plain Python ``dict`` with:

- ``artifact_format_version`` = 3
- ``model``                   fitted ``RandomForestClassifier`` (``predict_proba``)
- ``feature_names``           the EXACT ordered model-input features (28 for the
                              V1 dataset ``technical-30-eml-v1``; the two constant
                              Received-IP features were excluded at training time)
- ``suspicious_threshold``    decision threshold for the suspicious class (0.33)
- ``dataset_name`` / ``feature_contract_version`` / ``model_parameters`` /
  ``test_metrics`` / ``excluded_constant_features`` provenance

The V1 production artifact (``ai/models/technical_model.joblib``) uses format
3. Loading validates the structure and functionally smoke-tests the
estimator; an invalid artifact is a controlled ``incompatible_model`` /
``malformed_model`` state at inference time, never a wrong prediction.

sklearn version compatibility
=============================
The V1 artifact was pickled with scikit-learn 1.6.1. The loader does NOT
blindly suppress sklearn's ``InconsistentVersionWarning``: the warning is
captured, recorded verbatim into the bundle's ``compatibility_note``, and the
estimator must then pass a deterministic zero-vector ``predict_proba`` smoke
test before it is accepted. A compatibility matrix is documented in
``docs/model_compatibility.md``.

Architecture choice — ``RandomForestClassifier``:
- scale-invariant for mixed binary/count/ratio features;
- captures non-linear interactions (e.g. ``spf_fail`` AND
  ``credential_signal_count``);
- feature importances and TreeExplainer SHAP provide honest explanations.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Union

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

from app.schemas.features import feature_names

# Legacy bundle format (fixture + in-repo training pipeline).
ARTIFACT_FORMAT_VERSION = 2
# Production dict format (V1 external training pipeline).
V3_ARTIFACT_FORMAT_VERSION = 3
V3_MODEL_TYPE = "RandomForestClassifier"
V3_DATASET_NAME = "ForentisAI_TechnicalML_Dataset_V1"
V3_FEATURE_CONTRACT_VERSION = "technical-30-eml-v1"

# Fallback decision threshold when an artifact does not carry one.
DEFAULT_SUSPICIOUS_THRESHOLD = 0.5


class TechnicalModelLoadError(Exception):
    """Raised when a model artifact cannot be loaded or is incompatible."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ModelMetadata:
    """Provenance of a trained technical model (honesty fields included)."""

    model_name: str
    class_labels: tuple[str, ...]
    feature_names: tuple[str, ...]
    trained_at: str
    dataset_description: str
    training_notes: str
    artifact_format_version: int = ARTIFACT_FORMAT_VERSION


@dataclass(frozen=True, slots=True)
class TechnicalModelBundle:
    """A trained pipeline plus the metadata needed to use it safely (format 2)."""

    pipeline: Pipeline
    metadata: ModelMetadata
    extra: dict = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TechnicalModelV3Bundle:
    """Normalised view of a format-3 production dict artifact.

    ``feature_names`` is the exact, ordered model-input contract (28 names for
    the V1 dataset). ``threshold`` is the artifact's stored suspicious-class
    decision threshold (0.33 for V1) and is always applied at inference.
    ``compatibility_note`` carries any captured sklearn version warning text.
    """

    model: Any
    # Canonical backend-facing class labels, aligned positionally with the
    # estimator's ``classes_`` probability columns.
    class_labels: tuple[str, ...]
    threshold: float
    feature_names: tuple[str, ...]
    excluded_constant_features: tuple[str, ...]
    artifact_format_version: int
    dataset_name: str
    feature_contract_version: str
    model_parameters: dict[str, Any]
    test_metrics: dict[str, Any]
    created_at: str | None
    compatibility_note: str | None


# Any artifact bundle accepted by the inference layer.
TechnicalBundle = Union[TechnicalModelBundle, TechnicalModelV3Bundle]


def build_pipeline(n_estimators: int = 200, random_state: int = 42) -> Pipeline:
    """Build the (unfitted) sklearn pipeline used for training and export.

    ``random_state`` is fixed so that training and inference behavior are
    deterministic for identical inputs and artifacts.
    """

    return Pipeline(
        steps=[
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=n_estimators,
                    random_state=random_state,
                    n_jobs=1,  # deterministic ordering of tree building
                ),
            )
        ]
    )


def save_technical_model(bundle: TechnicalModelBundle, path: Path) -> None:
    """Persist a format-2 bundle with joblib, creating parent directories."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)


# ---------------------------------------------------------------------------
# Format-2 validation (legacy bundle)
# ---------------------------------------------------------------------------


def _validate_v2_bundle(bundle: TechnicalModelBundle) -> None:
    if bundle.metadata.artifact_format_version != ARTIFACT_FORMAT_VERSION:
        raise TechnicalModelLoadError("incompatible_model")

    current_names = feature_names()
    if tuple(bundle.metadata.feature_names) != current_names:
        raise TechnicalModelLoadError("incompatible_model")

    if not hasattr(bundle.pipeline, "predict_proba"):
        raise TechnicalModelLoadError("incompatible_model")


# ---------------------------------------------------------------------------
# Format-3 validation (production dict artifact)
# ---------------------------------------------------------------------------


def _v3_feature_names(raw_names: Any) -> tuple[str, ...]:
    """Validate and normalise the artifact's ordered feature-name list."""

    if not isinstance(raw_names, (list, tuple)) or not raw_names:
        raise TechnicalModelLoadError("malformed_model")
    names: list[str] = []
    seen: set[str] = set()
    for value in raw_names:
        if not isinstance(value, str) or not value.strip():
            raise TechnicalModelLoadError("malformed_model")
        name = value.strip()
        if name in seen:
            raise TechnicalModelLoadError("malformed_model")
        seen.add(name)
        names.append(name)

    runtime_contract = set(feature_names())
    unknown = [name for name in names if name not in runtime_contract]
    if unknown:
        # The runtime cannot compute features the artifact was trained on.
        raise TechnicalModelLoadError("incompatible_model")
    return tuple(names)


def _v3_threshold(raw_threshold: Any) -> float:
    if raw_threshold is None:
        return DEFAULT_SUSPICIOUS_THRESHOLD
    if isinstance(raw_threshold, bool) or not isinstance(raw_threshold, (int, float)):
        raise TechnicalModelLoadError("malformed_model")
    threshold = float(raw_threshold)
    if threshold != threshold or threshold in (float("inf"), float("-inf")):
        raise TechnicalModelLoadError("malformed_model")
    if not 0.0 <= threshold <= 1.0:
        raise TechnicalModelLoadError("malformed_model")
    return threshold


def _normalize_v3_classes(model: Any) -> tuple[str, ...]:
    """Map the estimator's ``classes_`` to backend class labels.

    The production V1 artifact stores integer classes ``[0, 1]``. The mapping
    0 → "benign", 1 → "suspicious" is verified from the artifact itself: its
    test confusion matrix [[882, 29], [10, 692]] has 911 benign samples in
    row 0 (``classes_[0]``) and 702 suspicious samples in row 1, matching the
    project-wide class contract (0 = benign, 1 = malicious/suspicious; see
    ``app.ai.nlp.model.FORENTISAI_ID2LABEL`` and docs/training_report.json).
    String-labelled artifacts ("benign"/"suspicious") are accepted as-is.
    Any other class set is incompatible.
    """

    classes = getattr(model, "classes_", None)
    if classes is None or len(classes) != 2:
        raise TechnicalModelLoadError("incompatible_model")
    raw = [cls for cls in classes]
    if all(isinstance(cls, str) for cls in raw):
        labels = tuple(str(cls) for cls in raw)
        if set(labels) == {"benign", "suspicious"}:
            return labels
        raise TechnicalModelLoadError("incompatible_model")
    try:
        numeric = [int(cls) for cls in raw]
    except (TypeError, ValueError):
        raise TechnicalModelLoadError("incompatible_model") from None
    if sorted(numeric) == [0, 1]:
        # Verified V1 mapping: class 0 = benign, class 1 = suspicious.
        return ("benign", "suspicious") if numeric == [0, 1] else ("suspicious", "benign")
    raise TechnicalModelLoadError("incompatible_model")


def _v3_smoke_test(
    model: Any, feature_names_ordered: tuple[str, ...]
) -> tuple[str, ...]:
    """Functionally validate the estimator after unpickling.

    This is the deliberate answer to sklearn's InconsistentVersionWarning:
    instead of trusting (or silently suppressing) the warning, the loader
    requires the unpickled estimator to actually run on a deterministic
    zero vector and return a finite probability row whose column count matches
    ``classes_``. Returns the normalized backend class labels. Any failure is
    a controlled incompatible_model state.
    """

    class_labels = _normalize_v3_classes(model)
    try:
        import numpy as np

        zeros = np.zeros((1, len(feature_names_ordered)), dtype=np.float64)
        probabilities = np.asarray(model.predict_proba(zeros), dtype=float)
    except Exception as error:  # noqa: BLE001 - broken estimator = incompatible
        raise TechnicalModelLoadError("incompatible_model") from error
    if probabilities.shape != (1, 2) or not np.isfinite(probabilities).all():
        raise TechnicalModelLoadError("incompatible_model")
    return class_labels


def _captured_version_warning(caught: list[warnings.WarningMessage]) -> str | None:
    """Extract verbatim sklearn version-mismatch warning text, if any."""

    notes: list[str] = []
    for message in caught:
        name = type(message.message).__name__
        if name == "InconsistentVersionWarning":
            notes.append(str(message.message))
    if not notes:
        return None
    return " | ".join(notes)


def _load_v3_dict(artifact: dict, compatibility_note: str | None) -> TechnicalModelV3Bundle:
    """Validate a format-3 production dict artifact; raise on any deviation."""

    version = artifact.get("artifact_format_version")
    if version != V3_ARTIFACT_FORMAT_VERSION:
        raise TechnicalModelLoadError("incompatible_model")

    model_type = artifact.get("model_type")
    if model_type != V3_MODEL_TYPE:
        raise TechnicalModelLoadError("incompatible_model")

    model = artifact.get("model")
    if model is None or not hasattr(model, "predict_proba"):
        raise TechnicalModelLoadError("incompatible_model")

    names = _v3_feature_names(artifact.get("feature_names"))
    threshold = _v3_threshold(artifact.get("suspicious_threshold"))

    # Excluded features, when recorded, must not appear in the model inputs.
    excluded_raw = artifact.get("excluded_constant_features") or []
    if not isinstance(excluded_raw, (list, tuple)):
        raise TechnicalModelLoadError("malformed_model")
    excluded = tuple(str(value) for value in excluded_raw if isinstance(value, str))
    if set(excluded) & set(names):
        raise TechnicalModelLoadError("incompatible_model")

    class_labels = _v3_smoke_test(model, names)

    dataset_name = artifact.get("dataset_name")
    if not isinstance(dataset_name, str) or not dataset_name.strip():
        raise TechnicalModelLoadError("malformed_model")
    contract_version = artifact.get("feature_contract_version")
    if not isinstance(contract_version, str) or not contract_version.strip():
        raise TechnicalModelLoadError("malformed_model")

    model_parameters = artifact.get("model_parameters")
    test_metrics = artifact.get("test_metrics")
    created_at = artifact.get("created_at")
    return TechnicalModelV3Bundle(
        model=model,
        class_labels=class_labels,
        threshold=threshold,
        feature_names=names,
        excluded_constant_features=excluded,
        artifact_format_version=int(version),
        dataset_name=dataset_name,
        feature_contract_version=contract_version,
        model_parameters=model_parameters if isinstance(model_parameters, dict) else {},
        test_metrics=test_metrics if isinstance(test_metrics, dict) else {},
        created_at=str(created_at) if created_at is not None else None,
        compatibility_note=compatibility_note,
    )


def load_technical_model(path: Path) -> TechnicalBundle:
    """Load and validate either supported artifact format.

    Raises :class:`TechnicalModelLoadError` (never arbitrary exceptions) when
    the file is missing, unreadable, malformed, or incompatible. The caller
    maps every failure to a controlled ``unavailable`` inference state.
    """

    path = Path(path)
    if not path.is_file():
        raise TechnicalModelLoadError("model_not_found")
    try:
        # Capture (never suppress) sklearn version warnings during unpickling.
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            raw = joblib.load(path)
    except Exception as error:  # noqa: BLE001 - any unpickling failure is a load failure
        raise TechnicalModelLoadError("malformed_model") from error

    if isinstance(raw, TechnicalModelBundle):
        _validate_v2_bundle(raw)
        return raw
    if isinstance(raw, dict):
        return _load_v3_dict(raw, _captured_version_warning(caught))
    raise TechnicalModelLoadError("incompatible_model")


__all__ = [
    "ARTIFACT_FORMAT_VERSION",
    "DEFAULT_SUSPICIOUS_THRESHOLD",
    "TechnicalBundle",
    "TechnicalModelBundle",
    "TechnicalModelLoadError",
    "TechnicalModelV3Bundle",
    "V3_ARTIFACT_FORMAT_VERSION",
    "build_pipeline",
    "load_technical_model",
    "save_technical_model",
]
