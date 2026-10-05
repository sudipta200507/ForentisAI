"""Technical ML inference (Phase D).

Converts a :class:`FeatureVector` into a :class:`TechnicalMLResult` with an
explicit state. Supports both artifact formats:

- format 2 (``TechnicalModelBundle``): legacy 48-feature runtime contract,
  argmax-style decision (``suspicious >= benign``);
- format 3 (``TechnicalModelV3Bundle``): the production V1 artifact — the
  array is built in the artifact's EXACT ordered feature contract (28 names),
  and the artifact's stored ``suspicious_threshold`` (0.33) decides the class.

Failures never become benign predictions:

- missing / incompatible artifact → ``unavailable`` with ``reason``;
- malformed feature vector → ``unavailable`` with ``feature_extraction_failed``;
- unexpected prediction failure → ``error``.
"""

from __future__ import annotations

import numpy as np

from app.ai.technical_ml.model import (
    TechnicalBundle,
    TechnicalModelBundle,
    TechnicalModelLoadError,
    TechnicalModelV3Bundle,
)
from app.schemas.ai import ModelIndicator, TechnicalMLResult
from app.schemas.features import FeatureVector, feature_names

# Human-readable detail for the strongest suspicious-leaning contributions.
# Used only as indicator text; values themselves come from the model.
_TOP_INDICATOR_LIMIT = 5

_RUNTIME_CONTRACT: tuple[str, ...] | None = None


def _runtime_contract() -> tuple[str, ...]:
    global _RUNTIME_CONTRACT
    if _RUNTIME_CONTRACT is None:
        _RUNTIME_CONTRACT = feature_names()
    return _RUNTIME_CONTRACT


def _lookup_feature(vector: FeatureVector, name: str) -> float:
    """Read one dotted feature value from the runtime vector."""

    section_name, field_name = name.split(".", maxsplit=1)
    section = getattr(vector, section_name, None)
    if section is None or not hasattr(section, field_name):
        raise ValueError(f"unknown feature in runtime contract: {name}")
    return float(getattr(section, field_name))


def vector_to_array(
    vector: FeatureVector, feature_names_ordered: tuple[str, ...] | None = None
) -> np.ndarray:
    """Serialize a FeatureVector into the contracted 2-D float array.

    Column order is exactly ``feature_names()`` (the full runtime contract)
    unless an explicit ordered tuple is supplied — the format-3 artifact
    supplies its own 28-name contract, which MUST be preserved deterministically.
    Raises ``ValueError`` on any name outside the runtime contract or any
    value that cannot become a finite float (bools and ints are fine).
    """

    names = (
        tuple(feature_names_ordered)
        if feature_names_ordered is not None
        else _runtime_contract()
    )
    if not names:
        raise ValueError("feature name contract is empty")
    if feature_names_ordered is not None:
        runtime = set(_runtime_contract())
        unknown = [name for name in names if name not in runtime]
        if unknown:
            raise ValueError(f"features outside the runtime contract: {unknown}")

    values: list[float] = []
    for name in names:
        value = _lookup_feature(vector, name)
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError(f"non-finite feature value for {name}")
        values.append(value)

    return np.asarray([values], dtype=np.float64)


def prediction_array(vector: FeatureVector, bundle: TechnicalBundle | None) -> np.ndarray:
    """Feature array in the exact column order the given bundle expects."""

    if isinstance(bundle, TechnicalModelV3Bundle):
        return vector_to_array(vector, bundle.feature_names)
    return vector_to_array(vector)


def _probabilities_dict(
    classes: list[str], probabilities: np.ndarray
) -> dict[str, float]:
    return {str(cls): float(prob) for cls, prob in zip(classes, probabilities)}


def _predict_v3(
    vector: FeatureVector, bundle: TechnicalModelV3Bundle
) -> TechnicalMLResult:
    """Format-3 inference: artifact contract + stored threshold decision."""

    try:
        array = vector_to_array(vector, bundle.feature_names)
    except Exception as error:  # noqa: BLE001 - malformed input is isolated
        return TechnicalMLResult(
            available=False,
            status="unavailable",
            reason="feature_extraction_failed",
            message=f"Feature vector could not be serialized: {error}",
        )

    try:
        probabilities = bundle.model.predict_proba(array)[0]
        # class_labels are positionally aligned with the estimator's classes_
        # probability columns (verified 0→benign / 1→suspicious mapping for
        # the integer-labelled V1 artifact; string artifacts pass through).
        classes = list(bundle.class_labels)
    except Exception as error:  # noqa: BLE001 - prediction failure is isolated
        return TechnicalMLResult(
            available=False,
            status="error",
            reason="incompatible_model",
            message=f"Technical model prediction failed: {error}",
        )

    prob_dict = _probabilities_dict(classes, np.asarray(probabilities, dtype=float))
    suspicious = prob_dict.get("suspicious")
    benign = prob_dict.get("benign")

    if suspicious is None:
        return TechnicalMLResult(
            available=False,
            status="error",
            reason="incompatible_model",
            message="Technical model classes do not include 'suspicious'.",
        )

    # Documented V1 decision rule: the artifact's stored threshold decides.
    threshold = bundle.threshold
    predicted = "suspicious" if suspicious >= threshold else "benign"
    # Confidence = probability of the predicted class (explainable within the
    # threshold band, where it is deliberately NOT max(p_benign, p_suspicious)).
    confidence = suspicious if predicted == "suspicious" else (benign or 1.0 - suspicious)

    indicators = _top_indicators(vector, suspicious)
    indicators.append(
        ModelIndicator(
            name="technical_threshold_decision",
            detail=(
                f"Suspicious probability {suspicious:.3f} compared against the "
                f"artifact threshold {threshold:.2f} → '{predicted}'."
            ),
            weight=round(suspicious, 4),
        )
    )

    message = (
        f"Production V1 artifact ({bundle.dataset_name}, contract "
        f"{bundle.feature_contract_version}): {len(bundle.feature_names)} model "
        f"features, threshold {threshold:.2f}."
    )
    if bundle.compatibility_note:
        message += (
            " Note: the artifact was pickled with a different scikit-learn "
            "version than the runtime; the estimator passed the loader's "
            "functional smoke test."
        )

    return TechnicalMLResult(
        available=True,
        status="available",
        model_name=f"{V3_MODEL_NAME_PREFIX}-{bundle.artifact_format_version}",
        predicted_class=predicted,  # type: ignore[arg-type]
        probabilities=prob_dict,
        confidence=confidence,
        indicators=indicators[:_TOP_INDICATOR_LIMIT],
        threshold=threshold,
        artifact_format_version=bundle.artifact_format_version,
        feature_contract_version=bundle.feature_contract_version,
        dataset_name=bundle.dataset_name,
        model_feature_count=len(bundle.feature_names),
        message=message,
    )


V3_MODEL_NAME_PREFIX = "forentisai-technical-rf"


def predict_technical(
    vector: FeatureVector,
    bundle: TechnicalBundle | None,
) -> TechnicalMLResult:
    """Run technical-ML inference; total function never raises."""

    if bundle is None:
        return TechnicalMLResult(
            available=False,
            status="unavailable",
            reason="model_not_found",
            message="No technical model artifact was provided (or it failed to load).",
        )

    if isinstance(bundle, TechnicalModelV3Bundle):
        return _predict_v3(vector, bundle)

    try:
        array = vector_to_array(vector)
    except Exception as error:  # noqa: BLE001 - malformed input is isolated
        return TechnicalMLResult(
            available=False,
            status="unavailable",
            reason="feature_extraction_failed",
            message=f"Feature vector could not be serialized: {error}",
        )

    try:
        probabilities = bundle.pipeline.predict_proba(array)[0]
        classes = [str(cls) for cls in bundle.pipeline.classes_]
    except Exception as error:  # noqa: BLE001 - prediction failure is isolated
        return TechnicalMLResult(
            available=False,
            status="error",
            reason="incompatible_model",
            message=f"Technical model prediction failed: {error}",
        )

    prob_dict = _probabilities_dict(classes, np.asarray(probabilities, dtype=float))
    suspicious = prob_dict.get("suspicious")
    benign = prob_dict.get("benign")

    if suspicious is None:
        predicted = "unknown"
        confidence = None
    else:
        predicted = "suspicious" if (benign is None or suspicious >= benign) else "benign"
        confidence = max(prob_dict.values()) if prob_dict else None

    return TechnicalMLResult(
        available=True,
        status="available",
        model_name=bundle.metadata.model_name,
        predicted_class=predicted,  # type: ignore[arg-type]
        probabilities=prob_dict,
        confidence=confidence,
        indicators=_top_indicators(vector, prob_dict.get("suspicious", 0.0)),
        message=None,
    )


def _top_indicators(
    vector: FeatureVector, suspicious_probability: float
) -> list[ModelIndicator]:
    """Deterministic model-signal list for the technical result.

    Signals are described as model evidence only — never "confirmed"-
    style language. The base rate note is included when the model itself
    leans suspicious so consumers do not over-read a single probability.
    """

    indicators: list[ModelIndicator] = []

    if suspicious_probability >= 0.5:
        indicators.append(
            ModelIndicator(
                name="technical_model_suspicious_lean",
                detail=(
                    "Technical model probability mass leans toward the "
                    f"suspicious class ({suspicious_probability:.2f}); this is a "
                    "model signal only."
                ),
                weight=round(suspicious_probability, 4),
            )
        )
    else:
        indicators.append(
            ModelIndicator(
                name="technical_model_benign_lean",
                detail=(
                    "Technical model probability mass leans toward the benign "
                    f"class ({1.0 - suspicious_probability:.2f}); this is a model "
                    "signal, not a safety guarantee."
                ),
                weight=round(1.0 - suspicious_probability, 4),
            )
        )

    return indicators[:_TOP_INDICATOR_LIMIT]


__all__ = [
    "load_error_to_result",
    "predict_technical",
    "prediction_array",
    "vector_to_array",
]


# Exported for orchestrator convenience: converts a load error to a result.
def load_error_to_result(error: TechnicalModelLoadError) -> TechnicalMLResult:
    """Convert a model-load failure into a controlled unavailable result."""

    mapping = {
        "model_not_found": "model_not_found",
        "malformed_model": "incompatible_model",
        "incompatible_model": "incompatible_model",
    }
    reason = mapping.get(error.reason, "model_not_found")
    return TechnicalMLResult(
        available=False,
        status="unavailable",
        reason=reason,  # type: ignore[arg-type]
        message=f"Technical model could not be loaded: {error.reason}",
    )
