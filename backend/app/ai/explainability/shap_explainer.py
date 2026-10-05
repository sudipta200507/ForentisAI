"""Explainability for the TECHNICAL model (Phase H).

SHAP is applied only where it is technically appropriate: the classical
tree-ensemble model (``TreeExplainer``). For a linear model a documented
coefficient-based fallback is used instead. For the transformer NLP model,
SHAP is deliberately NOT used: token attribution would require a separate
validated implementation, and pretending SHAP applies there would produce
fabricated explanations.

Both artifact formats are supported:

- format 2 (``TechnicalModelBundle``): classifier at
  ``bundle.pipeline.named_steps["classifier"]``; contributions use the full
  runtime 48-feature contract;
- format 3 (``TechnicalModelV3Bundle``): the production V1 artifact — the
  estimator is ``bundle.model`` and contributions use the artifact's exact
  28-name contract.

Failure behavior is total: any unsupported model, missing SHAP install, or
explainer error yields an explicit unavailable state with a reason — never
fabricated contributions and never an exception crossing the API boundary.

The output distinguishes MODEL PREDICTION (the probabilities already in
``TechnicalMLResult``) from SUPPORTING SIGNALS (the contributions here).
A contribution is attribution relative to the suspicious class: positive
pushed toward suspicious, negative away from it. It is not a statement
that the email is malicious or safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

from app.ai.technical_ml.model import TechnicalModelBundle, TechnicalModelV3Bundle
from app.schemas.ai import FeatureContribution
from app.schemas.features import feature_names

_MAX_CONTRIBUTIONS = 10


@dataclass(frozen=True, slots=True)
class TechnicalExplanation:
    """Result of explaining one technical-model prediction."""

    contributions: list[FeatureContribution] = field(default_factory=list)
    shap_available: bool = False
    reason: str | None = None
    message: str | None = None


def _classifier_of(bundle: Any) -> Any:
    """Extract the fitted classifier from either bundle format."""

    if isinstance(bundle, TechnicalModelV3Bundle):
        return bundle.model
    if isinstance(bundle, TechnicalModelBundle):
        return bundle.pipeline.named_steps.get("classifier")
    return None


def _classes_of(bundle: Any) -> list[str]:
    """Backend-facing class labels aligned with probability columns.

    The v3 bundle carries canonical labels (its estimator may store integer
    classes); the v2 pipeline exposes string classes directly.
    """

    if isinstance(bundle, TechnicalModelV3Bundle):
        return list(bundle.class_labels)
    classifier = _classifier_of(bundle)
    if classifier is None:
        return []
    return [str(cls) for cls in getattr(classifier, "classes_", [])]


def _feature_names_of(bundle: Any) -> tuple[str, ...]:
    """Feature-name contract matching the array fed to this bundle."""

    if isinstance(bundle, TechnicalModelV3Bundle):
        return bundle.feature_names
    return feature_names()


def _suspicious_index(bundle: Any) -> int | None:
    classes = _classes_of(bundle)
    try:
        return classes.index("suspicious")
    except ValueError:
        return None


def _explain_tree(
    bundle: Any, array: np.ndarray, class_index: int, names: tuple[str, ...]
) -> list[FeatureContribution]:
    import shap

    classifier = _classifier_of(bundle)
    if classifier is None:
        raise TypeError("bundle has no fitted classifier")
    explainer = shap.TreeExplainer(classifier)
    shap_values = explainer.shap_values(array)

    if isinstance(shap_values, list):
        values = np.asarray(shap_values[class_index])[0]
    else:
        array_values = np.asarray(shap_values)
        if array_values.ndim == 3:  # (n_samples, n_features, n_classes)
            values = array_values[0, :, class_index]
        elif array_values.ndim == 2:  # (n_samples, n_features)
            values = array_values[0]
        else:
            raise TypeError(f"unexpected shap_values shape {array_values.shape}")

    return _to_contributions(values, array[0], names)


def _explain_linear(bundle: Any, array: np.ndarray, names: tuple[str, ...]) -> list[FeatureContribution]:
    """Documented fallback for linear models: coefficient × feature value.

    This is a standard linear-model attribution approximation, clearly not
    SHAP; ``shap_available`` stays False for this path.
    """

    classifier = _classifier_of(bundle)
    classes = _classes_of(bundle)
    coefficients = np.asarray(classifier.coef_)
    if coefficients.ndim == 2:
        # Binary sklearn linear models expose a single row for classes_[1]
        # (the positive class); multi-class exposes one row per class.
        if coefficients.shape[0] == 1:
            coefficients = coefficients[0]
        else:
            class_index = classes.index("suspicious") if "suspicious" in classes else -1
            coefficients = coefficients[class_index]
    return _to_contributions(coefficients * array[0], array[0], names)


def _to_contributions(
    values: np.ndarray, feature_values: np.ndarray, names: tuple[str, ...]
) -> list[FeatureContribution]:
    contributions: list[FeatureContribution] = []
    for index, raw_value in enumerate(np.asarray(values).ravel()):
        if index >= len(names):
            break
        contribution = float(raw_value)
        if not np.isfinite(contribution):
            continue
        contributions.append(
            FeatureContribution(
                feature=names[index],
                value=float(feature_values[index]),
                contribution=round(contribution, 6),
                direction="toward" if contribution >= 0 else "away",
            )
        )
    contributions.sort(key=lambda item: (-abs(item.contribution), item.feature))
    return contributions[:_MAX_CONTRIBUTIONS]


def explain_technical_prediction(bundle: Any, array: np.ndarray) -> TechnicalExplanation:
    """Explain one technical prediction; total function never raises.

    ``array`` must be the 2-D feature array in this bundle's own contract
    order (``app.ai.technical_ml.inference.prediction_array``).
    """

    try:
        class_index = _suspicious_index(bundle)
        if class_index is None:
            return TechnicalExplanation(
                reason="unsupported_model",
                message="Model classes do not include 'suspicious'; nothing to attribute.",
            )

        classifier = _classifier_of(bundle)
        classifier_class_name = type(classifier).__name__
        names = _feature_names_of(bundle)

        if "Forest" in classifier_class_name or "Boosting" in classifier_class_name:
            contributions = _explain_tree(bundle, array, class_index, names)
            return TechnicalExplanation(
                contributions=contributions,
                shap_available=True,
                message="TreeExplainer SHAP values relative to the suspicious class.",
            )

        if "LogisticRegression" in classifier_class_name:
            contributions = _explain_linear(bundle, array, names)
            return TechnicalExplanation(
                contributions=contributions,
                shap_available=False,
                reason="unsupported_model",
                message=(
                    "Linear fallback attribution (coefficient × value) used; "
                    "SHAP TreeExplainer does not apply to this model type."
                ),
            )

        return TechnicalExplanation(
            reason="unsupported_model",
            message=f"Model type {classifier_class_name} has no validated explainer.",
        )
    except ImportError:
        return TechnicalExplanation(
            reason="dependency_unavailable",
            message="SHAP is not installed; technical explanations are unavailable.",
        )
    except Exception as error:  # noqa: BLE001 - any explainer failure is isolated
        return TechnicalExplanation(
            reason="explanation_failed",
            message=f"SHAP explanation failed: {type(error).__name__}",
        )


__all__ = ["TechnicalExplanation", "explain_technical_prediction"]
