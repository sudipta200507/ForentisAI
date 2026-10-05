"""Model fusion (Phase G).

Combines the NLP and technical-ML probability outputs into one
:class:`FusionResult` using a documented, deterministic formula:

    p_fused(suspicious) = Σ_i w_i · p_i(suspicious) / Σ_i w_i

where the sum runs over the AVAILABLE components only (weights are
renormalized when a component is missing), and ``w_nlp``/``w_technical``
default to 0.5 each (equal trust; no component is privileged).

Decision rule: ``predicted_class = suspicious`` iff ``p_fused >= 0.5``.
This is a threshold between MODEL CLASSES for downstream consumption —
it is NOT a security verdict and NOT the project risk score. A fused
result is deliberately never hard-coded to "malicious"; when the two
components disagree, the result is a probability near the boundary with
low confidence and an explicit disagreement note.

Availability matrix (required behavior):
- both available        → weighted mean of both suspicious probabilities;
- NLP unavailable       → technical evidence only (weight renormalized);
- technical unavailable → NLP evidence only (weight renormalized);
- both unavailable      → fusion ``unavailable`` (never a benign guess).
"""

from __future__ import annotations

from app.schemas.ai import FusionResult, FusionSignal, NLPResult, TechnicalMLResult

_DEFAULT_NLP_WEIGHT = 0.5
_DEFAULT_TECHNICAL_WEIGHT = 0.5

_DISAGREEMENT_THRESHOLD = 0.5


def _suspicious_probability(probabilities: dict[str, float]) -> float | None:
    """Suspicious-class probability from a component's probability dict."""

    value = probabilities.get("suspicious")
    if value is None:
        return None
    return max(0.0, min(1.0, float(value)))


def _model_status(nlp: NLPResult, technical: TechnicalMLResult) -> dict[str, str]:
    """Explicit availability map so degraded operation is never hidden."""

    return {
        "nlp": "available" if (nlp.available and nlp.status == "available") else "unavailable",
        "technical_ml": "available"
        if (technical.available and technical.status == "available")
        else "unavailable",
    }


def _mode(nlp_p: float | None, tech_p: float | None) -> str:
    if nlp_p is not None and tech_p is not None:
        return "full"
    if nlp_p is not None:
        return "nlp_only"
    if tech_p is not None:
        return "technical_only"
    return "none"


def fuse(
    nlp: NLPResult,
    technical: TechnicalMLResult,
    *,
    nlp_weight: float = _DEFAULT_NLP_WEIGHT,
    technical_weight: float = _DEFAULT_TECHNICAL_WEIGHT,
) -> FusionResult:
    """Fuse component results deterministically; total function never raises.

    Availability handling (never hidden, never manufactured):
    - both available → weighted mean (mode "full");
    - one available → renormalized weights (mode "nlp_only"/"technical_only");
    - neither available → fusion stays ``unavailable`` with mode "none" and
      NO probability is produced. Downstream rule/evidence assessment (the
      risk engine) is responsible for any low-confidence verdict in that case.
    """

    nlp_p = _suspicious_probability(nlp.probabilities) if nlp.available else None
    tech_p = (
        _suspicious_probability(technical.probabilities) if technical.available else None
    )

    signals: list[FusionSignal] = []
    status = _model_status(nlp, technical)
    mode = _mode(nlp_p, tech_p)

    nlp_effective = nlp_weight if nlp_p is not None else 0.0
    tech_effective = technical_weight if tech_p is not None else 0.0

    signals.append(
        FusionSignal(
            source="nlp",
            available=nlp.available and nlp_p is not None,
            weight=round(nlp_effective, 6),
            suspicious_probability=None if nlp_p is None else round(nlp_p, 6),
            contributed=nlp_p is not None,
        )
    )
    signals.append(
        FusionSignal(
            source="technical_ml",
            available=technical.available and tech_p is not None,
            weight=round(tech_effective, 6),
            suspicious_probability=None if tech_p is None else round(tech_p, 6),
            contributed=tech_p is not None,
        )
    )

    if nlp_p is None and tech_p is None:
        # Both components unusable: fusion is unavailable, never benign.
        reason = technical.reason or nlp.reason or "model_not_found"
        return FusionResult(
            available=False,
            status="unavailable",
            reason=reason,  # type: ignore[arg-type]
            signals=signals,
            mode=mode,  # "none"
            model_status=status,
            message=(
                "Fusion unavailable: neither the NLP nor the technical model "
                "produced usable evidence. This is not a benign prediction; "
                "downstream assessment may proceed on non-model evidence only, "
                "with reduced confidence."
            ),
        )

    total_weight = nlp_effective + tech_effective
    if total_weight <= 0:
        return FusionResult(
            available=False,
            status="unavailable",
            reason="invalid_input",
            signals=signals,
            mode=mode,
            model_status=status,
            message="Fusion weights sum to zero; no combination possible.",
        )

    fused = (
        (nlp_effective * (nlp_p or 0.0)) + (tech_effective * (tech_p or 0.0))
    ) / total_weight
    fused = max(0.0, min(1.0, fused))

    predicted = "suspicious" if fused >= 0.5 else "benign"
    confidence = max(fused, 1.0 - fused)

    messages: list[str] = []
    if nlp_p is not None and tech_p is not None:
        if abs(nlp_p - tech_p) >= _DISAGREEMENT_THRESHOLD:
            messages.append(
                "Components disagree: NLP and technical suspicious "
                "probabilities differ by more than 0.5; the fused value "
                "reflects the models' combined evidence only."
            )
    elif nlp_p is not None:
        messages.append(
            "Only the NLP component contributed: the technical-ML model was "
            "unavailable and its weight was renormalized."
        )
    else:
        messages.append(
            "Only the technical-ML component contributed: the NLP model was "
            "unavailable and its weight was renormalized."
        )

    return FusionResult(
        available=True,
        status="available",
        predicted_class=predicted,  # type: ignore[arg-type]
        probability_suspicious=round(fused, 6),
        probabilities={
            "suspicious": round(fused, 6),
            "benign": round(1.0 - fused, 6),
        },
        confidence=round(confidence, 6),
        signals=signals,
        mode=mode,  # type: ignore[arg-type]
        model_status=status,
        message=" ".join(messages) or None,
    )


__all__ = ["fuse"]
