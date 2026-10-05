"""AI orchestrator (Phase I).

Single entry point that turns Steps 1–4 evidence into an
:class:`AIAnalysis`:

    EmailEvidence + AuthenticationEvidence + IntelligenceEvidence
        → feature extraction (Phase C)
        → technical ML + DeBERTa NLP (Phases D/E, in parallel conceptually)
        → fusion (Phase G)
        → explainability (Phase H)
        → AIAnalysis

Guarantees:
- never re-parses the original email and never duplicates Steps 1/2/4;
- never fetches URLs or performs any network request (models load locally);
- isolates model failures: any component failure becomes an explicit
  ``unavailable``/``error`` state, never a benign prediction;
- deterministic schema and deterministic given deterministic components;
- never produces ``risk_score``, threat verdicts, or severity values.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError

from app.ai.explainability.reasons import build_textual_reasons
from app.ai.explainability.shap_explainer import explain_technical_prediction
from app.ai.explainability.structured import build_structured_explanations
from app.ai.fusion.classifier import fuse
from app.ai.model_registry import get_nlp_bundle, get_technical_bundle
from app.ai.nlp.inference import load_error_to_result as nlp_load_error_to_result
from app.ai.nlp.inference import predict_nlp
from app.ai.nlp.model import NLPModelLoadError
from app.ai.nlp.tokenizer import prepare_model_text
from app.ai.technical_ml.inference import (
    load_error_to_result as technical_load_error_to_result,
)
from app.ai.technical_ml.inference import (
    predict_technical,
    prediction_array,
)
from app.features.feature_fusion import build_feature_vector
from app.schemas.ai import (
    AIAnalysis,
    Explainability,
    NLPResult,
    TechnicalMLResult,
    UnavailabilityReason,
)
from app.schemas.authentication import AuthenticationEvidence
from app.schemas.email import EmailEvidence
from app.schemas.intelligence import IntelligenceEvidence


def _run_with_timeout(function, timeout_seconds: float):
    """Run ``function()`` in a worker thread; return its result or None on timeout.

    A timed-out worker thread cannot be killed, but the caller stops waiting
    and the analysis degrades to an explicit ``inference_timeout`` state.
    The worker thread is daemonized so it never blocks process shutdown.
    """

    result: dict = {"value": None}

    def _target() -> None:
        result["value"] = function()

    if timeout_seconds <= 0:
        return function()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="forentisai-ai") as pool:
        future = pool.submit(_target)
        try:
            future.result(timeout=timeout_seconds)
        except TimeoutError:
            return None
        except Exception:  # noqa: BLE001 - predict functions are total; defensive only
            return None
    return result["value"]


def _unavailable_all(reason: UnavailabilityReason, message: str) -> AIAnalysis:
    nlp = NLPResult(available=False, status="unavailable", reason=reason, message=message)
    technical = TechnicalMLResult(
        available=False, status="unavailable", reason=reason, message=message
    )
    from app.schemas.ai import FusionResult

    fusion = FusionResult(
        available=False,
        status="unavailable",
        reason=reason,
        signals=[],
        message=message,
    )
    return AIAnalysis(
        status="unavailable",
        nlp=nlp,
        technical_ml=technical,
        fusion=fusion,
        explainability=Explainability(reason=reason),
    )


def build_ai_analysis(
    evidence: EmailEvidence,
    authentication: AuthenticationEvidence | None = None,
    intelligence: IntelligenceEvidence | None = None,
    *,
    settings,
) -> AIAnalysis:
    """Run the full AI pipeline; total function never raises.

    ``settings`` is an ``app.core.config.AISettings`` instance. The evidence
    objects must come from Steps 1/2/4; they are consumed read-only.
    """

    if not settings.ai_enabled:
        return _unavailable_all(
            "not_enabled", "AI analysis is disabled via AI_ENABLED=false."
        )

    if not isinstance(evidence, EmailEvidence):
        return _unavailable_all(
            "invalid_input", "EmailEvidence object missing or malformed."
        )

    # ------------------------------------------------------------------
    # Phase C: deterministic features (already exception-isolated inside).
    # ------------------------------------------------------------------
    url_intelligence = list(intelligence.urls) if intelligence is not None else None
    try:
        vector = build_feature_vector(
            evidence,
            authentication,
            intelligence,
            url_intelligence=url_intelligence,
        )
    except Exception:  # noqa: BLE001 - feature failure must not kill analysis
        return _unavailable_all(
            "feature_extraction_failed",
            "Feature extraction failed unexpectedly.",
        )

    # ------------------------------------------------------------------
    # Phase D: technical model (cached load; failure → controlled state).
    # ------------------------------------------------------------------
    technical_bundle, technical_error = get_technical_bundle(settings.technical_model_path)
    if technical_bundle is None:
        technical_load = TechnicalMLResult(
            available=False,
            status="unavailable",
            reason="model_not_found" if technical_error == "model_not_found" else "incompatible_model",
            message=f"Technical model not usable ({technical_error}).",
        )
        technical_result = technical_load
    else:
        technical_result = _run_with_timeout(
            lambda: predict_technical(vector, technical_bundle),
            settings.inference_timeout_seconds,
        )
        if technical_result is None:
            technical_result = TechnicalMLResult(
                available=False,
                status="error",
                reason="inference_timeout",
                message="Technical model inference exceeded the configured timeout.",
            )

    # ------------------------------------------------------------------
    # Phase E/F: NLP model (cached load; fine-tuned artifacts only).
    # ------------------------------------------------------------------
    if settings.nlp_model_path is None:
        nlp_result = NLPResult(
            available=False,
            status="unavailable",
            reason="model_not_found",
            message="No NLP model path is configured (NLP_MODEL_PATH unset).",
        )
        nlp_bundle = None
    else:
        nlp_bundle, nlp_error = get_nlp_bundle(
            settings.nlp_model_path,
            model_name=settings.nlp_model_name,
        )
        if nlp_bundle is None:
            nlp_result = nlp_load_error_to_result(
                NLPModelLoadError(nlp_error or "model_not_found")
            )
        else:
            text = prepare_model_text(evidence, settings.max_text_length)
            nlp_result = _run_with_timeout(
                lambda: predict_nlp(text, nlp_bundle),
                settings.inference_timeout_seconds,
            )
            if nlp_result is None:
                nlp_result = NLPResult(
                    available=False,
                    status="error",
                    reason="inference_timeout",
                    message="NLP inference exceeded the configured timeout.",
                )

    # ------------------------------------------------------------------
    # Phase G: fusion.
    # ------------------------------------------------------------------
    fusion = fuse(nlp_result, technical_result)

    # ------------------------------------------------------------------
    # Phase H: explainability (SHAP for the technical model only).
    # ------------------------------------------------------------------
    feature_contributions = []
    shap_available = False
    explanation_reason = None
    if technical_bundle is not None and technical_result.available:
        try:
            # The array must be in the bundle's OWN contract order (the v3
            # production artifact uses its 28-feature order, not the 48).
            array = prediction_array(vector, technical_bundle)
            explanation = explain_technical_prediction(technical_bundle, array)
            feature_contributions = explanation.contributions
            shap_available = explanation.shap_available
            explanation_reason = explanation.reason
        except Exception:  # noqa: BLE001 - explanation must never break analysis
            explanation_reason = "explanation_failed"

    explainability = Explainability(
        feature_contributions=feature_contributions,
        textual_reasons=build_textual_reasons(nlp_result, technical_result, fusion),
        explanations=build_structured_explanations(
            evidence,
            authentication,
            intelligence,
            nlp_result,
            technical_result,
            fusion,
        ),
        shap_available=shap_available,
        reason=explanation_reason,
    )

    overall_status = "available" if fusion.available else "unavailable"

    return AIAnalysis(
        status=overall_status,  # type: ignore[arg-type]
        nlp=nlp_result,
        technical_ml=technical_result,
        fusion=fusion,
        explainability=explainability,
    )


__all__ = ["build_ai_analysis"]
