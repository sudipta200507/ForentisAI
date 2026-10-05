"""NLP inference (Phase E) and explainable indicators (Phase F).

Runs the fine-tuned DeBERTa-v3 classifier locally and derives deterministic
keyword-pattern indicators from the prepared model input text.

CLASS-INDEX MAPPING (documented contract)
========================================
The trained ForentisAI artifact outputs raw Hugging Face classes
(config.json ``id2label``): index 0 = "benign", index 1 = "malicious".
The backend schema deliberately uses "suspicious" instead of the raw model
label "malicious", because a model prediction is MODEL EVIDENCE, not a
final security verdict. The mapping applied here is explicit and
index-based (never keyword-based):

    model probabilities[0] ("benign")    -> backend probabilities["benign"]
    model probabilities[1] ("malicious") -> backend probabilities["suspicious"]

so ``probabilities["suspicious"]`` IS the model's raw malicious-class
probability, renamed for the evidence-only backend schema. The raw label
"malicious" is never exposed as a security verdict by this backend.

The DeBERTa probability IS the classification; the deterministic keyword
lexicons below are supplementary MODEL INDICATORS (surface patterns for
explainability). They never decide the predicted class and do NOT claim to
explain the transformer's internal reasoning.

Terminology contract (Phase F): indicators are "detected signals" /
"model indicators" / "patterns" — NEVER "confirmed phishing" or similar.
Keyword hits are pattern evidence for later phases, not verdicts.

Failures never become benign predictions:
- no fine-tuned artifact → ``unavailable`` with ``model_not_found`` or
  ``model_not_trained``;
- no usable text → ``unavailable`` with ``empty_text``;
- runtime inference failure → ``error``.
"""

from __future__ import annotations

from app.ai.nlp.model import NLPModelBundle, NLPModelLoadError
from app.schemas.ai import ModelIndicator, NLPResult

# Phase F keyword lexicons. Counts and hits are pattern signals only.
_INDICATOR_LEXICONS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "urgency_language",
        "Urgency/pressure pattern detected in the message text (model indicator, not a verdict).",
        ("urgent", "immediately", "act now", "final notice", "asap", "expires today", "last warning", "action required"),
    ),
    (
        "credential_request_pattern",
        "Credential-request pattern detected (password/login/verify signals; model indicator only).",
        ("password", "verify your account", "confirm your identity", "login", "sign in", "credentials", "reset your password"),
    ),
    (
        "payment_request_pattern",
        "Payment/wire-transfer request pattern detected (model indicator only).",
        ("invoice", "payment", "wire transfer", "bank details", "remittance", "amount due", "gift card"),
    ),
    (
        "account_verification_pattern",
        "Account-verification pattern detected (model indicator only).",
        ("verify your account", "account suspended", "account locked", "confirm your identity", "validate your account", "unusual activity"),
    ),
    (
        "threat_pressure_pattern",
        "Threat/pressure language pattern detected (model indicator only).",
        ("legal action", "lawsuit", "account will be closed", "suspended permanently", "report you", "final warning"),
    ),
    (
        "authority_claim_pattern",
        "Authority-claim pattern detected (bank/government/IT-support style claims; model indicator only).",
        ("irs", "hmrc", "bank officer", "security team", "it department", "administrator", "support team"),
    ),
    (
        "beca_request_pattern",
        "Business-email-compromise-style request pattern detected (model indicator only).",
        ("confidential", "this request is confidential", "discreet", "as discussed", "do not forward", "while traveling", "off hours"),
    ),
)

_MAX_NLP_INDICATORS = 10


def _detect_indicators(text: str) -> list[ModelIndicator]:
    """Deterministic keyword-pattern indicators over the prepared text."""

    lowered = text.casefold()
    indicators: list[ModelIndicator] = []
    for name, detail, keywords in _INDICATOR_LEXICONS:
        count = sum(lowered.count(keyword) for keyword in keywords)
        if count > 0:
            indicators.append(
                ModelIndicator(name=name, detail=detail, weight=float(min(count, 10)))
            )
    indicators.sort(key=lambda item: (-item.weight, item.name))
    return indicators[:_MAX_NLP_INDICATORS]


def _map_model_probabilities(model_probabilities) -> tuple[float, float] | None:
    """Map raw model class probabilities to (benign, suspicious).

    Explicit index-based mapping per the documented contract:
    model index 0 = "benign", model index 1 = "malicious" (renamed to the
    backend's evidence-only class "suspicious"). Returns None when the raw
    output does not have exactly two class probabilities.
    """

    if model_probabilities is None:
        return None
    try:
        values = [float(prob) for prob in model_probabilities]
    except (TypeError, ValueError):
        return None
    if len(values) != 2:
        return None
    return values[0], values[1]


def predict_nlp(text: str | None, bundle: NLPModelBundle | None) -> NLPResult:
    """Run NLP inference; total function never raises.

    ``text`` must be the prepared, length-bounded model input (see
    ``app.ai.nlp.tokenizer.prepare_model_text``).
    """

    if bundle is None:
        return NLPResult(
            available=False,
            status="unavailable",
            reason="model_not_found",
            message="No fine-tuned NLP model artifact is configured or loadable.",
        )

    if not text or not text.strip():
        return NLPResult(
            available=False,
            status="unavailable",
            reason="empty_text",
            message="No usable text was extracted from the email for NLP analysis.",
        )

    try:
        import torch

        tokenizer = bundle.tokenizer
        model = bundle.model
        encoded = tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=bundle.max_length_tokens,
        )
        with torch.no_grad():
            logits = model(**encoded).logits
        model_probabilities = torch.softmax(logits, dim=-1)[0].tolist()
    except Exception as error:  # noqa: BLE001 - inference failure is isolated
        return NLPResult(
            available=False,
            status="error",
            reason="invalid_input",
            message=f"NLP model inference failed: {type(error).__name__}",
        )

    # Explicit index-based mapping (see module docstring):
    #   model probabilities[0] ("benign")    -> backend "benign"
    #   model probabilities[1] ("malicious") -> backend "suspicious"
    mapped = _map_model_probabilities(model_probabilities)
    if mapped is None:
        return NLPResult(
            available=False,
            status="error",
            reason="incompatible_model",
            message="NLP model returned an unexpected number of class probabilities.",
        )
    benign, suspicious = mapped
    prob_dict = {"benign": benign, "suspicious": suspicious}

    predicted = "suspicious" if suspicious >= benign else "benign"
    confidence = max(benign, suspicious)

    indicators = _detect_indicators(text)

    return NLPResult(
        available=True,
        status="available",
        model_name=bundle.model_name,
        model_kind="fine_tuned",
        predicted_class=predicted,  # type: ignore[arg-type]
        probabilities=prob_dict,
        confidence=confidence,
        indicators=indicators,
        text_chars=len(text),
        message=None,
    )


def load_error_to_result(error: NLPModelLoadError) -> NLPResult:
    """Convert a model-load failure into a controlled NLP result."""

    mapping = {
        "model_not_found": "model_not_found",
        "model_not_trained": "model_not_trained",
        "incompatible_model": "incompatible_model",
        "dependency_unavailable": "dependency_unavailable",
    }
    reason = mapping.get(error.reason, "model_not_found")
    messages = {
        "model_not_trained": (
            "NLP artifact has no ForentisAI manifest (forentisai_model.json); "
            "it is a base/foreign model, NOT a fine-tuned ForentisAI email "
            "threat classifier, and is refused for prediction."
        ),
        "incompatible_model": (
            "NLP artifact was rejected: it is not the official ForentisAI "
            "deberta_v3_email_threat_classifier or its raw class contract "
            "(0=benign, 1=malicious) does not match."
        ),
    }
    return NLPResult(
        available=False,
        status="unavailable",
        reason=reason,  # type: ignore[arg-type]
        message=messages.get(reason, f"NLP model could not be loaded: {error.reason}"),
    )


__all__ = ["predict_nlp", "load_error_to_result"]
