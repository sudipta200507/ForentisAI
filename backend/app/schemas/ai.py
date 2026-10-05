"""Pydantic models for the Step 5 AI/ML threat-analysis evidence.

IMPORTANT — these models represent MODEL EVIDENCE, never a security decision:

- No ``risk_score``, no final threat verdict, no severity value, and no
  forensic report exists anywhere in this schema. Those belong to later
  project phases.
- A prediction of a suspicious class is a model signal only. It is never
  reported as "confirmed phishing" or "malicious".
- Every component carries an explicit state: ``available`` / ``unavailable``
  / ``error``. A model failure is NEVER silently converted into a benign
  prediction.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Vocabularies. "unknown" means the model produced no usable class.
# ---------------------------------------------------------------------------

AIStatus = Literal["available", "unavailable", "error"]

AIClass = Literal["suspicious", "benign", "unknown"]

UnavailabilityReason = Literal[
    "not_enabled",
    "model_not_found",
    "model_not_trained",
    "incompatible_model",
    "dependency_unavailable",
    "empty_text",
    "unsupported_model",
    "explanation_failed",
    "feature_extraction_failed",
    "invalid_input",
    "inference_timeout",
]

# ---------------------------------------------------------------------------
# Shared building blocks.
# ---------------------------------------------------------------------------


class EvidenceModel(BaseModel):
    """Base model that keeps the exported evidence shape predictable."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class ModelIndicator(EvidenceModel):
    """One explainable model signal.

    This is a detected pattern or feature signal, NOT a confirmed attack.
    ``name`` is a stable identifier; ``detail`` is a short human-readable
    description of the signal. Indicators never contain raw email body text.
    """

    name: str = Field(min_length=1)
    detail: str = Field(min_length=1)
    weight: float = Field(default=1.0)


class FeatureContribution(EvidenceModel):
    """One classical-ML feature contribution from SHAP (or fallback).

    ``direction`` is relative to the model's suspicious class: ``toward``
    pushed the prediction toward suspicious, ``away`` away from it. This is
    model attribution only, not a statement about the email itself.
    """

    feature: str = Field(min_length=1)
    value: float
    contribution: float
    direction: Literal["toward", "away"]


# ---------------------------------------------------------------------------
# Component results.
# ---------------------------------------------------------------------------


class NLPResult(EvidenceModel):
    """DeBERTa-v3 NLP component result (model evidence only)."""

    available: bool = False
    status: AIStatus = "unavailable"
    reason: UnavailabilityReason | None = None
    model_name: str | None = None
    model_kind: Literal["fine_tuned", "base", None] = None
    predicted_class: AIClass = "unknown"
    probabilities: dict[str, float] = Field(default_factory=dict)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    indicators: list[ModelIndicator] = Field(default_factory=list)
    text_chars: int | None = Field(default=None, ge=0)
    message: str | None = None


class TechnicalMLResult(EvidenceModel):
    """Classical scikit-learn component result (model evidence only).

    The v3 provenance fields are populated only by the production V1
    (format-3) artifact; the legacy fixture bundle leaves them ``None``.
    ``threshold`` is the artifact's stored suspicious-class decision
    threshold and is the value actually applied at inference.
    """

    available: bool = False
    status: AIStatus = "unavailable"
    reason: UnavailabilityReason | None = None
    model_name: str | None = None
    predicted_class: AIClass = "unknown"
    probabilities: dict[str, float] = Field(default_factory=dict)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    indicators: list[ModelIndicator] = Field(default_factory=list)
    message: str | None = None
    # Format-3 (production V1) artifact provenance:
    threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    artifact_format_version: int | None = None
    feature_contract_version: str | None = None
    dataset_name: str | None = None
    model_feature_count: int | None = Field(default=None, ge=1)


class StructuredExplanation(EvidenceModel):
    """One structured, human-readable explanation entry.

    Explanations are EVIDENCE/REASON statements produced by deterministic
    rules (keyword patterns, header/URL checks, authentication outcomes) or
    by model outputs restated in plain language. They are NOT exact
    transformer token attributions and never claim certainty about intent.

    ``category`` is a stable identifier (e.g. ``credential_harvesting``);
    ``impact`` is a coarse qualitative weight (low/medium/high); ``evidence``
    is a short factual anchor (indicator values, counts) with no raw email
    body text.
    """

    reason: str = Field(min_length=1)
    category: str = Field(min_length=1)
    impact: Literal["low", "medium", "high"] = "low"
    evidence: str = Field(min_length=1)


class FusionSignal(EvidenceModel):
    """One component contribution inside the fusion result."""

    source: Literal["nlp", "technical_ml"]
    available: bool
    weight: float = Field(ge=0.0)
    suspicious_probability: float | None = Field(default=None, ge=0.0, le=1.0)
    contributed: bool


class FusionResult(EvidenceModel):
    """Deterministic fusion of the NLP and technical-ML probabilities.

    ``probability_suspicious`` is the weighted mean of the available
    components' suspicious-class probabilities (weights renormalized when a
    component is missing). It is a MODEL EVIDENCE value, not a project risk
    score, and ``predicted_class`` is a thresholded model output, not a
    security verdict.
    """

    available: bool = False
    status: AIStatus = "unavailable"
    reason: UnavailabilityReason | None = None
    predicted_class: AIClass = "unknown"
    probability_suspicious: float | None = Field(default=None, ge=0.0, le=1.0)
    probabilities: dict[str, float] = Field(default_factory=dict)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    signals: list[FusionSignal] = Field(default_factory=list)
    # Explicit degraded-operation reporting (never hidden):
    # "full" = both models contributed; "nlp_only" / "technical_only" = one
    # model contributed (weights renormalized); "none" = no model evidence.
    mode: Literal["full", "nlp_only", "technical_only", "none"] = "none"
    model_status: dict[str, str] = Field(default_factory=dict)
    message: str | None = None


class Explainability(EvidenceModel):
    """Combined explainability output for one analysis.

    ``feature_contributions`` come from SHAP (or the linear fallback) on the
    classical model only. ``textual_reasons`` are human-readable model
    signals — they are explicitly NOT explanations of transformer internals.
    ``explanations`` are structured evidence-based entries (category + impact
    + factual evidence) built by deterministic rules and model-output restatements.
    """

    feature_contributions: list[FeatureContribution] = Field(default_factory=list)
    textual_reasons: list[str] = Field(default_factory=list)
    explanations: list[StructuredExplanation] = Field(default_factory=list)
    shap_available: bool = False
    reason: UnavailabilityReason | None = None


# ---------------------------------------------------------------------------
# Top-level AI analysis.
# ---------------------------------------------------------------------------


class AIAnalysis(EvidenceModel):
    """Step 5 output: combined AI model evidence for one email.

    This object is an input for later risk-scoring and reporting phases. It
    never claims an email is definitively malicious or safe: even a benign
    prediction from both models must not be read as "safe", and a suspicious
    prediction must not be read as "confirmed phishing".
    """

    schema_version: Literal["1.0"] = "1.0"
    status: AIStatus = "unavailable"
    nlp: NLPResult = Field(default_factory=NLPResult)
    technical_ml: TechnicalMLResult = Field(default_factory=TechnicalMLResult)
    fusion: FusionResult = Field(default_factory=FusionResult)
    explainability: Explainability = Field(default_factory=Explainability)
