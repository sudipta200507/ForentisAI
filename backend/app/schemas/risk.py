"""Pydantic models for the Phase 3 risk-engine output.

IMPORTANT — separation of concepts:

- ``risk_score`` (0–100) is the DETERMINISTIC risk-engine composite over all
  available evidence. It is never a model probability restated on a different
  scale, and never an Rspamd score.
- ``verdict`` (benign/suspicious/malicious/inconclusive) is a policy threshold
  over the risk score with an explicit ``inconclusive`` path when evidence is
  insufficient. It is not a model class and not a legal determination.
- ``confidence`` expresses how much CORROBORATING evidence existed (models,
  authentication, intelligence). Missing critical evidence LOWERS it; it is
  never inflated by a single loud signal.
- Threat types are DETERMINISTIC CATEGORIES of observed evidence (e.g.
  ``sender_impersonation``); they never claim attacker attribution.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RiskVerdict = Literal["benign", "suspicious", "malicious", "inconclusive"]

RiskSeverity = Literal["info", "low", "medium", "high", "critical"]

ThreatType = Literal[
    "credential_harvesting",
    "payment_fraud",
    "urgency_pressure",
    "sender_impersonation",
    "authentication_failure",
    "suspicious_links",
    "young_infrastructure",
    "model_flagged",
]


class ModelContribution(BaseModel):
    """One AI component's input to the risk score.

    ``points`` is the exact number of risk-score points the component added
    (0.0 when unavailable). ``suspicious_probability`` is the raw model value
    used; it is reported SEPARATELY from the composite risk score on purpose.
    """

    model_config = ConfigDict(extra="forbid")

    component: Literal["nlp", "technical_ml", "fusion"]
    available: bool
    suspicious_probability: float | None = Field(default=None, ge=0.0, le=1.0)
    points: float = Field(ge=0.0)
    note: str | None = None


class ContributingSignal(BaseModel):
    """One named, weighted signal behind the risk score.

    ``source`` identifies the evidence layer (``model``, ``authentication``,
    ``header``, ``url``, ``intelligence``, ``text``); ``detail`` is a short
    factual anchor with no raw email body text.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    category: ThreatType
    source: Literal[
        "model", "authentication", "header", "url", "intelligence", "text"
    ]
    points: float = Field(ge=0.0)
    detail: str = Field(min_length=1)


class RiskAssessment(BaseModel):
    """Deterministic Phase 3 risk assessment for one email.

    The score is the capped sum of documented signal weights (see
    ``app.ai.risk.scorer`` for the full table). It is fully deterministic:
    identical inputs always produce an identical assessment.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: Literal["1.0"] = "1.0"
    risk_score: float = Field(ge=0.0, le=100.0)
    verdict: RiskVerdict
    severity: RiskSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    primary_threat_type: ThreatType | None = None
    threat_types: list[ThreatType] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    contributing_signals: list[ContributingSignal] = Field(default_factory=list)
    model_contributions: list[ModelContribution] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    thresholds: dict[str, float] = Field(default_factory=dict)


__all__ = [
    "ContributingSignal",
    "ModelContribution",
    "RiskAssessment",
    "RiskSeverity",
    "RiskVerdict",
    "ThreatType",
]
