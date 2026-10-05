"""Pydantic models for the combined API responses (Steps 1-5 + Phase 3/5)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.ai import AIAnalysis
from app.schemas.authentication import AuthenticationEvidence
from app.schemas.email import EmailEvidence
from app.schemas.forensics import ForensicEvidence
from app.schemas.intelligence import IntelligenceEvidence
from app.schemas.risk import RiskAssessment


class AnalysisMetadata(BaseModel):
    """Run metadata for one analysis (Phase 5).

    ``timestamp`` is the UTC completion time and ``processing_time_ms`` the
    measured wall-clock duration of the whole pipeline. No email content is
    included.
    """

    model_config = ConfigDict(extra="forbid")

    timestamp: str = Field(min_length=1)
    processing_time_ms: float = Field(ge=0.0)
    engine_version: str = Field(min_length=1)
    model_versions: dict[str, str | None] = Field(default_factory=dict)


class AnalysisResponse(BaseModel):
    """Combined product response (Steps 1-5 + risk + forensics).

    ``email``, ``authentication``, and ``intelligence`` reuse the existing
    evidence schemas verbatim; ``ai`` carries Step 5 MODEL EVIDENCE only —
    model probabilities and explanations, never a verdict. The Phase 3 risk
    engine output lives in ``risk`` (deterministic, documented composite),
    forensic transport-path evidence in ``forensics``, and run facts in
    ``metadata``. AI model failures never abort the request: they degrade to
    explicit ``unavailable``/``error`` states inside ``ai``.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: str = "1.0"
    analysis_id: str = Field(min_length=1)
    email: EmailEvidence
    authentication: AuthenticationEvidence
    intelligence: IntelligenceEvidence = Field(default_factory=IntelligenceEvidence)
    ai: AIAnalysis = Field(default_factory=AIAnalysis)
    risk: RiskAssessment = Field(default_factory=RiskAssessment)
    forensics: ForensicEvidence = Field(default_factory=ForensicEvidence)
    metadata: AnalysisMetadata | None = None


class HealthResponse(BaseModel):
    """Liveness response for the API process itself."""

    model_config = ConfigDict(extra="forbid")

    status: str = "ok"
    service: str = "forentisai-api"


class RspamdHealthResponse(BaseModel):
    """Rspamd dependency availability, clearly separate from API liveness."""

    model_config = ConfigDict(extra="forbid")

    rspamd_available: bool
    detail: str | None = Field(default=None)
