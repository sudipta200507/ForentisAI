"""Phase 15 stored-analysis endpoints: dashboard list + detail.

Read-only views over the Phase 6 persisted DERIVED record. The database
never stores raw email content, so these endpoints expose exactly what was
persisted (privacy-safe metadata, indicators, risk assessment, evidence)
and never reconstruct the original email.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field

from app.api import errors
from app.database.models import Analysis
from app.database.repositories import get_analysis_by_id

router = APIRouter(prefix="/analyses", tags=["analyses"])


class StoredAnalysisSummary(BaseModel):
    """One row for the dashboard's recent-analyses list."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    created_at: str
    filename: str
    risk_score: float
    verdict: str
    severity: str
    confidence: float
    primary_threat_type: str | None = None
    auth_available: bool
    sender_domain: str | None = None
    reply_to_domain: str | None = None
    url_count: int = 0
    attachment_count: int = 0
    received_hop_count: int = 0
    model_status: dict[str, str] = Field(default_factory=dict)


class StoredIndicator(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    value: str
    source_kind: str = ""
    source_location: str = ""


class StoredEvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    category: str
    name: str
    detail: str
    payload: dict = Field(default_factory=dict)


class StoredThreatAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_score: float
    verdict: str
    severity: str
    confidence: float
    primary_threat_type: str | None = None
    threat_types: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    contributing_signals: list[dict] = Field(default_factory=list)
    model_contributions: list[dict] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    thresholds: dict = Field(default_factory=dict)


class StoredAnalysisDetail(BaseModel):
    """The full persisted derived record for one analysis."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    created_at: str
    engine_version: str
    email_sha256: str
    email_size: int
    filename: str
    processing_time_ms: float
    auth_available: bool
    model_status: dict[str, str] = Field(default_factory=dict)
    subject_length: int = 0
    sender_domain: str | None = None
    reply_to_domain: str | None = None
    return_path_domain: str | None = None
    message_id_domain: str | None = None
    date_missing: bool = False
    url_count: int = 0
    attachment_count: int = 0
    parser_defect_count: int = 0
    indicators: list[StoredIndicator] = Field(default_factory=list)
    evidence: list[StoredEvidenceItem] = Field(default_factory=list)
    threat_assessment: StoredThreatAssessment | None = None


def _summary_from(row: Analysis) -> StoredAnalysisSummary:
    metadata = row.email_metadata
    return StoredAnalysisSummary(
        analysis_id=row.analysis_id,
        created_at=row.created_at.isoformat() if row.created_at else "",
        filename=row.filename,
        risk_score=row.risk_score,
        verdict=row.verdict,
        severity=row.severity,
        confidence=row.confidence,
        primary_threat_type=row.primary_threat_type,
        auth_available=row.auth_available,
        sender_domain=metadata.sender_domain if metadata else None,
        reply_to_domain=metadata.reply_to_domain if metadata else None,
        url_count=metadata.url_count if metadata else 0,
        attachment_count=metadata.attachment_count if metadata else 0,
        received_hop_count=metadata.received_hop_count if metadata else 0,
        model_status={str(k): str(v) for k, v in (row.model_status or {}).items()},
    )


@router.get("", response_model=list[StoredAnalysisSummary], name="list_analyses")
def list_analyses(
    limit: int = Query(50, ge=1, le=200, description="Maximum rows to return."),
) -> list[StoredAnalysisSummary]:
    """Most recent stored analyses (derived data only)."""

    from app.database.session import create_all
    from app.database.repositories import recent_analyses

    create_all()  # idempotent; keeps first-run behavior working
    rows = recent_analyses(limit=limit)
    return [_summary_from(row) for row in rows]


@router.get("/{analysis_id}", response_model=StoredAnalysisDetail, name="get_analysis")
def get_analysis(analysis_id: str) -> StoredAnalysisDetail:
    """One stored analysis (the persisted derived record, never raw email)."""

    from app.database.session import create_all

    create_all()
    row = get_analysis_by_id(analysis_id)
    if row is None:
        raise errors.api_error("not_found", detail="No stored analysis with that id.")

    metadata = row.email_metadata
    assessment = row.threat_assessments[0] if row.threat_assessments else None

    return StoredAnalysisDetail(
        analysis_id=row.analysis_id,
        created_at=row.created_at.isoformat() if row.created_at else "",
        engine_version=row.engine_version,
        email_sha256=row.email_sha256,
        email_size=row.email_size,
        filename=row.filename,
        processing_time_ms=row.processing_time_ms,
        auth_available=row.auth_available,
        model_status={str(k): str(v) for k, v in (row.model_status or {}).items()},
        subject_length=metadata.subject_length if metadata else 0,
        sender_domain=metadata.sender_domain if metadata else None,
        reply_to_domain=metadata.reply_to_domain if metadata else None,
        return_path_domain=metadata.return_path_domain if metadata else None,
        message_id_domain=metadata.message_id_domain if metadata else None,
        date_missing=metadata.date_missing if metadata else False,
        url_count=metadata.url_count if metadata else 0,
        attachment_count=metadata.attachment_count if metadata else 0,
        parser_defect_count=metadata.parser_defect_count if metadata else 0,
        indicators=[
            StoredIndicator(
                type=indicator.type,
                value=indicator.value,
                source_kind=indicator.source_kind,
                source_location=indicator.source_location,
            )
            for indicator in row.indicators
        ],
        evidence=[
            StoredEvidenceItem(
                kind=item.kind,
                category=item.category,
                name=item.name,
                detail=item.detail,
                payload=dict(item.payload or {}),
            )
            for item in row.evidence
        ],
        threat_assessment=(
            StoredThreatAssessment(
                risk_score=assessment.risk_score,
                verdict=assessment.verdict,
                severity=assessment.severity,
                confidence=assessment.confidence,
                primary_threat_type=assessment.primary_threat_type,
                threat_types=list(assessment.threat_types or []),
                reasons=list(assessment.reasons or []),
                contributing_signals=list(assessment.contributing_signals or []),
                model_contributions=list(assessment.model_contributions or []),
                limitations=list(assessment.limitations or []),
                thresholds=dict(assessment.thresholds or {}),
            )
            if assessment
            else None
        ),
    )


__all__ = ["router"]
