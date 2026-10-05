"""Phase 16 correlation endpoints over stored analyses.

All correlation operates on the persisted derived record (indicators and
privacy-safe domains). Every response carries an explicit interpretation
caveat: overlap is NOT attacker attribution.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field

from app.api import errors
from app.correlation.campaign_similarity import similarity_between
from app.correlation.graph_builder import build_indicator_graph
from app.correlation.indicator_correlation import (
    INDICATOR_TYPES,
    CorrelationResult,
    find_analyses_by_indicator,
    related_analyses,
)
from app.database.session import session_scope

router = APIRouter(prefix="/correlation", tags=["correlation"])


class SharedIndicator(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    value: str


class CorrelatedAnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    created_at: str
    filename: str
    risk_score: float
    verdict: str
    severity: str
    shared_indicators: list[SharedIndicator] = Field(default_factory=list)
    overlap_score: float = 0.0


class IndicatorCorrelationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator_type: str
    indicator_value: str
    analyses: list[CorrelatedAnalysisModel] = Field(default_factory=list)
    interpretation: str


class RelatedAnalysesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    related: list[CorrelatedAnalysisModel] = Field(default_factory=list)
    interpretation: str = (
        "Shared indicators show that analyses observed the same infrastructure "
        "or sender domain. This is overlap evidence, NOT proof of common "
        "attacker ownership."
    )


class GraphNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str
    type: str | None = None
    value: str | None = None
    analysis_id: str | None = None
    verdict: str | None = None
    risk_score: float | None = None
    filename: str | None = None


class GraphEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    target: str


class GraphResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    interpretation: str


class SimilarityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id_a: str
    analysis_id_b: str
    similarity: float
    shared_indicators: list[str] = Field(default_factory=list)
    indicator_count_a: int
    indicator_count_b: int
    interpretation: str


def _serialize(result: CorrelationResult) -> IndicatorCorrelationResponse:
    return IndicatorCorrelationResponse(
        indicator_type=result.indicator_type,
        indicator_value=result.indicator_value,
        analyses=[
            CorrelatedAnalysisModel(
                analysis_id=item.analysis_id,
                created_at=item.created_at,
                filename=item.filename,
                risk_score=item.risk_score,
                verdict=item.verdict,
                severity=item.severity,
                shared_indicators=[
                    SharedIndicator(**shared) for shared in item.shared_indicators
                ],
                overlap_score=item.overlap_score,
            )
            for item in result.analyses
        ],
        interpretation=result.interpretation,
    )


@router.get(
    "/indicators/{indicator_type}",
    response_model=IndicatorCorrelationResponse,
    name="correlate_indicator",
)
def correlate_indicator(
    indicator_type: str,
    value: str = Query(..., description="Indicator value (URLs correlate by host)."),
    limit: int = Query(50, ge=1, le=200),
) -> IndicatorCorrelationResponse:
    """Analyses that observed one indicator (URLs correlate by host).

    The value is a QUERY parameter so URL values containing '/' are handled
    without path-routing ambiguity.
    """

    if indicator_type.casefold() not in INDICATOR_TYPES:
        raise errors.api_error(
            "invalid_indicator_type",
            detail=f"indicator_type must be one of: {', '.join(sorted(INDICATOR_TYPES))}.",
        )
    with session_scope() as session:
        result = find_analyses_by_indicator(
            session, indicator_type, value, limit=limit
        )
        return _serialize(result)


@router.get(
    "/analyses/{analysis_id}",
    response_model=RelatedAnalysesResponse,
    name="related_analyses",
)
def get_related_analyses(
    analysis_id: str,
    limit: int = Query(25, ge=1, le=100),
) -> RelatedAnalysesResponse:
    """Analyses sharing at least one normalized indicator with the given one."""

    with session_scope() as session:
        related = related_analyses(session, analysis_id, limit=limit)
        return RelatedAnalysesResponse(
            analysis_id=analysis_id,
            related=[
                CorrelatedAnalysisModel(
                    analysis_id=item.analysis_id,
                    created_at=item.created_at,
                    filename=item.filename,
                    risk_score=item.risk_score,
                    verdict=item.verdict,
                    severity=item.severity,
                    shared_indicators=[
                        SharedIndicator(**shared) for shared in item.shared_indicators
                    ],
                    overlap_score=item.overlap_score,
                )
                for item in related
            ],
        )


@router.get("/graph", response_model=GraphResponse, name="correlation_graph")
def correlation_graph(
    max_analyses: int = Query(50, ge=1, le=200),
    max_indicators: int = Query(200, ge=1, le=1000),
) -> GraphResponse:
    """Bipartite analysis↔indicator overlap graph (visual support)."""

    with session_scope() as session:
        graph = build_indicator_graph(
            session, max_analyses=max_analyses, max_indicators=max_indicators
        )
        return GraphResponse(
            nodes=[GraphNode(**node) for node in graph["nodes"]],
            edges=[GraphEdge(**edge) for edge in graph["edges"]],
            interpretation=graph["interpretation"],
        )


@router.get("/similarity", response_model=SimilarityResponse, name="analysis_similarity")
def analysis_similarity(
    analysis_id_a: str = Query(..., description="First stored analysis id."),
    analysis_id_b: str = Query(..., description="Second stored analysis id."),
) -> SimilarityResponse:
    """Observational overlap (Jaccard) between two stored analyses."""

    with session_scope() as session:
        result = similarity_between(session, analysis_id_a, analysis_id_b)
        if result is None:
            raise errors.api_error(
                "not_found", detail="One or both analysis ids are not stored."
            )
        return SimilarityResponse(**result)


__all__ = ["router"]
