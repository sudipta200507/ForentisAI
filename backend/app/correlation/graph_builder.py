"""Indicator↔analysis graph builder V1 (Phase 16).

Builds a JSON-serializable bipartite graph over STORED analyses and their
normalized indicators. Used by the dashboard for a visual overlap view.

INTERPRETATION BOUNDARY: edges mean "this analysis observed this indicator";
they never encode attacker identity or campaign membership by themselves.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.correlation.indicator_correlation import normalize_indicator_value
from app.database.models import Analysis, Indicator


def build_indicator_graph(
    session: Session,
    *,
    max_analyses: int = 50,
    max_indicators: int = 200,
) -> dict:
    """Bipartite graph {nodes, edges} over recent analyses and indicators.

    Nodes carry a ``kind`` ("analysis" or "indicator"); edges connect an
    analysis node to an indicator node it observed. Indicator values are
    normalized (urls collapse to their host) so shared infrastructure merges.
    """

    analyses = session.execute(
        select(Analysis)
        .order_by(Analysis.created_at.desc())
        .limit(max_analyses)
    ).scalars().all()
    if not analyses:
        return {"nodes": [], "edges": [], "interpretation": _INTERPRETATION}

    analysis_by_internal_id = {analysis.id: analysis for analysis in analyses}

    indicator_rows = session.execute(
        select(Indicator)
        .where(Indicator.analysis_id.in_(list(analysis_by_internal_id.keys())))
        .limit(5000)
    ).scalars().all()

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    indicator_count = 0

    for indicator in indicator_rows:
        normalized = normalize_indicator_value(indicator.type, indicator.value)
        if not normalized:
            continue
        node_key = f"{indicator.type}:{normalized}"
        if node_key not in nodes:
            if indicator_count >= max_indicators:
                continue
            indicator_count += 1
            nodes[node_key] = {
                "id": node_key,
                "kind": "indicator",
                "type": indicator.type,
                "value": normalized,
            }
        analysis = analysis_by_internal_id.get(indicator.analysis_id)
        if analysis is None:
            continue
        analysis_key = f"analysis:{analysis.analysis_id}"
        if analysis_key not in nodes:
            nodes[analysis_key] = {
                "id": analysis_key,
                "kind": "analysis",
                "analysis_id": analysis.analysis_id,
                "verdict": analysis.verdict,
                "risk_score": analysis.risk_score,
                "filename": analysis.filename,
            }
        edges.append({"source": analysis_key, "target": node_key})

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "interpretation": _INTERPRETATION,
    }


_INTERPRETATION = (
    "Edges mean 'this analysis observed this indicator'. Shared nodes show "
    "overlap between analyses, NOT common attacker ownership."
)


__all__ = ["build_indicator_graph"]
