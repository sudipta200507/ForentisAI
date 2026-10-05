"""Campaign similarity V1 (Phase 16).

Jaccard similarity between two STORED analyses over their normalized
indicator sets (IPs, domains, URL hosts) plus the privacy-safe sender /
Reply-To / Message-ID domains.

INTERPRETATION BOUNDARY: the score expresses OBSERVATIONAL OVERLAP between
two analyses. It is NOT proof that the same attacker sent both emails.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.correlation.indicator_correlation import (
    normalize_domain,
    normalize_indicator_value,
)
from app.database.models import Analysis


def jaccard_similarity(set_a: set[str], set_b: set[str]) -> float:
    """Jaccard index of two sets (0.0 for two empty sets)."""
    if not set_a and not set_b:
        return 0.0
    union = set_a | set_b
    if not union:
        return 0.0
    return len(set_a & set_b) / len(union)


def analysis_indicator_set(analysis: Analysis) -> set[str]:
    """Normalized comparison set for one analysis (indicators + domains)."""
    values: set[str] = set()
    for indicator in analysis.indicators:
        normalized = normalize_indicator_value(indicator.type, indicator.value)
        if normalized:
            values.add(f"{indicator.type}:{normalized}")
    metadata = analysis.email_metadata
    if metadata is not None:
        for domain in (
            metadata.sender_domain,
            metadata.reply_to_domain,
            metadata.message_id_domain,
        ):
            normalized = normalize_domain(domain)
            if normalized:
                values.add(f"domain:{normalized}")
    return values


def similarity_between(
    session: Session,
    analysis_id_a: str,
    analysis_id_b: str,
) -> dict | None:
    """Similarity report for two stored analyses, or None if either is missing."""

    row_a = session.execute(
        select(Analysis).where(Analysis.analysis_id == analysis_id_a)
    ).scalar_one_or_none()
    row_b = session.execute(
        select(Analysis).where(Analysis.analysis_id == analysis_id_b)
    ).scalar_one_or_none()
    if row_a is None or row_b is None:
        return None

    set_a = analysis_indicator_set(row_a)
    set_b = analysis_indicator_set(row_b)
    shared = set_a & set_b

    return {
        "analysis_id_a": analysis_id_a,
        "analysis_id_b": analysis_id_b,
        "similarity": round(jaccard_similarity(set_a, set_b), 4),
        "shared_indicators": sorted(shared),
        "indicator_count_a": len(set_a),
        "indicator_count_b": len(set_b),
        "interpretation": _INTERPRETATION,
    }


_INTERPRETATION = (
    "The similarity score is observational overlap between the two analyses' "
    "indicators (Jaccard index). It is NOT evidence that one attacker sent "
    "both emails; shared providers and CDNs can produce overlap."
)


__all__ = ["analysis_indicator_set", "jaccard_similarity", "similarity_between"]
