"""Indicator correlation V1 (Phase 16).

Correlates STORED analyses through shared normalized indicators:
IPs, domains, URL hosts, sender/Reply-To/Message-ID domains.

INTERPRETATION BOUNDARY (important):
A shared indicator means the analyses OBSERVE THE SAME INFRASTRUCTURE or
the same sender domain. It does NOT prove common attacker ownership: shared
CDNs, shared mail providers, reused throwaway domains, or a recipient being
in both threads can produce overlap. Every result therefore carries an
explicit interpretation caveat, and scores are described as "overlap"
(similarity), never as attribution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Analysis, EmailMetadata, Indicator

INDICATOR_TYPES = frozenset({"ipv4", "ipv6", "domain", "hostname", "url"})


@dataclass
class CorrelatedAnalysis:
    """One analysis that shares indicators with the query."""

    analysis_id: str
    created_at: str
    filename: str
    risk_score: float
    verdict: str
    severity: str
    shared_indicators: list[dict] = field(default_factory=list)
    overlap_score: float = 0.0  # |shared| / |indicators of this analysis|, 0..1


@dataclass
class CorrelationResult:
    """Result of an indicator→analyses lookup."""

    indicator_type: str
    indicator_value: str
    analyses: list[CorrelatedAnalysis] = field(default_factory=list)
    interpretation: str = (
        "Shared indicators show that analyses observed the same infrastructure "
        "or sender domain. This is overlap evidence, NOT proof of common "
        "attacker ownership."
    )


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize_domain(value: str | None) -> str | None:
    """Lower-case, strip trailing dot and surrounding punctuation."""
    if not value:
        return None
    domain = value.strip().strip(".").strip("<>").strip("\"'").casefold()
    if not domain or "." not in domain and domain != "localhost":
        return None
    return domain


def url_host(url: str | None) -> str | None:
    """Extract the lower-case host from a URL string (no network access)."""
    if not url:
        return None
    candidate = url.strip()
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    return normalize_domain(parsed.hostname)


def normalize_indicator_value(indicator_type: str, value: str) -> str | None:
    """Normalized matching form for a stored indicator value."""
    kind = (indicator_type or "").casefold()
    if kind in ("ipv4", "ipv6"):
        return value.strip().casefold() or None
    if kind in ("domain", "hostname"):
        return normalize_domain(value)
    if kind == "url":
        return url_host(value)
    return None


# ---------------------------------------------------------------------------
# Correlation queries (stored data only)
# ---------------------------------------------------------------------------

def _analysis_summary(row: Analysis) -> dict:
    return {
        "analysis_id": row.analysis_id,
        "created_at": row.created_at.isoformat() if row.created_at else "",
        "filename": row.filename,
        "risk_score": row.risk_score,
        "verdict": row.verdict,
        "severity": row.severity,
    }


def find_analyses_by_indicator(
    session: Session,
    indicator_type: str,
    value: str,
    *,
    limit: int = 50,
) -> CorrelationResult:
    """All stored analyses containing a normalized indicator value.

    For url indicators the match is by URL HOST (shared full URL strings are
    too brittle for correlation).
    """
    kind = (indicator_type or "").casefold()
    if kind not in INDICATOR_TYPES:
        raise ValueError(f"Unsupported indicator type: {indicator_type!r}")

    normalized = normalize_indicator_value(kind, value)
    if not normalized:
        return CorrelationResult(indicator_type=kind, indicator_value=value)

    rows = session.execute(
        select(Indicator)
        .where(Indicator.type == kind)
        .order_by(Indicator.created_at.desc())
        .limit(2000)
    ).scalars().all()

    matches: dict[str, Analysis] = {}
    for indicator in rows:
        if normalize_indicator_value(indicator.type, indicator.value) != normalized:
            continue
        analysis = indicator.analysis
        if analysis is not None:
            matches[analysis.analysis_id] = analysis

    result = CorrelationResult(indicator_type=kind, indicator_value=normalized)
    for analysis in list(matches.values())[:limit]:
        result.analyses.append(
            CorrelatedAnalysis(
                analysis_id=analysis.analysis_id,
                created_at=analysis.created_at.isoformat() if analysis.created_at else "",
                filename=analysis.filename,
                risk_score=analysis.risk_score,
                verdict=analysis.verdict,
                severity=analysis.severity,
                shared_indicators=[{"type": kind, "value": normalized}],
            )
        )
    return result


def related_analyses(
    session: Session,
    analysis_id: str,
    *,
    limit: int = 25,
) -> list[CorrelatedAnalysis]:
    """Analyses that share at least one normalized indicator with the given one.

    Shared sender/Reply-To/Message-ID domains are also correlated (from the
    privacy-safe stored domain fields, never raw addresses).
    """
    origin = session.execute(
        select(Analysis).where(Analysis.analysis_id == analysis_id)
    ).scalar_one_or_none()
    if origin is None:
        return []

    # The origin's normalized indicator set.
    origin_indicators: dict[str, str] = {}
    for indicator in origin.indicators:
        normalized = normalize_indicator_value(indicator.type, indicator.value)
        if normalized:
            origin_indicators[f"{indicator.type}:{normalized}"] = normalized

    origin_metadata = origin.email_metadata
    origin_domains: set[str] = set()
    if origin_metadata is not None:
        for domain in (
            origin_metadata.sender_domain,
            origin_metadata.reply_to_domain,
            origin_metadata.message_id_domain,
        ):
            normalized = normalize_domain(domain)
            if normalized:
                origin_domains.add(normalized)

    # Candidate analyses: any that share an indicator row value.
    candidates: dict[str, Analysis] = {}
    shared_by_analysis: dict[str, set[str]] = {}

    if origin_indicators:
        rows = session.execute(
            select(Indicator).where(
                Indicator.analysis_id != origin.id,
                Indicator.type.in_({key.split(":", 1)[0] for key in origin_indicators}),
            )
        ).scalars().all()
        for indicator in rows:
            normalized = normalize_indicator_value(indicator.type, indicator.value)
            if not normalized:
                continue
            # Match against any origin indicator of the same type.
            for origin_type, origin_value in (
                (key.split(":", 1)[0], val)
                for key, val in origin_indicators.items()
            ):
                if origin_type == indicator.type and normalized == origin_value:
                    analysis = indicator.analysis
                    if analysis is None:
                        break
                    candidates.setdefault(analysis.analysis_id, analysis)
                    shared_by_analysis.setdefault(analysis.analysis_id, set()).add(
                        f"{indicator.type}:{normalized}"
                    )
                    break

    # Sender/Reply-To/Message-ID domain overlap.
    domain_rows = session.execute(
        select(EmailMetadata).where(EmailMetadata.analysis_id != origin.id)
    ).scalars().all()
    for metadata in domain_rows:
        for domain in (
            metadata.sender_domain,
            metadata.reply_to_domain,
            metadata.message_id_domain,
        ):
            normalized = normalize_domain(domain)
            if normalized and normalized in origin_domains:
                analysis = metadata.analysis
                if analysis is None:
                    continue
                candidates.setdefault(analysis.analysis_id, analysis)
                shared_by_analysis.setdefault(analysis.analysis_id, set()).add(
                    f"domain:{normalized}"
                )

    results: list[CorrelatedAnalysis] = []
    for analysis_id, analysis in candidates.items():
        shared = sorted(shared_by_analysis.get(analysis_id, set()))
        own_count = max(1, len(origin_indicators) + len(origin_domains))
        results.append(
            CorrelatedAnalysis(
                analysis_id=analysis.analysis_id,
                created_at=analysis.created_at.isoformat() if analysis.created_at else "",
                filename=analysis.filename,
                risk_score=analysis.risk_score,
                verdict=analysis.verdict,
                severity=analysis.severity,
                shared_indicators=[
                    {"type": key.split(":", 1)[0], "value": key.split(":", 1)[1]}
                    for key in shared
                ],
                overlap_score=round(min(1.0, len(shared) / own_count), 3),
            )
        )

    results.sort(key=lambda item: (-len(item.shared_indicators), item.analysis_id))
    return results[:limit]


__all__ = [
    "CorrelatedAnalysis",
    "CorrelationResult",
    "find_analyses_by_indicator",
    "normalize_domain",
    "normalize_indicator_value",
    "related_analyses",
    "url_host",
]
