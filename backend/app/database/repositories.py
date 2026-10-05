"""Repositories (Phase 6): map an analysis response to database rows.

All functions are privacy-first: they persist DERIVED data only. No raw
email body, no full headers, no full addresses is ever passed to these
functions. Persistence failures are contained: :func:`persist_analysis`
returns ``False`` instead of raising so an analysis response is never lost
to a database outage.
"""

from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import (
    Analysis,
    AnalysisEvent,
    EmailMetadata,
    Evidence,
    Indicator,
    ThreatAssessment,
)
from app.database.session import session_scope


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _domain_of(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    domain = address.rpartition("@")[2].strip().strip(".").strip(">").casefold()
    return domain or None


def _first(reply_to) -> str | None:
    for address in reply_to or []:
        if address.address:
            return address.address
    return None


def persist_analysis(response: Any) -> bool:
    """Persist one analysis response (derived data only). Total function.

    ``response`` is the API :class:`AnalysisResponse`. Returns True when a
    row was written. Any failure returns False — persistence must never
    break analysis delivery.
    """

    try:
        with session_scope() as session:
            _persist(session, response)
        return True
    except Exception:  # noqa: BLE001 - persistence is best-effort
        return False


def _persist(session: Session, response: Any) -> None:
    evidence = response.email
    risk = response.risk
    ai = response.ai

    existing = session.execute(
        select(Analysis).where(Analysis.analysis_id == response.analysis_id)
    ).scalar_one_or_none()
    if existing is not None:
        return  # idempotent: same original bytes → same analysis_id

    sender_address = evidence.sender.address if evidence.sender else None
    reply_address = _first(evidence.message.reply_to)
    message_id = evidence.message.message_id
    subject = evidence.message.subject or ""

    analysis = Analysis(
        analysis_id=response.analysis_id,
        engine_version=response.metadata.engine_version if response.metadata else "",
        email_sha256=evidence.file.sha256,
        email_size=evidence.file.size,
        filename=evidence.file.filename[:512],
        processing_time_ms=(
            response.metadata.processing_time_ms if response.metadata else 0.0
        ),
        auth_available=(
            authentication_is_available(response.authentication)
        ),
        risk_score=risk.risk_score,
        verdict=risk.verdict,
        severity=risk.severity,
        confidence=risk.confidence,
        primary_threat_type=risk.primary_threat_type,
        model_status=dict(ai.fusion.model_status or {}),
        limitations=list(risk.limitations),
        metadata_json=(
            response.metadata.model_dump() if response.metadata else {}
        ),
    )
    session.add(analysis)
    session.flush()

    session.add(
        EmailMetadata(
            analysis_id=analysis.id,
            subject_length=len(subject),
            subject_sha256=_sha256(subject) if subject else None,
            sender_domain=_domain_of(sender_address),
            sender_sha256=_sha256(sender_address) if sender_address else None,
            reply_to_domain=_domain_of(reply_address),
            reply_to_sha256=_sha256(reply_address) if reply_address else None,
            return_path_domain=_domain_of(
                (evidence.message.return_path or "").strip().strip("<>")
            ),
            recipient_domains=sorted(
                {
                    domain
                    for group in (evidence.recipients.to, evidence.recipients.cc)
                    for address in group
                    if (domain := _domain_of(address.address))
                }
            ),
            message_id_sha256=_sha256(message_id) if message_id else None,
            message_id_domain=_domain_of(message_id) if message_id else None,
            date_header=(evidence.message.date[:128] if evidence.message.date else None),
            date_missing=evidence.message.date is None,
            received_hop_count=len(evidence.received_chain or []),
            url_count=len(evidence.urls or []),
            attachment_count=len(evidence.attachments or []),
            parser_defect_count=len(evidence.parser_defects or []),
        )
    )

    for indicator in response.intelligence.indicators:
        session.add(
            Indicator(
                analysis_id=analysis.id,
                type=indicator.type,
                value=indicator.value[:2048],
                source_kind=indicator.source.kind,
                source_location=indicator.source.location[:128],
            )
        )
    for url in evidence.urls:
        session.add(
            Indicator(
                analysis_id=analysis.id,
                type="url",
                value=url.url[:2048],
                source_kind="body",
                source_location=url.source,
            )
        )

    for explanation in ai.explainability.explanations:
        session.add(
            Evidence(
                analysis_id=analysis.id,
                kind="explanation",
                category=explanation.category,
                name="structured_explanation",
                detail=explanation.reason[:1024],
                payload={
                    "impact": explanation.impact,
                    "evidence": explanation.evidence,
                },
            )
        )
    for signal in risk.contributing_signals:
        session.add(
            Evidence(
                analysis_id=analysis.id,
                kind="risk_signal",
                category=signal.category,
                name=signal.name[:128],
                detail=signal.detail[:1024],
                payload={"points": signal.points, "source": signal.source},
            )
        )
    for hop in response.forensics.received_chain:
        session.add(
            Evidence(
                analysis_id=analysis.id,
                kind="forensic",
                category="received_hop",
                name=f"received_header[{hop.position}]",
                detail=(
                    f"from={hop.from_host or 'unknown'}; ip_class="
                    f"{hop.ip_classification or 'unknown'}; by={hop.by_host or 'unknown'}"
                ),
                payload={
                    "hop_from_origin": hop.hop_from_origin,
                    "ip": hop.from_ip,
                    "classification": hop.ip_classification,
                    "timestamp": hop.timestamp,
                },
            )
        )

    session.add(
        ThreatAssessment(
            analysis_id=analysis.id,
            risk_score=risk.risk_score,
            verdict=risk.verdict,
            severity=risk.severity,
            confidence=risk.confidence,
            primary_threat_type=risk.primary_threat_type,
            threat_types=list(risk.threat_types),
            reasons=list(risk.reasons),
            contributing_signals=[signal.model_dump() for signal in risk.contributing_signals],
            model_contributions=[
                contribution.model_dump() for contribution in risk.model_contributions
            ],
            limitations=list(risk.limitations),
            thresholds=dict(risk.thresholds),
        )
    )

    session.add(
        AnalysisEvent(
            analysis_id=analysis.id,
            event_type="analyzed",
            detail="Analysis persisted (derived data only).",
        )
    )


def authentication_is_available(authentication: Any) -> bool:
    """True when at least one auth protocol actually answered."""

    if authentication is None:
        return False
    return any(
        protocol.available == "available"
        for protocol in (authentication.spf, authentication.dkim, authentication.dmarc)
    )


def get_analysis_by_id(analysis_id: str) -> Analysis | None:
    """Fetch one stored analysis by its deterministic analysis_id."""

    with session_scope() as session:
        return session.execute(
            select(Analysis).where(Analysis.analysis_id == analysis_id)
        ).scalar_one_or_none()


def recent_analyses(limit: int = 50) -> list[Analysis]:
    """Most recent analyses for the dashboard."""

    with session_scope() as session:
        rows = session.execute(
            select(Analysis)
            .order_by(Analysis.created_at.desc())
            .limit(limit)
        ).scalars().all()
        session.expunge_all()
        return list(rows)


__all__ = [
    "get_analysis_by_id",
    "persist_analysis",
    "recent_analyses",
]
