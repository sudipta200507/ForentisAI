"""SQLAlchemy ORM models (Phase 6).

PRIVACY-FIRST CONTRACT:

- raw email bodies, full HTML, and raw headers are NEVER stored;
- sender/recipient addresses are stored as (domain, sha256-of-address) pairs
  so correlation can match exact senders without keeping the address;
- subjects are stored as (length, sha256) — enough to recognize repetition,
  not enough to leak content;
- indicators (IPs/domains/URLs) ARE stored in normalized form: they are the
  operational IOC data of the product;
- every child row cascades from its Analysis row so retention purges
  remove the full record.

All tables work on PostgreSQL and SQLite (no vendor-specific types).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    """Declarative base for all ForentisAI models."""


class Analysis(Base):
    """One analysis run: the retention root for all derived records."""

    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    # Deterministic, content-derived id returned by the API (UUIDv5 over the
    # email SHA-256). Indexed for correlation lookups.
    analysis_id: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    engine_version: Mapped[str] = mapped_column(String(32), default="")

    # Original-file fingerprint (never the content itself).
    email_sha256: Mapped[str] = mapped_column(String(64), index=True)
    email_size: Mapped[int] = mapped_column(Integer, default=0)
    filename: Mapped[str] = mapped_column(String(512), default="")

    processing_time_ms: Mapped[float] = mapped_column(Float, default=0.0)
    auth_available: Mapped[bool] = mapped_column(Boolean, default=False)

    # Denormalized top-line risk fields for fast dashboards; the full
    # assessment lives in ThreatAssessment.
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    verdict: Mapped[str] = mapped_column(String(16), default="inconclusive")
    severity: Mapped[str] = mapped_column(String(16), default="info")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    primary_threat_type: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # Model availability map, e.g. {"nlp": "available", "technical_ml": "unavailable"}.
    model_status: Mapped[dict] = mapped_column(JSON, default=dict)
    limitations: Mapped[list] = mapped_column(JSON, default=list)

    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)

    email_metadata: Mapped["EmailMetadata | None"] = relationship(
        back_populates="analysis",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="joined",
    )
    indicators: Mapped[list["Indicator"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", lazy="selectin"
    )
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", lazy="selectin"
    )
    threat_assessments: Mapped[list["ThreatAssessment"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", lazy="selectin"
    )
    events: Mapped[list["AnalysisEvent"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", lazy="selectin"
    )


class EmailMetadata(Base):
    """Derived, privacy-safe email metadata (no content, no raw addresses)."""

    __tablename__ = "email_metadata"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )

    subject_length: Mapped[int] = mapped_column(Integer, default=0)
    subject_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    sender_domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    sender_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    reply_to_domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    reply_to_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    return_path_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)

    recipient_domains: Mapped[list] = mapped_column(JSON, default=list)

    message_id_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    message_id_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)

    date_header: Mapped[str | None] = mapped_column(String(128), nullable=True)
    date_missing: Mapped[bool] = mapped_column(Boolean, default=False)

    received_hop_count: Mapped[int] = mapped_column(Integer, default=0)
    url_count: Mapped[int] = mapped_column(Integer, default=0)
    attachment_count: Mapped[int] = mapped_column(Integer, default=0)
    parser_defect_count: Mapped[int] = mapped_column(Integer, default=0)

    analysis: Mapped[Analysis] = relationship(back_populates="email_metadata")


class Indicator(Base):
    """One normalized IOC extracted from the analysis (never raw content)."""

    __tablename__ = "indicators"
    __table_args__ = (
        Index("ix_indicators_type_value", "type", "value"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    type: Mapped[str] = mapped_column(String(16))  # ipv4|ipv6|hostname|domain|url
    value: Mapped[str] = mapped_column(String(2048))
    source_kind: Mapped[str] = mapped_column(String(32), default="")
    source_location: Mapped[str] = mapped_column(String(128), default="")

    analysis: Mapped[Analysis] = relationship(back_populates="indicators")


class Evidence(Base):
    """One derived evidence record (explanations, auth outcomes, anomalies).

    ``detail`` and ``payload`` contain derived facts only — never raw email
    body text.
    """

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    kind: Mapped[str] = mapped_column(String(32), index=True)  # explanation|authentication|forensic|risk_signal
    category: Mapped[str] = mapped_column(String(64), default="")
    name: Mapped[str] = mapped_column(String(128), default="")
    detail: Mapped[str] = mapped_column(String(1024), default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)

    analysis: Mapped[Analysis] = relationship(back_populates="evidence")


class ThreatAssessment(Base):
    """The full risk-engine output for one analysis (immutable snapshot)."""

    __tablename__ = "threat_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    verdict: Mapped[str] = mapped_column(String(16), default="inconclusive")
    severity: Mapped[str] = mapped_column(String(16), default="info")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    primary_threat_type: Mapped[str | None] = mapped_column(String(64), nullable=True)

    threat_types: Mapped[list] = mapped_column(JSON, default=list)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    contributing_signals: Mapped[list] = mapped_column(JSON, default=list)
    model_contributions: Mapped[list] = mapped_column(JSON, default=list)
    limitations: Mapped[list] = mapped_column(JSON, default=list)
    thresholds: Mapped[dict] = mapped_column(JSON, default=dict)

    analysis: Mapped[Analysis] = relationship(back_populates="threat_assessments")


class AnalysisEvent(Base):
    """Lifecycle event for one analysis (audit trail; no content)."""

    __tablename__ = "analysis_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    event_type: Mapped[str] = mapped_column(String(32))  # received|analyzed|persisted|purged|error
    detail: Mapped[str] = mapped_column(String(512), default="")

    analysis: Mapped[Analysis] = relationship(back_populates="events")


__all__ = [
    "Analysis",
    "AnalysisEvent",
    "Base",
    "EmailMetadata",
    "Evidence",
    "Indicator",
    "ThreatAssessment",
]
