"""Pydantic models for Phase 7 forensic reports.

A report is a DERIVED, self-contained document over one analysis response.
It contains no raw email body and never fabricates forensic conclusions:
every section either restates evidence that already exists in the analysis
response or explicitly reports its absence.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ReportFormat = Literal["json", "html"]


class ReportMetadata(BaseModel):
    """Report identity and provenance (no email content)."""

    model_config = ConfigDict(extra="forbid")

    report_id: str = Field(min_length=1)
    analysis_id: str = Field(min_length=1)
    schema_version: str = "1.0"
    generated_at: str = Field(min_length=1)
    engine_version: str = ""
    model_versions: dict[str, str | None] = Field(default_factory=dict)
    processing_time_ms: float = Field(default=0.0, ge=0.0)


class ExecutiveSummary(BaseModel):
    """Deterministic headline: what the evidence says, nothing more."""

    model_config = ConfigDict(extra="forbid")

    headline: str = Field(min_length=1)
    risk_score: float = Field(ge=0.0, le=100.0)
    verdict: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    primary_threat_type: str | None = None
    threat_types: list[str] = Field(default_factory=list)
    models_available: list[str] = Field(default_factory=list)
    authentication_available: bool = False


class SenderSummary(BaseModel):
    """Sender/header identity facts extracted from the evidence schema."""

    model_config = ConfigDict(extra="forbid")

    from_address: str | None = None
    from_display_name: str | None = None
    reply_to: list[str] = Field(default_factory=list)
    return_path: str | None = None
    message_id: str | None = None
    subject: str | None = None
    date: str | None = None
    recipients_to: list[str] = Field(default_factory=list)
    recipients_cc: list[str] = Field(default_factory=list)
    attachments: list[dict[str, Any]] = Field(default_factory=list)


class ReportPayload(BaseModel):
    """The complete Phase 7 report document."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    metadata: ReportMetadata
    executive_summary: ExecutiveSummary
    threat: dict[str, Any]
    authentication: dict[str, Any]
    sender: SenderSummary
    received_path: dict[str, Any]
    intelligence: dict[str, Any]
    ai: dict[str, Any]
    explanations: list[dict[str, Any]] = Field(default_factory=list)
    evidence: dict[str, Any]
    limitations: list[str] = Field(default_factory=list)


__all__ = [
    "ExecutiveSummary",
    "ReportFormat",
    "ReportMetadata",
    "ReportPayload",
    "SenderSummary",
]