"""Pydantic models for Phase 5A forensic evidence.

CRITICAL WORDING RULE: observed infrastructure is NOT automatically the
attacker. Everything in this schema describes the EARLIEST OBSERVED SENDING
INFRASTRUCTURE / earliest reliable candidate derived from the Received chain.
No field, reason, or detail may claim sender or attacker attribution.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.email import EvidenceModel

EarliestCandidateStatus = Literal["success", "no_candidate", "unavailable"]

Confidence = Literal["high", "medium", "low"]

IpClassification = Literal[
    "public",
    "private",
    "loopback",
    "link_local",
    "reserved",
    "multicast",
    "unspecified",
    "unparseable",
]


class ReceivedHop(EvidenceModel):
    """One parsed Received header.

    ``position`` is the index inside ``EmailEvidence.received_chain`` (message
    order: position 0 is the FIRST Received header in the message and is
    therefore the LAST transport hop; the last position is the EARLIEST hop).
    ``hop_from_origin`` counts from the origin side (1 = earliest hop).
    """

    position: int = Field(ge=0)
    hop_from_origin: int = Field(ge=1)
    from_host: str | None = None
    from_ip: str | None = None
    ip_classification: IpClassification | None = None
    by_host: str | None = None
    protocol: str | None = None
    timestamp_raw: str | None = None
    timestamp: str | None = Field(
        default=None,
        description="ISO-8601 UTC when the Received date parsed; otherwise None.",
    )
    timestamp_parsed: bool = False
    raw: str = Field(min_length=1)


class EarliestReliableCandidate(EvidenceModel):
    """The earliest reliable sending-infrastructure candidate (Phase 5A).

    This is NOT an attacker claim. It is the best-supported answer to the
    question 'which infrastructure most plausibly injected this message into
    the observed transport path, according to the Received chain alone'.
    """

    status: EarliestCandidateStatus
    label: str = "earliest observed sending infrastructure"
    ip: str | None = None
    hostname: str | None = None
    timestamp: str | None = None
    receiving_server: str | None = None
    hop_from_origin: int | None = Field(default=None, ge=1)
    confidence: Confidence = "low"
    reasoning: list[str] = Field(default_factory=list)
    provenance: dict[str, str | int] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)


class ForensicIndicator(EvidenceModel):
    """One deterministic structural observation about the Received chain.

    These are EVIDENCE entries, not verdicts. ``received_timestamp_inversion``
    means timestamps are not monotonically increasing toward the recipient —
    consistent with header forgery, clock skew, or re-serialization.
    """

    name: Literal[
        "received_timestamp_inversion",
        "missing_received_timestamps",
        "internal_relay_hops",
        "no_received_headers",
        "unparseable_received_header",
    ]
    detail: str = Field(min_length=1)


class ForensicEvidence(EvidenceModel):
    """Phase 5A output: forensic structure of the transport path."""

    schema_version: Literal["1.0"] = "1.0"
    received_chain: list[ReceivedHop] = Field(default_factory=list)
    earliest_reliable_candidate: EarliestReliableCandidate | None = None
    indicators: list[ForensicIndicator] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


__all__ = [
    "Confidence",
    "EarliestReliableCandidate",
    "ForensicEvidence",
    "ForensicIndicator",
    "ReceivedHop",
]
