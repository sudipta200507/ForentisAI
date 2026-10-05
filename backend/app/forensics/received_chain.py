"""Forensic received-chain analysis (Phase 5A).

Parses the Received headers that Step 1 already extracted (no re-parsing of
the original email, no network requests) and derives:

- one :class:`ReceivedHop` per header with the fields that can be reliably
  extracted (from-host, from-IP, IP classification, by-host, protocol,
  timestamp);
- the EARLIEST RELIABLE CANDIDATE: the transport hop that most plausibly
  injected the message into the observed path, chosen deterministically from
  the origin side of the chain while skipping internal (non-public) relays;
- deterministic structural indicators (timestamp inversions, missing
  timestamps, internal relay counts).

TRUST MODEL (V1, documented):
- Positional trust only: the LAST Received header in the message is the
  earliest hop because genuine servers PREPEND Received headers in transit.
  A forged header injected at the top is the LEAST trustworthy one and is
  also the farthest from the origin, so this ordering is the conservative
  choice. Header forgery is detected only as structural anomalies (e.g.
  timestamp inversions), never asserted.
- An IP in a Received header is a candidate indicator, never an attacker
  attribution. The candidate is always labeled "earliest observed sending
  infrastructure".

CONFIDENCE (documented):
- high   → public IP + parsed timestamp + hostname;
- medium → public IP + at least one of (timestamp, hostname);
- low    → only a non-public IP, or no IP at all (hostname-only hop).

Timestamps are parsed with ``email.utils.parsedate_to_datetime`` and
normalized to UTC ISO-8601. Unparseable timestamps stay None and are never
guessed. The module is total: malformed individual headers degrade to
'unparseable' hops instead of raising.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from app.schemas.email import EmailEvidence
from app.schemas.forensics import (
    Confidence,
    EarliestReliableCandidate,
    ForensicEvidence,
    ForensicIndicator,
    IpClassification,
    ReceivedHop,
)

_FROM_HOST_RE = re.compile(r"^from\s+(?P<host>\S+)", re.IGNORECASE)
_FROM_IP_RE = re.compile(r"\((?:[^()]*?)\[(?P<ip>[0-9a-fA-F:.]+)\]", re.IGNORECASE)
_BY_HOST_RE = re.compile(r"\bby\s+(?P<host>[^\s;]+)", re.IGNORECASE)
_WITH_PROTO_RE = re.compile(r"\bwith\s+(?P<proto>[A-Za-z0-9]+)", re.IGNORECASE)


def _classify_ip(raw_ip: str) -> tuple[str | None, IpClassification | None]:
    """Validate and classify a Received-header IP; None when unparseable."""

    candidate = raw_ip.strip().strip("[]")
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return None, None
    if not parsed.is_global:
        if parsed.is_loopback:
            classification: IpClassification = "loopback"
        elif parsed.is_link_local:
            classification = "link_local"
        elif parsed.is_multicast:
            classification = "multicast"
        elif parsed.is_reserved or parsed.is_private:
            classification = "reserved" if parsed.is_reserved else "private"
        else:
            classification = "unspecified"
        return str(parsed), classification
    return str(parsed), "public"


def _parse_timestamp(raw: str) -> str | None:
    """Normalize a Received timestamp to UTC ISO-8601, or None."""

    if ";" not in raw:
        return None
    raw_date = raw.rsplit(";", 1)[1].strip()
    try:
        parsed = parsedate_to_datetime(raw_date)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _parse_hop(raw: str, position: int, hop_from_origin: int) -> ReceivedHop:
    from_host = None
    from_match = _FROM_HOST_RE.search(raw.strip())
    if from_match:
        from_host = from_match.group("host").rstrip(".").casefold()

    from_ip: str | None = None
    classification: IpClassification | None = None
    # Prefer the first parenthesised [...] address (the connecting IP).
    for match in _FROM_IP_RE.finditer(raw):
        ip, parsed_classification = _classify_ip(match.group("ip"))
        if ip is not None:
            from_ip = ip
            classification = parsed_classification
            break

    by_host = None
    by_match = _BY_HOST_RE.search(raw)
    if by_match:
        by_host = by_match.group("host").rstrip(".").casefold().strip("()")

    protocol = None
    proto_match = _WITH_PROTO_RE.search(raw)
    if proto_match:
        protocol = proto_match.group("proto").casefold()

    timestamp = _parse_timestamp(raw)

    return ReceivedHop(
        position=position,
        hop_from_origin=hop_from_origin,
        from_host=from_host,
        from_ip=from_ip,
        ip_classification=classification,
        by_host=by_host,
        protocol=protocol,
        timestamp_raw=(raw.rsplit(";", 1)[1].strip() if ";" in raw else None),
        timestamp=timestamp,
        timestamp_parsed=timestamp is not None,
        raw=raw,
    )


def _select_candidate(
    hops: list[ReceivedHop],
) -> EarliestReliableCandidate:
    """Deterministically pick the earliest reliable candidate.

    Walk the chain from the origin side (the LAST Received header) toward the
    recipient. The first hop carrying a PUBLIC IP is selected immediately:
    public addresses are globally routable and therefore the most reliable
    candidate for where the message entered the public transport path.
    Non-public (internal) IPs are skipped as internal relays. If no public IP
    exists anywhere, the earliest hop with any parseable IP is selected with
    low confidence; if there are no IPs at all, the earliest hop with a
    hostname is a low-confidence candidate; with nothing at all the result is
    ``no_candidate``.
    """

    limitations = [
        "Derived from Received headers only, which the sending client does "
        "not control but intermediate servers may rewrite; this is the "
        "earliest OBSERVED candidate, not a proven origin.",
        "No attribution is implied: the selected infrastructure is not "
        "accused of anything by this analysis.",
    ]

    if not hops:
        return EarliestReliableCandidate(
            status="no_candidate",
            confidence="low",
            reasoning=["The message contains no Received headers."],
            limitations=limitations
            + ["No transport-path evidence exists to evaluate."],
        )

    origin_first = sorted(hops, key=lambda hop: -hop.position)  # origin side first

    # 1) First public-IP hop from the origin side.
    for hop in origin_first:
        if hop.ip_classification == "public":
            confidence: Confidence = "low"
            reasoning = [
                f"Selected the earliest hop with a globally routable "
                f"(public) IP at Received header position {hop.position}.",
                "Skipped internal (non-public) relay hops closer to the origin.",
            ]
            if hop.timestamp_parsed:
                confidence = "medium"
                reasoning.append("The hop carries a parseable timestamp.")
            if hop.from_host:
                if confidence == "medium":
                    confidence = "high"
                reasoning.append(f"The hop includes a hostname ({hop.from_host}).")
            return EarliestReliableCandidate(
                status="success",
                ip=hop.from_ip,
                hostname=hop.from_host,
                timestamp=hop.timestamp,
                receiving_server=hop.by_host,
                hop_from_origin=hop.hop_from_origin,
                confidence=confidence,
                reasoning=reasoning,
                provenance={
                    "kind": "received_header",
                    "location": f"received_header[{hop.position}]",
                    "hop_from_origin": hop.hop_from_origin,
                    "ip_classification": "public",
                },
                limitations=limitations,
            )

    # 2) No public IP anywhere: earliest hop with any parseable IP.
    for hop in origin_first:
        if hop.from_ip is not None:
            return EarliestReliableCandidate(
                status="success",
                ip=hop.from_ip,
                hostname=hop.from_host,
                timestamp=hop.timestamp,
                receiving_server=hop.by_host,
                hop_from_origin=hop.hop_from_origin,
                confidence="low",
                reasoning=[
                    f"No public IP exists in the Received chain; selected the "
                    f"earliest hop with a non-public "
                    f"({hop.ip_classification}) IP at position {hop.position}.",
                    "A non-public IP cannot be verified beyond the local "
                    "network that reported it.",
                ],
                provenance={
                    "kind": "received_header",
                    "location": f"received_header[{hop.position}]",
                    "hop_from_origin": hop.hop_from_origin,
                    "ip_classification": hop.ip_classification or "unparseable",
                },
                limitations=limitations
                + ["The candidate IP is not globally routable."],
            )

    # 3) No IPs at all: earliest hostname-only hop.
    first = origin_first[0]
    if first.from_host:
        return EarliestReliableCandidate(
            status="success",
            ip=None,
            hostname=first.from_host,
            timestamp=first.timestamp,
            receiving_server=first.by_host,
            hop_from_origin=first.hop_from_origin,
            confidence="low",
            reasoning=[
                f"The Received chain contains no IP addresses; the earliest "
                f"hostname-only claim ({first.from_host}) is reported without "
                "any network verification.",
            ],
            provenance={
                "kind": "received_header",
                "location": f"received_header[{first.position}]",
                "hop_from_origin": first.hop_from_origin,
                "ip_classification": "unparseable",
            },
            limitations=limitations
            + ["No IP address could be extracted from the chain."],
        )

    return EarliestReliableCandidate(
        status="no_candidate",
        confidence="low",
        reasoning=["No Received header contained a usable IP or hostname."],
        limitations=limitations,
    )


def _indicators(hops: list[ReceivedHop]) -> list[ForensicIndicator]:
    indicators: list[ForensicIndicator] = []

    if not hops:
        indicators.append(
            ForensicIndicator(
                name="no_received_headers",
                detail="The message carries no Received headers; the transport "
                "path cannot be reconstructed.",
            )
        )
        return indicators

    parsed = [hop for hop in hops if hop.timestamp_parsed]
    if len(parsed) < len(hops):
        indicators.append(
            ForensicIndicator(
                name="missing_received_timestamps",
                detail=(
                    f"{len(hops) - len(parsed)} of {len(hops)} Received "
                    "headers carry no parseable timestamp."
                ),
            )
        )

    # Timestamp inversion: transport hops toward the recipient (decreasing
    # hop_from_origin) should NOT get earlier. Compare consecutive parsed hops
    # in origin order.
    with_time = sorted(
        (hop for hop in hops if hop.timestamp_parsed),
        key=lambda hop: hop.hop_from_origin,
    )
    inversions = 0
    for previous, current in zip(with_time, with_time[1:]):
        if current.timestamp and previous.timestamp and current.timestamp < previous.timestamp:
            inversions += 1
    if inversions:
        indicators.append(
            ForensicIndicator(
                name="received_timestamp_inversion",
                detail=(
                    f"{inversions} Received timestamp inversion(s) detected: "
                    "later hops report earlier times than the hops before "
                    "them, consistent with header forgery, clock skew, or "
                    "re-serialization."
                ),
            )
        )

    internal = [hop for hop in hops if hop.ip_classification not in (None, "public")]
    if internal:
        indicators.append(
            ForensicIndicator(
                name="internal_relay_hops",
                detail=(
                    f"{len(internal)} of {len(hops)} hops report non-public "
                    "(internal) IP addresses."
                ),
            )
        )

    unparseable = [hop for hop in hops if hop.from_host is None and hop.from_ip is None]
    if unparseable:
        indicators.append(
            ForensicIndicator(
                name="unparseable_received_header",
                detail=(
                    f"{len(unparseable)} Received header(s) could not be "
                    "structurally parsed."
                ),
            )
        )

    return indicators


def build_forensic_evidence(evidence: EmailEvidence) -> ForensicEvidence:
    """Build the Phase 5A forensic evidence; total function never raises."""

    raw_chain = list(evidence.received_chain or [])
    total = len(raw_chain)
    hops: list[ReceivedHop] = []
    for position, raw in enumerate(raw_chain):
        # position 0 = first header in the message = LAST transport hop.
        hop_from_origin = total - position
        try:
            hops.append(_parse_hop(raw, position, hop_from_origin))
        except Exception:  # noqa: BLE001 - one bad header must not kill forensics
            hops.append(
                ReceivedHop(
                    position=position,
                    hop_from_origin=max(1, hop_from_origin),
                    raw=raw,
                )
            )

    try:
        candidate = _select_candidate(hops)
    except Exception:  # noqa: BLE001 - forensics must never break the analysis
        candidate = EarliestReliableCandidate(
            status="unavailable",
            confidence="low",
            reasoning=["Candidate selection failed unexpectedly."],
        )

    limitations: list[str] = [
        "Received-header analysis relies on positional trust; injected or "
        "rewritten headers can mislead it, so all findings are candidates.",
    ]
    if not any(hop.timestamp_parsed for hop in hops):
        limitations.append(
            "No Received timestamp could be parsed, so transport timing "
            "cannot be cross-checked."
        )

    return ForensicEvidence(
        received_chain=hops,
        earliest_reliable_candidate=candidate,
        indicators=_indicators(hops),
        limitations=limitations,
    )


__all__ = ["build_forensic_evidence"]
