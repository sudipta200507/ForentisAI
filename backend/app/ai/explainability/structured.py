"""Structured, evidence-based explanations (Phase H).

Builds deterministic, human-readable explanation entries that combine:

- model outputs restated in plain language (clearly labeled as model
  assessments — never claimed to be exact transformer attribution);
- deterministic keyword-pattern indicators from the NLP layer;
- header evidence (sender/reply-to/return-path/message-id mismatches,
  missing structural headers);
- URL evidence (IP-literal hosts, registered-domain mismatches, odd ports);
- authentication outcomes (SPF/DKIM/DMARC failures);
- infrastructure evidence (young RDAP domain age).

Every entry is EVIDENCE/REASON, not a verdict: categories are stable
identifiers, impact is a coarse qualitative weight, and ``evidence`` is a
short factual anchor using extracted indicator values only — never raw email
body text. The list is sorted high-impact-first and capped.
"""

from __future__ import annotations

from app.ai.fusion.classifier import FusionResult  # noqa: F401 - typing re-export
from app.schemas.ai import (
    NLPResult,
    StructuredExplanation,
    TechnicalMLResult,
)
from app.schemas.authentication import AuthenticationEvidence
from app.schemas.email import EmailEvidence
from app.schemas.intelligence import IntelligenceEvidence

_IMPACT_ORDER = {"high": 0, "medium": 1, "low": 2}
_MAX_EXPLANATIONS = 12

# NLP keyword-indicator name -> (category, impact).
_INDICATOR_CATEGORIES: dict[str, tuple[str, str]] = {
    "credential_request_pattern": ("credential_harvesting", "high"),
    "beca_request_pattern": ("bec_social_engineering", "high"),
    "urgency_language": ("urgency_pressure", "medium"),
    "account_verification_pattern": ("credential_harvesting", "medium"),
    "payment_request_pattern": ("payment_fraud", "medium"),
    "threat_pressure_pattern": ("threat_intimidation", "medium"),
    "authority_claim_pattern": ("authority_impersonation", "medium"),
}

_COMPOUND_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.jp", "com.br",
    "co.in", "co.nz", "com.mx", "co.za",
}


def _mailbox_domain(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    domain = address.rpartition("@")[2].strip().strip(".").casefold()
    return domain or None


def _first_reply_to_domain(evidence: EmailEvidence) -> str | None:
    for address in evidence.message.reply_to:
        if address.address:
            return _mailbox_domain(address.address)
    return None


def _sender_domain(evidence: EmailEvidence) -> str | None:
    if evidence.sender and evidence.sender.address:
        return _mailbox_domain(evidence.sender.address)
    return None


def _model_impact(probability: float) -> str:
    if probability >= 0.85:
        return "high"
    if probability >= 0.6:
        return "medium"
    return "low"


def _nlp_explanations(nlp: NLPResult) -> list[StructuredExplanation]:
    entries: list[StructuredExplanation] = []
    if not nlp.available:
        return entries

    p_susp = nlp.probabilities.get("suspicious")
    if p_susp is not None and p_susp >= 0.5:
        entries.append(
            StructuredExplanation(
                reason=(
                    f"The fine-tuned NLP model classifies the message text as "
                    f"'{nlp.predicted_class}' (suspicious probability "
                    f"{p_susp:.2f}). This is a model assessment, not an exact "
                    "explanation of the transformer's internal reasoning."
                ),
                category="model_assessment",
                impact=_model_impact(p_susp),  # type: ignore[arg-type]
                evidence=f"nlp.suspicious_probability={p_susp:.3f}",
            )
        )

    for indicator in nlp.indicators:
        mapping = _INDICATOR_CATEGORIES.get(indicator.name)
        if mapping is None:
            continue
        category, impact = mapping
        entries.append(
            StructuredExplanation(
                reason=f"{indicator.detail}",
                category=category,
                impact=impact,  # type: ignore[arg-type]
                evidence=f"pattern_hits={int(indicator.weight)} (deterministic keyword pattern)",
            )
        )
    return entries


def _technical_explanations(technical: TechnicalMLResult) -> list[StructuredExplanation]:
    if not technical.available:
        return []
    p_susp = technical.probabilities.get("suspicious")
    if p_susp is None:
        return []
    threshold = technical.threshold
    decision_rule = (
        f"threshold {threshold:.2f}" if threshold is not None else "argmax rule"
    )
    impact = "low"
    if technical.predicted_class == "suspicious":
        impact = "high" if p_susp >= 0.7 else "medium"
    return [
        StructuredExplanation(
            reason=(
                f"The technical (Random Forest) model scores the email's "
                f"structural features at {p_susp:.2f} suspicious probability "
                f"and flags '{technical.predicted_class}' using the "
                f"{decision_rule}. This is a model assessment over derived "
                "features, not a statement about the sender's intent."
            ),
            category="model_assessment",
            impact=impact,  # type: ignore[arg-type]
            evidence=(
                f"technical.suspicious_probability={p_susp:.3f}; "
                f"model_features={technical.model_feature_count or 'n/a'}"
            ),
        )
    ]


def _header_explanations(evidence: EmailEvidence) -> list[StructuredExplanation]:
    entries: list[StructuredExplanation] = []
    sender_domain = _sender_domain(evidence)

    reply_domain = _first_reply_to_domain(evidence)
    if sender_domain and reply_domain and reply_domain != sender_domain:
        entries.append(
            StructuredExplanation(
                reason=(
                    "The Reply-To address points to a different domain than "
                    "the From sender; replies would go to an unrelated "
                    "mailbox — a common phishing/BEC pattern."
                ),
                category="sender_mismatch",
                impact="high",
                evidence=f"from_domain={sender_domain}; reply_to_domain={reply_domain}",
            )
        )

    return_path = evidence.message.return_path
    return_domain = None
    if return_path:
        cleaned = return_path.strip().strip("<>").strip()
        return_domain = _mailbox_domain(cleaned)
    if sender_domain and return_domain and return_domain != sender_domain:
        entries.append(
            StructuredExplanation(
                reason=(
                    "The envelope Return-Path (bounce address) domain differs "
                    "from the visible sender domain."
                ),
                category="sender_mismatch",
                impact="medium",
                evidence=f"from_domain={sender_domain}; return_path_domain={return_domain}",
            )
        )

    message_id = evidence.message.message_id
    if message_id:
        inner = message_id.strip().strip("<>").strip()
        mid_domain = _mailbox_domain(inner) if "@" in inner else None
        if sender_domain and mid_domain and mid_domain != sender_domain:
            entries.append(
                StructuredExplanation(
                    reason=(
                        "The Message-ID was generated on a domain unrelated to "
                        "the sender domain, which can indicate a forged or "
                        "externally injected message."
                    ),
                    category="unusual_header_structure",
                    impact="medium",
                    evidence=f"from_domain={sender_domain}; message_id_domain={mid_domain}",
                )
            )
    else:
        entries.append(
            StructuredExplanation(
                reason="The message has no Message-ID header.",
                category="unusual_header_structure",
                impact="low",
                evidence="message_id=missing",
            )
        )

    if not evidence.message.date:
        entries.append(
            StructuredExplanation(
                reason="The message has no Date header.",
                category="unusual_header_structure",
                impact="low",
                evidence="date=missing",
            )
        )

    hop_count = len(evidence.received_chain or [])
    if hop_count == 0:
        entries.append(
            StructuredExplanation(
                reason=(
                    "No Received headers were found, so the transport path "
                    "cannot be reviewed at all."
                ),
                category="unusual_header_structure",
                impact="low",
                evidence="received_hop_count=0",
            )
        )

    return entries


def _url_explanations(evidence: EmailEvidence) -> list[StructuredExplanation]:
    entries: list[StructuredExplanation] = []
    urls = list(evidence.urls or [])
    if not urls:
        return entries

    from urllib.parse import urlparse

    ip_hosts: list[str] = []
    odd_ports: list[str] = []
    for url_indicator in urls:
        parsed = urlparse(url_indicator.url)
        host = (parsed.hostname or "").casefold()
        if not host:
            continue
        try:
            ipaddress_module = __import__("ipaddress")
            ipaddress_module.ip_address(host.strip("[]"))
            ip_hosts.append(host.strip("[]"))
        except ValueError:
            pass
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is not None and port not in (80, 443):
            odd_ports.append(f"{host}:{port}")

    if ip_hosts:
        entries.append(
            StructuredExplanation(
                reason=(
                    "One or more links point to a bare IP address instead of a "
                    "domain name, a pattern typical of throwaway phishing "
                    "infrastructure."
                ),
                category="suspicious_url",
                impact="high",
                evidence=f"ip_literal_url_count={len(ip_hosts)}",
            )
        )

    sender_domain = _sender_domain(evidence)
    sender_registered = None
    if sender_domain and "." in sender_domain:
        last_two = ".".join(sender_domain.split(".")[-2:])
        if last_two not in _COMPOUND_SUFFIXES:
            sender_registered = last_two

    mismatched = 0
    for url_indicator in urls:
        parsed = urlparse(url_indicator.url)
        host = (parsed.hostname or "").casefold()
        if not host or "." not in host or host.startswith("["):
            continue
        last_two = ".".join(host.split(".")[-2:])
        if last_two in _COMPOUND_SUFFIXES or sender_registered is None:
            continue
        if last_two != sender_registered:
            mismatched += 1
    if mismatched:
        entries.append(
            StructuredExplanation(
                reason=(
                    "Link destinations use registered domains different from "
                    "the sender's domain; recipients are being sent off-site."
                ),
                category="suspicious_url",
                impact="medium",
                evidence=(
                    f"url_registered_domain_mismatch_count={mismatched}; "
                    f"from_domain={sender_domain or 'unknown'}"
                ),
            )
        )

    if odd_ports:
        entries.append(
            StructuredExplanation(
                reason=(
                    "Links use non-standard TCP ports, which is unusual for "
                    "ordinary correspondence."
                ),
                category="suspicious_url",
                impact="low",
                evidence=f"hosts_with_odd_ports={len(odd_ports)}",
            )
        )

    return entries


def _authentication_explanations(
    authentication: AuthenticationEvidence | None,
) -> list[StructuredExplanation]:
    if authentication is None:
        return []
    entries: list[StructuredExplanation] = []

    spf = authentication.spf
    if spf.available == "available" and spf.result in {"fail", "softfail"}:
        entries.append(
            StructuredExplanation(
                reason=(
                    "SPF did not authorize the sending infrastructure for the "
                    "envelope domain; the message may have been sent by an "
                    "unauthorized server."
                ),
                category="authentication_failure",
                impact="medium" if spf.result == "softfail" else "high",
                evidence=f"spf_result={spf.result}",
            )
        )

    dkim = authentication.dkim
    if dkim.available == "available" and dkim.result == "fail":
        entries.append(
            StructuredExplanation(
                reason=(
                    "The DKIM signature failed verification, so the message "
                    "content cannot be attributed to the signing domain."
                ),
                category="authentication_failure",
                impact="medium",
                evidence=f"dkim_result={dkim.result}",
            )
        )

    dmarc = authentication.dmarc
    if dmarc.available == "available" and dmarc.result in {"fail", "quarantine", "reject"}:
        entries.append(
            StructuredExplanation(
                reason=(
                    "DMARC evaluation failed for the visible From domain; "
                    "legitimate senders with a strict policy would not pass "
                    "this message off."
                ),
                category="authentication_failure",
                impact="high" if dmarc.result in {"reject", "fail"} else "medium",
                evidence=f"dmarc_result={dmarc.result}; policy={dmarc.policy or 'unknown'}",
            )
        )

    return entries


def _intelligence_explanations(
    intelligence: IntelligenceEvidence | None,
) -> list[StructuredExplanation]:
    if intelligence is None:
        return []
    entries: list[StructuredExplanation] = []

    youngest = None
    for domain in intelligence.domains:
        rdap = domain.rdap
        if rdap is None or rdap.status != "success" or not rdap.registration_date:
            continue
        from datetime import datetime, timezone

        try:
            registered = datetime.fromisoformat(
                rdap.registration_date.strip().replace("Z", "+00:00")
            )
        except ValueError:
            continue
        if registered.tzinfo is None:
            registered = registered.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - registered).total_seconds() / 86400.0
        if youngest is None or age_days < youngest:
            youngest = age_days
            domain_name = domain.normalized_domain or domain.indicator.value

    if youngest is not None and 0 <= youngest < 30:
        entries.append(
            StructuredExplanation(
                reason=(
                    "A linked or sending domain was registered less than 30 "
                    "days before this analysis; newly created domains are "
                    "over-represented in phishing campaigns."
                ),
                category="unusual_infrastructure",
                impact="medium",
                evidence=f"youngest_domain_age_days={youngest:.1f}",
            )
        )

    return entries


def build_structured_explanations(
    evidence: EmailEvidence,
    authentication: AuthenticationEvidence | None,
    intelligence: IntelligenceEvidence | None,
    nlp: NLPResult,
    technical: TechnicalMLResult,
    fusion: FusionResult,
) -> list[StructuredExplanation]:
    """Deterministic, evidence-anchored explanations; total function.

    Sorted high-impact-first, then by category, capped at
    ``_MAX_EXPLANATIONS``. Never raises; a failure in one builder only drops
    that builder's entries.
    """

    entries: list[StructuredExplanation] = []
    builders = (
        lambda: _nlp_explanations(nlp),
        lambda: _technical_explanations(technical),
        lambda: _header_explanations(evidence),
        lambda: _url_explanations(evidence),
        lambda: _authentication_explanations(authentication),
        lambda: _intelligence_explanations(intelligence),
    )
    for builder in builders:
        try:
            entries.extend(builder())
        except Exception:  # noqa: BLE001 - explanation must never break analysis
            continue

    entries.sort(
        key=lambda item: (
            _IMPACT_ORDER.get(item.impact, 3),
            item.category,
            item.reason,
        )
    )
    return entries[:_MAX_EXPLANATIONS]


__all__ = ["build_structured_explanations"]
