"""Deterministic V1 risk engine (Phase 3).

Turns all available evidence — AI model outputs, authentication results,
header anomalies, URL indicators, infrastructure intelligence, and text
signals — into one documented, deterministic risk assessment.

METHOD (V1, documented and versioned):

    risk_score = min(100, Σ signal points)

    Model evidence (max 45 points):
        NLP suspicious probability          × 20
        Technical-ML suspicious probability × 15
        Fused suspicious probability        × 10

    Authentication evidence (max 21 points):
        DMARC reject         → 10      quarantine → 8      fail → 8
        SPF fail → 6   SPF softfail → 3
        DKIM fail → 5
        (PASS never scores: authentication is one evidence source and a
         pass must never imply the email is safe.)

    Header anomalies (max 15 points):
        sender/reply-to domain mismatch → 6
        return-path/sender mismatch     → 3
        message-id domain mismatch      → 3
        message-id missing              → 1
        date missing                    → 1
        parser defects (capped)         → 1

    URL indicators (max 16 points):
        literal-IP URL hosts        → 4 each, capped at 8
        off-site registered domains → 2 each, capped at 6
        non-default URL ports       → 1 each, capped at 2

    Intelligence evidence (max 9 points):
        youngest linked/sending domain age < 30 days  → 6
        youngest domain age 30–89 days                → 3
        (Observed public IPs score NOTHING: infrastructure observed in
         Received headers is NOT the attacker and is never scored as such.)

    Text keyword signals (max 10 points):
        credential keywords → 5   payment keywords → 3   urgency → 2

VERDICT (documented thresholds):
    risk_score >= 75                    → "malicious"
    45 <= risk_score < 75               → "suspicious"
    risk_score < 45                     → "benign"
    models AND authentication BOTH
    unavailable                         → "inconclusive" (no verdict can be
                                          responsibly reached on the
                                          remaining evidence alone)

SEVERITY:
    malicious: score >= 90 → critical, else high
    suspicious: score >= 60 → medium, else low
    benign:    score >= 15 → low, else info
    inconclusive → info

CONFIDENCE (evidence-corroboration based, never single-signal based):
    base 0.20; +0.25 NLP available; +0.20 technical available; +0.10 fusion
    available; +0.15 authentication available; +0.10 intelligence had at
    least one successful lookup; +0.05 when both models agree (|Δp| < 0.25).
    Missing critical evidence therefore LOWERS confidence by construction.

Design rules:
- risk_score and model probabilities are DISTINCT concepts (a p=1.0 model
  with no corroboration scores 45, not 100);
- the engine is a pure, total function: no network, no clock (domain age
  comes pre-computed relative to the email date from the feature layer),
  identical inputs → identical assessment;
- missing evidence is never treated as a clean pass: it reduces confidence
  and appends an explicit limitation;
- no signal ever claims sender/attacker attribution.
"""

from __future__ import annotations

from app.features.feature_fusion import build_feature_vector
from app.schemas.ai import AIAnalysis
from app.schemas.authentication import AuthenticationEvidence
from app.schemas.email import EmailEvidence
from app.schemas.features import FeatureVector
from app.schemas.intelligence import IntelligenceEvidence
from app.schemas.risk import (
    ContributingSignal,
    ModelContribution,
    RiskAssessment,
    RiskSeverity,
    RiskVerdict,
    ThreatType,
)

# ---------------------------------------------------------------------------
# Documented weight tables (V1).
# ---------------------------------------------------------------------------

_WEIGHT_NLP = 20.0
_WEIGHT_TECHNICAL = 15.0
_WEIGHT_FUSION = 10.0

_DMARC_REJECT_POINTS = 10.0
_DMARC_QUARANTINE_OR_FAIL_POINTS = 8.0
_SPF_FAIL_POINTS = 6.0
_SPF_SOFTFAIL_POINTS = 3.0
_DKIM_FAIL_POINTS = 5.0

_REPLY_TO_MISMATCH_POINTS = 6.0
_RETURN_PATH_MISMATCH_POINTS = 3.0
_MESSAGE_ID_MISMATCH_POINTS = 3.0
_MESSAGE_ID_MISSING_POINTS = 1.0
_DATE_MISSING_POINTS = 1.0
_PARSER_DEFECT_POINTS = 1.0

_IP_URL_POINTS_EACH = 4.0
_IP_URL_POINTS_CAP = 8.0
_OFFSITE_DOMAIN_POINTS_EACH = 2.0
_OFFSITE_DOMAIN_POINTS_CAP = 6.0
_ODD_PORT_POINTS_EACH = 1.0
_ODD_PORT_POINTS_CAP = 2.0

_YOUNG_DOMAIN_POINTS = 6.0
_YOUNG_DOMAIN_DAYS = 30.0
_MID_DOMAIN_POINTS = 3.0
_MID_DOMAIN_DAYS = 90.0

_CREDENTIAL_TEXT_POINTS = 5.0
_PAYMENT_TEXT_POINTS = 3.0
_URGENCY_TEXT_POINTS = 2.0

_CAP = 100.0

_SUSPICIOUS_THRESHOLD = 45.0
_MALICIOUS_THRESHOLD = 75.0
_MEDIUM_SEVERITY_THRESHOLD = 60.0
_INFO_SEVERITY_THRESHOLD = 15.0

_CONFIDENCE_BASE = 0.20
_CONFIDENCE_NLP = 0.25
_CONFIDENCE_TECHNICAL = 0.20
_CONFIDENCE_FUSION = 0.10
_CONFIDENCE_AUTH = 0.15
_CONFIDENCE_INTELLIGENCE = 0.10
_CONFIDENCE_AGREEMENT = 0.05
_CONFIDENCE_CAP = 0.95
_AGREEMENT_DELTA = 0.25

_MAX_SIGNALS = 40

_VERDICT_THRESHOLDS = {
    "suspicious": _SUSPICIOUS_THRESHOLD,
    "malicious": _MALICIOUS_THRESHOLD,
}


def _suspicious_probability(probabilities: dict[str, float]) -> float | None:
    value = probabilities.get("suspicious")
    if value is None:
        return None
    return max(0.0, min(1.0, float(value)))


# ---------------------------------------------------------------------------
# Signal collectors. Each returns (points, signal | None).
# ---------------------------------------------------------------------------


def _model_signals(
    ai: AIAnalysis,
) -> tuple[float, list[ContributingSignal], list[ModelContribution]]:
    points = 0.0
    signals: list[ContributingSignal] = []
    contributions: list[ModelContribution] = []

    nlp_p = _suspicious_probability(ai.nlp.probabilities) if ai.nlp.available else None
    tech_p = (
        _suspicious_probability(ai.technical_ml.probabilities)
        if ai.technical_ml.available
        else None
    )
    fusion_p = (
        _suspicious_probability(ai.fusion.probabilities) if ai.fusion.available else None
    )

    for component, available, probability, weight in (
        ("nlp", ai.nlp.available, nlp_p, _WEIGHT_NLP),
        ("technical_ml", ai.technical_ml.available, tech_p, _WEIGHT_TECHNICAL),
        ("fusion", ai.fusion.available, fusion_p, _WEIGHT_FUSION),
    ):
        component_points = round(weight * probability, 4) if probability is not None else 0.0
        points += component_points
        if probability is not None and component_points > 0:
            if component == "nlp":
                detail = (
                    f"nlp.suspicious_probability={probability:.3f} × weight {weight:g}"
                )
            elif component == "technical_ml":
                detail = (
                    f"technical_ml.suspicious_probability={probability:.3f} "
                    f"× weight {weight:g}"
                )
            else:
                detail = (
                    f"fusion.suspicious_probability={probability:.3f} × weight {weight:g}"
                )
            signals.append(
                ContributingSignal(
                    name=f"{component}_suspicious_probability",
                    category="model_flagged",
                    source="model",
                    points=component_points,
                    detail=detail,
                )
            )
        contributions.append(
            ModelContribution(
                component=component,  # type: ignore[arg-type]
                available=available,
                suspicious_probability=probability,
                points=component_points,
                note=None if available else "model unavailable; contributed no points",
            )
        )

    return points, signals, contributions


def _authentication_signals(
    authentication: AuthenticationEvidence | None,
) -> tuple[float, list[ContributingSignal]]:
    points = 0.0
    signals: list[ContributingSignal] = []
    if authentication is None:
        return points, signals

    dmarc = authentication.dmarc
    if dmarc.available == "available":
        dmarc_points = 0.0
        if dmarc.result == "reject":
            dmarc_points = _DMARC_REJECT_POINTS
        elif dmarc.result in {"quarantine", "fail"}:
            dmarc_points = _DMARC_QUARANTINE_OR_FAIL_POINTS
        if dmarc_points:
            points += dmarc_points
            signals.append(
                ContributingSignal(
                    name="dmarc_failure",
                    category="authentication_failure",
                    source="authentication",
                    points=dmarc_points,
                    detail=f"dmarc_result={dmarc.result}; policy={dmarc.policy or 'unknown'}",
                )
            )

    spf = authentication.spf
    if spf.available == "available":
        if spf.result == "fail":
            points += _SPF_FAIL_POINTS
            signals.append(
                ContributingSignal(
                    name="spf_failure",
                    category="authentication_failure",
                    source="authentication",
                    points=_SPF_FAIL_POINTS,
                    detail=f"spf_result=fail; domain={spf.domain or 'unknown'}",
                )
            )
        elif spf.result == "softfail":
            points += _SPF_SOFTFAIL_POINTS
            signals.append(
                ContributingSignal(
                    name="spf_softfail",
                    category="authentication_failure",
                    source="authentication",
                    points=_SPF_SOFTFAIL_POINTS,
                    detail=f"spf_result=softfail; domain={spf.domain or 'unknown'}",
                )
            )

    dkim = authentication.dkim
    if dkim.available == "available" and dkim.result == "fail":
        points += _DKIM_FAIL_POINTS
        signals.append(
            ContributingSignal(
                name="dkim_failure",
                category="authentication_failure",
                source="authentication",
                points=_DKIM_FAIL_POINTS,
                detail=f"dkim_result=fail; domain={dkim.domain or 'unknown'}",
            )
        )

    return points, signals


def _mailbox_domain(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    domain = address.rpartition("@")[2].strip().strip(".").strip(">").casefold()
    return domain or None


def _header_signals(evidence: EmailEvidence) -> tuple[float, list[ContributingSignal]]:
    points = 0.0
    signals: list[ContributingSignal] = []

    sender_domain = _mailbox_domain(evidence.sender.address if evidence.sender else None)
    reply_domain = None
    for address in evidence.message.reply_to:
        if address.address:
            reply_domain = _mailbox_domain(address.address)
            break
    if sender_domain and reply_domain and reply_domain != sender_domain:
        points += _REPLY_TO_MISMATCH_POINTS
        signals.append(
            ContributingSignal(
                name="reply_to_domain_mismatch",
                category="sender_impersonation",
                source="header",
                points=_REPLY_TO_MISMATCH_POINTS,
                detail=(
                    f"from_domain={sender_domain}; reply_to_domain={reply_domain}"
                ),
            )
        )

    return_path_domain = _mailbox_domain(
        (evidence.message.return_path or "").strip().strip("<>")
    )
    if sender_domain and return_path_domain and return_path_domain != sender_domain:
        points += _RETURN_PATH_MISMATCH_POINTS
        signals.append(
            ContributingSignal(
                name="return_path_mismatch",
                category="sender_impersonation",
                source="header",
                points=_RETURN_PATH_MISMATCH_POINTS,
                detail=(
                    f"from_domain={sender_domain}; "
                    f"return_path_domain={return_path_domain}"
                ),
            )
        )

    message_id = evidence.message.message_id
    if message_id:
        inner = message_id.strip().strip("<>").strip()
        mid_domain = _mailbox_domain(inner) if "@" in inner else None
        if sender_domain and mid_domain and mid_domain != sender_domain:
            points += _MESSAGE_ID_MISMATCH_POINTS
            signals.append(
                ContributingSignal(
                    name="message_id_domain_mismatch",
                    category="sender_impersonation",
                    source="header",
                    points=_MESSAGE_ID_MISMATCH_POINTS,
                    detail=(
                        f"from_domain={sender_domain}; message_id_domain={mid_domain}"
                    ),
                )
            )
    else:
        points += _MESSAGE_ID_MISSING_POINTS
        signals.append(
            ContributingSignal(
                name="message_id_missing",
                category="suspicious_links",
                source="header",
                points=_MESSAGE_ID_MISSING_POINTS,
                detail="message_id=missing",
            )
        )

    if not evidence.message.date:
        points += _DATE_MISSING_POINTS
        signals.append(
            ContributingSignal(
                name="date_missing",
                category="sender_impersonation",
                source="header",
                points=_DATE_MISSING_POINTS,
                detail="date=missing",
            )
        )

    if evidence.parser_defects:
        points += _PARSER_DEFECT_POINTS
        signals.append(
            ContributingSignal(
                name="parser_defects_present",
                category="sender_impersonation",
                source="header",
                points=_PARSER_DEFECT_POINTS,
                detail=f"parser_defect_count={len(evidence.parser_defects)}",
            )
        )

    return points, signals


def _url_signals(
    evidence: EmailEvidence,
    features: FeatureVector,
) -> tuple[float, list[ContributingSignal]]:
    points = 0.0
    signals: list[ContributingSignal] = []

    ip_urls = features.url.ip_url_count
    if ip_urls > 0:
        url_points = min(_IP_URL_POINTS_CAP, ip_urls * _IP_URL_POINTS_EACH)
        points += url_points
        signals.append(
            ContributingSignal(
                name="ip_literal_urls",
                category="suspicious_links",
                source="url",
                points=url_points,
                detail=f"ip_url_count={ip_urls}",
            )
        )

    mismatch_count = features.url.url_registered_domain_mismatch_count
    if mismatch_count > 0:
        url_points = min(
            _OFFSITE_DOMAIN_POINTS_CAP, mismatch_count * _OFFSITE_DOMAIN_POINTS_EACH
        )
        points += url_points
        signals.append(
            ContributingSignal(
                name="offsite_link_domains",
                category="suspicious_links",
                source="url",
                points=url_points,
                detail=(
                    f"url_registered_domain_mismatch_count={mismatch_count}"
                ),
            )
        )

    odd_ports = features.url.suspicious_port_count
    if odd_ports > 0:
        url_points = min(_ODD_PORT_POINTS_CAP, odd_ports * _ODD_PORT_POINTS_EACH)
        points += url_points
        signals.append(
            ContributingSignal(
                name="nonstandard_url_ports",
                category="suspicious_links",
                source="url",
                points=url_points,
                detail=f"suspicious_port_count={odd_ports}",
            )
        )

    return points, signals


def _intelligence_signals(
    features: FeatureVector,
) -> tuple[float, list[ContributingSignal]]:
    points = 0.0
    signals: list[ContributingSignal] = []

    age = features.intelligence.min_domain_age_days
    if age >= 0:
        if age < _YOUNG_DOMAIN_DAYS:
            points += _YOUNG_DOMAIN_POINTS
            signals.append(
                ContributingSignal(
                    name="young_linked_domain",
                    category="young_infrastructure",
                    source="intelligence",
                    points=_YOUNG_DOMAIN_POINTS,
                    detail=f"min_domain_age_days={age:.1f}",
                )
            )
        elif age < _MID_DOMAIN_DAYS:
            points += _MID_DOMAIN_POINTS
            signals.append(
                ContributingSignal(
                    name="recently_registered_domain",
                    category="young_infrastructure",
                    source="intelligence",
                    points=_MID_DOMAIN_POINTS,
                    detail=f"min_domain_age_days={age:.1f}",
                )
            )

    return points, signals


def _text_signals(
    features: FeatureVector,
) -> tuple[float, list[ContributingSignal]]:
    points = 0.0
    signals: list[ContributingSignal] = []

    if features.text.credential_signal_count > 0:
        points += _CREDENTIAL_TEXT_POINTS
        signals.append(
            ContributingSignal(
                name="credential_keywords",
                category="credential_harvesting",
                source="text",
                points=_CREDENTIAL_TEXT_POINTS,
                detail=(
                    f"credential_signal_count={features.text.credential_signal_count}"
                ),
            )
        )

    if features.text.payment_signal_count > 0:
        points += _PAYMENT_TEXT_POINTS
        signals.append(
            ContributingSignal(
                name="payment_keywords",
                category="payment_fraud",
                source="text",
                points=_PAYMENT_TEXT_POINTS,
                detail=f"payment_signal_count={features.text.payment_signal_count}",
            )
        )

    if features.text.urgency_signal_count > 0:
        points += _URGENCY_TEXT_POINTS
        signals.append(
            ContributingSignal(
                name="urgency_keywords",
                category="urgency_pressure",
                source="text",
                points=_URGENCY_TEXT_POINTS,
                detail=f"urgency_signal_count={features.text.urgency_signal_count}",
            )
        )

    return points, signals


# ---------------------------------------------------------------------------
# Verdict / severity / confidence / threat types.
# ---------------------------------------------------------------------------


def _verdict(
    score: float,
    *,
    model_available: bool,
    auth_available: bool,
) -> RiskVerdict:
    if not model_available and not auth_available:
        return "inconclusive"
    if score >= _MALICIOUS_THRESHOLD:
        return "malicious"
    if score >= _SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "benign"


def _severity(verdict: RiskVerdict, score: float) -> RiskSeverity:
    if verdict == "inconclusive":
        return "info"
    if verdict == "malicious":
        return "critical" if score >= 90.0 else "high"
    if verdict == "suspicious":
        return "medium" if score >= _MEDIUM_SEVERITY_THRESHOLD else "low"
    return "low" if score >= _INFO_SEVERITY_THRESHOLD else "info"


def _confidence(
    ai: AIAnalysis,
    authentication: AuthenticationEvidence | None,
    intelligence: IntelligenceEvidence | None,
) -> float:
    confidence = _CONFIDENCE_BASE
    if ai.nlp.available:
        confidence += _CONFIDENCE_NLP
    if ai.technical_ml.available:
        confidence += _CONFIDENCE_TECHNICAL
    if ai.fusion.available:
        confidence += _CONFIDENCE_FUSION
    if authentication is not None and authentication.dmarc.available == "available":
        confidence += _CONFIDENCE_AUTH
    if intelligence is not None and (
        intelligence.counts.get("dns_success", 0) > 0
        or intelligence.counts.get("rdap_success", 0) > 0
        or intelligence.counts.get("geoip_available", 0) > 0
    ):
        confidence += _CONFIDENCE_INTELLIGENCE
    nlp_p = _suspicious_probability(ai.nlp.probabilities) if ai.nlp.available else None
    tech_p = (
        _suspicious_probability(ai.technical_ml.probabilities)
        if ai.technical_ml.available
        else None
    )
    if nlp_p is not None and tech_p is not None and abs(nlp_p - tech_p) < _AGREEMENT_DELTA:
        confidence += _CONFIDENCE_AGREEMENT
    return round(min(_CONFIDENCE_CAP, confidence), 4)


_THREAT_PRIORITY: tuple[ThreatType, ...] = (
    "credential_harvesting",
    "payment_fraud",
    "sender_impersonation",
    "authentication_failure",
    "suspicious_links",
    "young_infrastructure",
    "urgency_pressure",
    "model_flagged",
)


def _threat_types(signals: list[ContributingSignal]) -> tuple[ThreatType | None, list[ThreatType]]:
    present = {signal.category for signal in signals}
    ordered = [t for t in _THREAT_PRIORITY if t in present]
    primary = ordered[0] if ordered else None
    return primary, ordered


# ---------------------------------------------------------------------------
# Public entry point.
# ---------------------------------------------------------------------------


def assess_risk(
    evidence: EmailEvidence,
    ai: AIAnalysis,
    authentication: AuthenticationEvidence | None = None,
    intelligence: IntelligenceEvidence | None = None,
    *,
    features: FeatureVector | None = None,
) -> RiskAssessment:
    """Compute the deterministic V1 risk assessment; total function.

    ``features`` may be passed to avoid recomputing the deterministic feature
    vector; when omitted it is rebuilt locally (pure, no network, no clock).
    """

    if features is None:
        url_intelligence = list(intelligence.urls) if intelligence is not None else None
        try:
            features = build_feature_vector(
                evidence, authentication, intelligence, url_intelligence=url_intelligence
            )
        except Exception:  # noqa: BLE001 - risk assessment must never raise
            features = FeatureVector()

    limitations: list[str] = []
    reasons: list[str] = []

    model_points, model_signal_list, model_contributions = _model_signals(ai)
    auth_points, auth_signal_list = _authentication_signals(authentication)
    header_points, header_signal_list = _header_signals(evidence)
    url_points, url_signal_list = _url_signals(evidence, features)
    intel_points, intel_signal_list = _intelligence_signals(features)
    text_points, text_signal_list = _text_signals(features)

    all_signals = [
        *model_signal_list,
        *auth_signal_list,
        *header_signal_list,
        *url_signal_list,
        *intel_signal_list,
        *text_signal_list,
    ][:_MAX_SIGNALS]

    raw_score = (
        model_points
        + auth_points
        + header_points
        + url_points
        + intel_points
        + text_points
    )
    score = round(min(_CAP, raw_score), 2)

    model_available = ai.nlp.available or ai.technical_ml.available or ai.fusion.available
    auth_available = (
        authentication is not None
        and authentication.dmarc.available == "available"
        or (
            authentication is not None
            and authentication.spf.available == "available"
        )
    )
    verdict = _verdict(
        score, model_available=model_available, auth_available=auth_available
    )
    severity = _severity(verdict, score)
    confidence = _confidence(ai, authentication, intelligence)
    primary_threat, threat_types = _threat_types(all_signals)

    # Reasons: deterministic, evidence-anchored, grouped by layer.
    if model_points > 0:
        reasons.append(
            f"AI model evidence contributed {model_points:g} of {score:g} risk points."
        )
    if auth_points > 0:
        reasons.append(
            f"Authentication failures contributed {auth_points:g} risk points."
        )
    if header_points > 0:
        reasons.append(
            f"Header anomalies contributed {header_points:g} risk points."
        )
    if url_points > 0:
        reasons.append(f"URL indicators contributed {url_points:g} risk points.")
    if intel_points > 0:
        reasons.append(
            f"Infrastructure intelligence contributed {intel_points:g} risk points."
        )
    if text_points > 0:
        reasons.append(f"Text keyword signals contributed {text_points:g} risk points.")
    if not reasons:
        reasons.append(
            "No weighted risk signals were present in the available evidence."
        )

    # Limitations: every missing critical evidence source is explicit.
    if not model_available:
        limitations.append(
            "No AI model produced usable evidence; the score rests on "
            "non-model evidence only."
        )
    else:
        if not ai.nlp.available:
            limitations.append("The NLP model was unavailable; text-based model evidence is missing.")
        if not ai.technical_ml.available:
            limitations.append(
                "The technical-ML model was unavailable; structural model evidence is missing."
            )
    if authentication is None or (
        authentication.dmarc.available != "available"
        and authentication.spf.available != "available"
    ):
        limitations.append(
            "Authentication (SPF/DKIM/DMARC) results were unavailable; "
            "authentication evidence contributes nothing to this assessment."
        )
    if intelligence is None or (
        intelligence.counts.get("dns_success", 0) == 0
        and intelligence.counts.get("rdap_success", 0) == 0
    ):
        limitations.append(
            "Infrastructure intelligence produced no successful lookups; "
            "domain-age and DNS evidence are missing."
        )
    limitations.append(
        "V1 risk scoring is a documented heuristic composite, not a validated "
        "real-world detection benchmark; model inputs come from project-"
        "internal datasets (DeBERTa V2 synthetic; technical V1)."
    )

    return RiskAssessment(
        risk_score=score,
        verdict=verdict,
        severity=severity,
        confidence=confidence,
        primary_threat_type=primary_threat,
        threat_types=threat_types,
        reasons=reasons,
        contributing_signals=all_signals,
        model_contributions=model_contributions,
        limitations=limitations,
        thresholds={
            "suspicious": _SUSPICIOUS_THRESHOLD,
            "malicious": _MALICIOUS_THRESHOLD,
            "medium_severity": _MEDIUM_SEVERITY_THRESHOLD,
            "info_severity": _INFO_SEVERITY_THRESHOLD,
        },
    )


__all__ = ["assess_risk"]
