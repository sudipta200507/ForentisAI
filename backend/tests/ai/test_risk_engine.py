"""Phase 3 risk-engine tests: determinism, thresholds, degradation, guards."""

from __future__ import annotations

import pytest

from app.ai.risk.scorer import assess_risk
from app.schemas.ai import AIAnalysis
from app.schemas.authentication import (
    AuthenticationEvidence,
    DkimEvidence,
    DmarcEvidence,
    SpfEvidence,
)
from app.schemas.email import (
    EmailAddress,
    EmailBody,
    EmailEvidence,
    FileMetadata,
    HeaderSummary,
    MessageMetadata,
    RecipientGroups,
    URLIndicator,
)
from app.schemas.features import FeatureVector

from ai_fixtures.helpers import intelligence_with_domain_ages, make_nlp_result, make_technical_result


def _evidence(
    *,
    sender: str | None = "alice@example.test",
    reply_to: list[str] | None = None,
    return_path: str | None = None,
    message_id: str | None = "<abc@example.test>",
    date: str | None = "Mon, 01 Sep 2026 10:00:00 +0000",
    urls: list[URLIndicator] | None = None,
    body_text: str = "Meeting notes from today.",
) -> EmailEvidence:
    return EmailEvidence(
        file=FileMetadata(
            filename="test.eml", size=256, sha256="b" * 64, source_format="eml"
        ),
        message=MessageMetadata(
            subject="Notes",
            date=date,
            message_id=message_id,
            reply_to=[EmailAddress(address=a) for a in (reply_to or [])],
            return_path=return_path,
        ),
        sender=EmailAddress(address=sender) if sender else None,
        recipients=RecipientGroups(),
        body=EmailBody(plain_text=body_text),
        headers=HeaderSummary(),
        urls=urls or [],
    )


def _auth(
    *,
    spf: str = "pass",
    dkim: str = "pass",
    dmarc: str = "pass",
) -> AuthenticationEvidence:
    return AuthenticationEvidence(
        spf=SpfEvidence(result=spf, available="available", domain="example.test"),
        dkim=DkimEvidence(result=dkim, available="available", domain="example.test"),
        dmarc=DmarcEvidence(result=dmarc, available="available", domain="example.test"),
    )


def _ai(
    *,
    nlp_susp: float | None = None,
    tech_susp: float | None = None,
) -> AIAnalysis:
    nlp = (
        make_nlp_result(suspicious=nlp_susp, benign=1 - nlp_susp)
        if nlp_susp is not None
        else make_nlp_result(available=False)
    )
    technical = (
        make_technical_result(suspicious=tech_susp, benign=1 - tech_susp)
        if tech_susp is not None
        else make_technical_result(available=False)
    )
    from app.ai.fusion.classifier import fuse

    return AIAnalysis(
        status="available" if (nlp.available or technical.available) else "unavailable",
        nlp=nlp,
        technical_ml=technical,
        fusion=fuse(nlp, technical),
    )


# ---------------------------------------------------------------------------
# Clean baseline
# ---------------------------------------------------------------------------


def test_clean_email_scores_low_and_benign():
    risk = assess_risk(_evidence(), _ai(), _auth())
    assert risk.risk_score == 0.0
    assert risk.verdict == "benign"
    assert risk.severity == "info"
    assert risk.primary_threat_type is None
    assert risk.threat_types == []


def test_risk_score_is_bounded():
    risk = assess_risk(
        _evidence(
            reply_to=["x@evil.example"],
            urls=[
                URLIndicator(url="http://203.0.113.5/a", source="plain"),
                URLIndicator(url="http://203.0.113.6/b", source="plain"),
                URLIndicator(url="http://203.0.113.7/c", source="plain"),
            ],
            body_text="verify your password urgent wire transfer invoice now",
        ),
        _ai(nlp_susp=1.0, tech_susp=1.0),
        _auth(spf="fail", dkim="fail", dmarc="reject"),
        intelligence_with_domain_ages([5.0]),
    )
    assert 0.0 <= risk.risk_score <= 100.0
    assert risk.verdict == "malicious"
    assert risk.severity in {"high", "critical"}


# ---------------------------------------------------------------------------
# Model probability is NOT the risk score
# ---------------------------------------------------------------------------


def test_model_probability_is_distinct_from_risk_score():
    """A p=1.0 model with zero corroboration must NOT score 100."""

    risk = assess_risk(_evidence(), _ai(nlp_susp=1.0), None)
    # 20 (NLP) + 10 (fusion) = 30 points max from a single model source.
    assert risk.risk_score < 45.0
    assert risk.verdict == "benign"
    # The raw probability is reported separately.
    nlp_contribution = next(
        c for c in risk.model_contributions if c.component == "nlp"
    )
    assert nlp_contribution.suspicious_probability == 1.0
    assert nlp_contribution.points == 20.0


def test_both_models_at_max_without_corroboration_stay_suspicious():
    risk = assess_risk(_evidence(), _ai(nlp_susp=1.0, tech_susp=1.0), None)
    assert risk.risk_score == 45.0
    assert risk.verdict == "suspicious"
    assert risk.severity == "low"  # below the medium threshold of 60


# ---------------------------------------------------------------------------
# Verdict thresholds
# ---------------------------------------------------------------------------


def test_suspicious_threshold_boundary():
    # 45 points exactly: models maxed (45) → suspicious.
    risk = assess_risk(_evidence(), _ai(nlp_susp=1.0, tech_susp=1.0), None)
    assert risk.risk_score == 45.0
    assert risk.verdict == "suspicious"


def test_malicious_threshold_boundary():
    # 45 model + 21 auth (10+6+5) + 6 reply-to + 2 urgency + 1 date = 75.
    risk = assess_risk(
        _evidence(
            reply_to=["boss@evil.example"],
            date=None,
            body_text="urgent action required",
        ),
        _ai(nlp_susp=1.0, tech_susp=1.0),
        _auth(spf="fail", dkim="fail", dmarc="reject"),
    )
    assert risk.risk_score == 75.0
    assert risk.verdict == "malicious"
    assert risk.severity == "high"


# ---------------------------------------------------------------------------
# Authentication evidence
# ---------------------------------------------------------------------------


def test_authentication_pass_scores_zero():
    risk = assess_risk(_evidence(), _ai(), _auth())
    auth_signals = [s for s in risk.contributing_signals if s.source == "authentication"]
    assert auth_signals == []


def test_dmarc_fail_scores():
    risk = assess_risk(_evidence(), _ai(), _auth(dmarc="fail"))
    assert any(s.name == "dmarc_failure" for s in risk.contributing_signals)
    assert risk.risk_score == 8.0


def test_dmarc_reject_outweighs_fail():
    reject = assess_risk(_evidence(), _ai(), _auth(dmarc="reject"))
    fail = assess_risk(_evidence(), _ai(), _auth(dmarc="fail"))
    assert reject.risk_score > fail.risk_score


# ---------------------------------------------------------------------------
# Header anomalies
# ---------------------------------------------------------------------------


def test_reply_to_mismatch_scores():
    risk = assess_risk(
        _evidence(reply_to=["boss@evil.example"]), _ai(), _auth()
    )
    assert any(
        s.name == "reply_to_domain_mismatch" and s.category == "sender_impersonation"
        for s in risk.contributing_signals
    )
    assert risk.risk_score == 6.0


def test_header_anomalies_stack():
    risk = assess_risk(
        _evidence(
            reply_to=["x@evil.example"],
            return_path="<bounce@other.example>",
            message_id=None,
            date=None,
        ),
        _ai(),
        _auth(),
    )
    # 6 + 3 + 1 + 1 = 11
    assert risk.risk_score == 11.0


# ---------------------------------------------------------------------------
# URL + intelligence signals
# ---------------------------------------------------------------------------


def test_ip_urls_score_with_cap():
    risk = assess_risk(
        _evidence(
            urls=[
                URLIndicator(url=f"http://203.0.113.{i}/x", source="plain")
                for i in range(5)
            ]
        ),
        _ai(),
        _auth(),
    )
    # 4 each capped at 8 (2 URLs' worth) = 8
    assert risk.risk_score == 8.0
    assert any(s.name == "ip_literal_urls" for s in risk.contributing_signals)


def test_young_domain_scores_more_than_old_domain():
    young = assess_risk(
        _evidence(), _ai(), _auth(), intelligence_with_domain_ages([5.0])
    )
    old = assess_risk(
        _evidence(), _ai(), _auth(), intelligence_with_domain_ages([2000.0])
    )
    assert young.risk_score == 6.0
    assert old.risk_score == 0.0
    assert old.contributing_signals == []


# ---------------------------------------------------------------------------
# Inconclusive path + confidence degradation
# ---------------------------------------------------------------------------


def test_no_models_no_auth_is_inconclusive():
    risk = assess_risk(_evidence(), _ai(), None)
    assert risk.verdict == "inconclusive"
    assert risk.severity == "info"
    assert risk.confidence <= 0.5
    assert any("No AI model" in lim for lim in risk.limitations)
    assert any("Authentication" in lim for lim in risk.limitations)


def test_models_present_but_auth_missing_is_not_inconclusive():
    risk = assess_risk(_evidence(), _ai(nlp_susp=0.9), None)
    assert risk.verdict in {"benign", "suspicious", "malicious"}
    assert any("Authentication" in lim for lim in risk.limitations)


def test_confidence_degrades_when_evidence_missing():
    full = assess_risk(_evidence(), _ai(nlp_susp=0.5, tech_susp=0.5), _auth(),
                       intelligence_with_domain_ages([10.0]))
    partial = assess_risk(_evidence(), _ai(nlp_susp=0.5, tech_susp=0.5), None, None)
    assert full.confidence > partial.confidence


def test_model_agreement_raises_confidence():
    agree = assess_risk(_evidence(), _ai(nlp_susp=0.5, tech_susp=0.5), _auth())
    disagree = assess_risk(_evidence(), _ai(nlp_susp=0.95, tech_susp=0.05), _auth())
    assert agree.confidence > disagree.confidence


def test_confidence_is_capped():
    risk = assess_risk(
        _evidence(),
        _ai(nlp_susp=0.5, tech_susp=0.5),
        _auth(),
        intelligence_with_domain_ages([10.0]),
    )
    assert risk.confidence <= 0.95


# ---------------------------------------------------------------------------
# Threat types
# ---------------------------------------------------------------------------


def test_threat_type_priority_credential_first():
    risk = assess_risk(
        _evidence(body_text="please verify your password urgently"),
        _ai(),
        _auth(),
    )
    assert risk.primary_threat_type == "credential_harvesting"
    assert "urgency_pressure" in risk.threat_types


def test_model_only_threat_type():
    risk = assess_risk(_evidence(), _ai(nlp_susp=0.9), None)
    assert "model_flagged" in risk.threat_types


def test_sender_impersonation_beats_model_flagged():
    risk = assess_risk(
        _evidence(reply_to=["x@evil.example"]), _ai(nlp_susp=0.9), _auth()
    )
    assert risk.primary_threat_type == "sender_impersonation"


# ---------------------------------------------------------------------------
# Guards: attribution, privacy, determinism
# ---------------------------------------------------------------------------


def test_no_attacker_attribution_language():
    risk = assess_risk(
        _evidence(),
        _ai(nlp_susp=0.9, tech_susp=0.9),
        _auth(spf="fail", dkim="fail", dmarc="reject"),
        intelligence_with_domain_ages([5.0]),
    )
    blob = " ".join(risk.reasons + risk.limitations + [s.detail for s in risk.contributing_signals]).lower()
    assert "attacker" not in blob
    assert "criminal" not in blob


def test_assessment_is_deterministic():
    args = (
        _evidence(reply_to=["x@evil.example"]),
        _ai(nlp_susp=0.7, tech_susp=0.4),
        _auth(spf="softfail"),
        intelligence_with_domain_ages([45.0]),
    )
    a = assess_risk(*args)
    b = assess_risk(*args)
    assert a.model_dump_json() == b.model_dump_json()


def test_thresholds_documented_in_output():
    risk = assess_risk(_evidence(), _ai(), _auth())
    assert risk.thresholds["suspicious"] == 45.0
    assert risk.thresholds["malicious"] == 75.0


def test_no_raw_body_text_in_signal_details():
    secret_phrase = "zzqq-unique-body-token"
    risk = assess_risk(
        _evidence(body_text=f"hello {secret_phrase} verify your password"),
        _ai(nlp_susp=0.9),
        _auth(),
    )
    blob = " ".join(
        [s.detail for s in risk.contributing_signals] + risk.reasons + risk.limitations
    )
    assert secret_phrase not in blob


def test_text_signals_stack():
    risk = assess_risk(
        _evidence(body_text="verify your password, send the wire transfer invoice urgently"),
        _ai(),
        _auth(),
    )
    # 5 (credential) + 3 (payment) + 2 (urgency) = 10
    assert risk.risk_score == 10.0


def test_features_override_is_respected():
    features = FeatureVector()
    features.url.ip_url_count = 1
    risk = assess_risk(_evidence(), _ai(), _auth(), features=features)
    assert risk.risk_score == 4.0


def test_synthetic_dataset_limitation_always_present():
    risk = assess_risk(_evidence(), _ai(), _auth())
    assert any("synthetic" in lim or "not a validated" in lim for lim in risk.limitations)
