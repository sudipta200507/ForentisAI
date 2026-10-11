"""Regression tests: DMARC authentication result vs published policy.

These tests pin the corrected behavior required after a real-world incident:
a legitimate Gmail message with valid SPF/DKIM/DMARC authentication whose
domain publishes ``p=quarantine`` received a negative DMARC signal because
Rspamd's ``DMARC_POLICY_QUARANTINE`` symbol (a FAILURE disposition) was
mistaken for the message's authentication result.

Invariants enforced here:

1. ``result`` is the authentication outcome for THIS message
   (pass/fail/none/unknown) and is derived only from Rspamd's evaluation;
2. ``policy`` is the sender domain's published policy, kept for forensic
   context, and never changes the authentication result;
3. risk scoring penalizes actual authentication failures, never a published
   policy by itself.
"""

from __future__ import annotations

import pytest

from app.ai.risk.scorer import assess_risk
from app.authentication.dmarc import build_authentication_evidence, normalize_dmarc
from app.schemas.ai import AIAnalysis
from app.schemas.authentication import RspamdAnalysis, RspamdSymbol
from app.schemas.email import (
    EmailAddress,
    EmailBody,
    EmailEvidence,
    FileMetadata,
    HeaderSummary,
    MessageMetadata,
    RecipientGroups,
)
from app.schemas.features import FeatureVector


def _rspamd(dmarc_symbol: str, *, domain: str | None = "example.test") -> RspamdAnalysis:
    options = [domain] if domain else []
    return RspamdAnalysis(
        scanned=True,
        symbols={dmarc_symbol: RspamdSymbol(score=0.0, options=options)},
    )


def _email_evidence() -> EmailEvidence:
    return EmailEvidence(
        file=FileMetadata(
            filename="test.eml", size=256, sha256="b" * 64, source_format="eml"
        ),
        message=MessageMetadata(
            subject="Hello",
            date="Mon, 01 Sep 2026 10:00:00 +0000",
            message_id="<abc@example.test>",
            reply_to=[],
            return_path=None,
        ),
        sender=EmailAddress(address="alice@example.test"),
        recipients=RecipientGroups(),
        body=EmailBody(plain_text="Hello team."),
        headers=HeaderSummary(),
        urls=[],
    )


def _unavailable_ai() -> AIAnalysis:
    return AIAnalysis()  # all components unavailable; isolates auth evidence


# ---------------------------------------------------------------------------
# 1-2. DMARC PASS with strict published policies (the incident scenario).
# ---------------------------------------------------------------------------


def test_dmarc_pass_with_quarantine_policy_is_pass_and_scores_zero() -> None:
    """ALLOW symbol under a p=quarantine domain: pass + policy quarantine."""

    analysis = _rspamd("DMARC_POLICY_ALLOW")
    evidence = build_authentication_evidence(analysis)

    assert evidence.dmarc.result == "pass"
    assert evidence.dmarc.policy is None  # symbol does not carry p= value
    assert evidence.dmarc.available == "available"

    risk = assess_risk(_email_evidence(), _unavailable_ai(), evidence)
    assert risk.risk_score == 0.0
    assert not any(
        s.source == "authentication" for s in risk.contributing_signals
    ), "a passing DMARC evaluation must never contribute risk points"


def test_dmarc_pass_with_reject_policy_is_pass_and_scores_zero() -> None:
    """ALLOW symbol under a p=reject domain: pass + policy unknown, 0 points."""

    analysis = _rspamd("DMARC_POLICY_ALLOW")
    evidence = build_authentication_evidence(analysis)

    assert evidence.dmarc.result == "pass"
    assert evidence.dmarc.policy != "reject"  # never fabricated from ALLOW

    risk = assess_risk(_email_evidence(), _unavailable_ai(), evidence)
    assert risk.risk_score == 0.0
    assert not any(
        s.source == "authentication" for s in risk.contributing_signals
    )


def test_published_policy_alone_never_creates_auth_signals() -> None:
    """Policy is forensic context: p=reject on evidence must not score."""

    from app.schemas.authentication import (
        AuthenticationEvidence,
        DkimEvidence,
        DmarcEvidence,
        SpfEvidence,
    )

    evidence = AuthenticationEvidence(
        spf=SpfEvidence(result="pass", available="available", domain="example.test"),
        dkim=DkimEvidence(result="pass", available="available", domain="example.test"),
        dmarc=DmarcEvidence(
            result="pass",
            available="available",
            domain="example.test",
            policy="reject",
        ),
    )
    risk = assess_risk(_email_evidence(), _unavailable_ai(), evidence)
    assert risk.risk_score == 0.0
    assert not any(
        s.source == "authentication" for s in risk.contributing_signals
    )


# ---------------------------------------------------------------------------
# 3-4. DMARC FAIL with strict published policies (disposition context kept).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("symbol", "expected_policy"),
    [
        ("DMARC_POLICY_QUARANTINE", "quarantine"),
        ("DMARC_POLICY_REJECT", "reject"),
    ],
)
def test_dmarc_fail_keeps_policy_and_scores_fail(
    symbol: str, expected_policy: str
) -> None:
    evidence = build_authentication_evidence(_rspamd(symbol))

    assert evidence.dmarc.result == "fail"
    assert evidence.dmarc.policy == expected_policy

    risk = assess_risk(_email_evidence(), _unavailable_ai(), evidence)
    auth_signals = [
        s for s in risk.contributing_signals if s.name == "dmarc_failure"
    ]
    assert len(auth_signals) == 1
    assert auth_signals[0].points == 8.0
    assert f"policy={expected_policy}" in auth_signals[0].detail
    assert risk.risk_score == 8.0


# ---------------------------------------------------------------------------
# 5. DMARC none (no published policy / DMARC_NA).
# ---------------------------------------------------------------------------


def test_dmarc_none_is_recorded_without_penalty_or_policy() -> None:
    evidence = build_authentication_evidence(_rspamd("DMARC_NA"))

    assert evidence.dmarc.result == "none"
    assert evidence.dmarc.available == "available"

    risk = assess_risk(_email_evidence(), _unavailable_ai(), evidence)
    assert not any(
        s.name == "dmarc_failure" for s in risk.contributing_signals
    ), "absence of a DMARC record is not an authentication failure"
    assert risk.risk_score == 0.0


# ---------------------------------------------------------------------------
# 6. Malformed / unknown DMARC output.
# ---------------------------------------------------------------------------


def test_unknown_dmarc_symbols_stay_unknown_and_available() -> None:
    evidence = normalize_dmarc(_rspamd("DMARC_FUTURE_UNKNOWN_SYMBOL"))

    assert evidence.result == "unknown"
    assert evidence.policy is None
    assert evidence.available == "available"  # a DMARC symbol WAS reported
    assert evidence.symbols == ["DMARC_FUTURE_UNKNOWN_SYMBOL"]


def test_missing_dmarc_symbol_is_unknown_and_unavailable() -> None:
    evidence = normalize_dmarc(
        RspamdAnalysis(scanned=True, symbols={"R_SPF_ALLOW": RspamdSymbol()})
    )

    assert evidence.result == "unknown"
    assert evidence.available == "unavailable"
    assert evidence.symbols == []


def test_malformed_dmarc_options_do_not_crash_or_invent_values() -> None:
    analysis = RspamdAnalysis(
        scanned=True,
        symbols={
            "DMARC_POLICY_QUARANTINE": RspamdSymbol(
                score=0.0, options=[";;", ",,,", "not-a-domain", "spf_aligned=???"]
            )
        },
    )
    evidence = build_authentication_evidence(analysis)

    assert evidence.dmarc.result == "fail"
    assert evidence.dmarc.policy == "quarantine"
    assert evidence.dmarc.spf_aligned is None  # garbage option never guessed
    assert evidence.dmarc.dkim_aligned is None


# ---------------------------------------------------------------------------
# Feature layer: the technical-model feature contract keys off the result.
# ---------------------------------------------------------------------------


def test_auth_features_use_result_not_policy() -> None:
    from app.features.auth_features import extract_auth_features

    # p=quarantine domain whose message PASSED: dmarc_pass=1, dmarc_fail=0.
    passing = build_authentication_evidence(_rspamd("DMARC_POLICY_ALLOW"))
    passing_features = extract_auth_features(passing)
    assert passing_features.dmarc_pass == 1
    assert passing_features.dmarc_fail == 0

    # p=quarantine domain whose message FAILED: dmarc_fail=1, dmarc_pass=0.
    failing = build_authentication_evidence(_rspamd("DMARC_POLICY_QUARANTINE"))
    failing_features = extract_auth_features(failing)
    assert failing_features.dmarc_fail == 1
    assert failing_features.dmarc_pass == 0
