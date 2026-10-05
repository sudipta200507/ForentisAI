"""Structured evidence-based explanations (Phase 2 completion).

Tests for ``app.ai.explainability.structured`` and its wiring into the AI
orchestrator. Guarantees under test:

- every explanation carries a stable category, a coarse impact, and a short
  factual ``evidence`` anchor (indicator values, never raw body text);
- model outputs are restated as MODEL ASSESSMENTS, never as exact transformer
  token attributions;
- unavailable models contribute no fabricated entries;
- output is deterministic, sorted high-impact-first, and capped;
- the orchestrator populates ``Explainability.explanations``.
"""

from __future__ import annotations

import pytest

from app.ai.explainability.structured import build_structured_explanations
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
from app.schemas.ai import NLPResult, TechnicalMLResult

from ai_fixtures.helpers import (
    intelligence_with_domain_ages,
    make_nlp_result,
    make_technical_result,
    sample_evidence,
)


def _make_evidence(
    *,
    sender: str | None = "alice@example.test",
    reply_to: list[str] | None = None,
    return_path: str | None = "<alice@example.test>",
    message_id: str | None = "<abc123@example.test>",
    date: str | None = "Mon, 01 Sep 2026 10:00:00 +0000",
    received_count: int = 2,
    urls: list[URLIndicator] | None = None,
) -> EmailEvidence:
    message = MessageMetadata(
        subject="Hello",
        date=date,
        message_id=message_id,
        reply_to=[EmailAddress(address=a) for a in (reply_to or [])],
        return_path=return_path,
    )
    return EmailEvidence(
        file=FileMetadata(
            filename="test.eml", size=128, sha256="a" * 64, source_format="eml"
        ),
        message=message,
        sender=EmailAddress(address=sender) if sender else None,
        recipients=RecipientGroups(),
        body=EmailBody(plain_text="Hello there"),
        headers=HeaderSummary(),
        received_chain=[f"line {i}" for i in range(received_count)],
        urls=urls or [],
    )


def _authentication(
    *,
    spf: str = "pass",
    dkim: str = "pass",
    dmarc: str = "pass",
) -> AuthenticationEvidence:
    return AuthenticationEvidence(
        spf=SpfEvidence(result=spf, available="available", domain="example.test"),
        dkim=DkimEvidence(result=dkim, available="available", domain="example.test"),
        dmarc=DmarcEvidence(
            result=dmarc, available="available", domain="example.test", policy="reject"
        ),
    )


# ---------------------------------------------------------------------------
# Model assessments
# ---------------------------------------------------------------------------


def test_nlp_suspicious_produces_model_assessment_entry():
    nlp = make_nlp_result(suspicious=0.9, benign=0.1)
    entries = build_structured_explanations(
        _make_evidence(), None, None, nlp, make_technical_result(available=False),
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(nlp, make_technical_result(available=False)),
    )
    assessments = [e for e in entries if e.category == "model_assessment"]
    assert len(assessments) == 1
    assert "NLP model" in assessments[0].reason
    assert assessments[0].evidence.startswith("nlp.suspicious_probability=")


def test_nlp_benign_produces_no_nlp_entry():
    nlp = make_nlp_result(suspicious=0.1, benign=0.9)
    technical = make_technical_result(available=False)
    entries = build_structured_explanations(
        _make_evidence(), None, None, nlp, technical,
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(nlp, technical),
    )
    assert not [e for e in entries if e.category == "model_assessment"]


def test_technical_model_assessment_includes_threshold():
    nlp = make_nlp_result(available=False)
    technical = make_technical_result(suspicious=0.8, benign=0.2)
    technical.threshold = 0.33
    entries = build_structured_explanations(
        _make_evidence(), None, None, nlp, technical,
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(nlp, technical),
    )
    assessments = [e for e in entries if e.category == "model_assessment"]
    assert len(assessments) == 1
    assert "threshold 0.33" in assessments[0].reason
    assert "Random Forest" in assessments[0].reason


def test_unavailable_models_contribute_no_entries():
    nlp = make_nlp_result(available=False)
    technical = make_technical_result(available=False)
    # Evidence still contains real header/URL anomalies to explain.
    evidence = _make_evidence(
        reply_to=["attacker@evil.example"],
        urls=[URLIndicator(url="http://203.0.113.9/login", source="plain")],
    )
    entries = build_structured_explanations(
        evidence, None, None, nlp, technical,
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(nlp, technical),
    )
    assert not [e for e in entries if e.category == "model_assessment"]
    # Real evidence entries were still produced (no fabricated model output).
    assert any(e.category == "sender_mismatch" for e in entries)
    assert any(e.category == "suspicious_url" for e in entries)


def test_no_token_attribution_claim_in_wording():
    nlp = make_nlp_result(suspicious=0.95, benign=0.05)
    technical = make_technical_result(suspicious=0.8, benign=0.2)
    entries = build_structured_explanations(
        _make_evidence(), None, None, nlp, technical,
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(nlp, technical),
    )
    for entry in entries:
        text = (entry.reason + " " + entry.evidence).lower()
        assert "token" not in text
        assert "attribution" not in text
        assert "confirmed" not in text


# ---------------------------------------------------------------------------
# Header evidence
# ---------------------------------------------------------------------------


def test_reply_to_domain_mismatch_is_high_impact():
    evidence = _make_evidence(reply_to=["attacker@evil.example"])
    entries = build_structured_explanations(
        evidence, None, None, make_nlp_result(available=False),
        make_technical_result(available=False),
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(
            make_nlp_result(available=False), make_technical_result(available=False)
        ),
    )
    mismatches = [e for e in entries if e.category == "sender_mismatch"]
    assert any("Reply-To" in e.reason for e in mismatches)
    assert any(
        "from_domain=example.test" in e.evidence and "reply_to_domain=evil.example" in e.evidence
        for e in mismatches
    )
    assert any(e.impact == "high" for e in mismatches)


def test_return_path_mismatch_detected():
    evidence = _make_evidence(return_path="<bounce@other.example>")
    entries = build_structured_explanations(
        evidence, None, None, make_nlp_result(available=False),
        make_technical_result(available=False),
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(
            make_nlp_result(available=False), make_technical_result(available=False)
        ),
    )
    assert any(
        "Return-Path" in e.reason and e.evidence.startswith("from_domain=example.test")
        for e in entries
    )


def test_message_id_domain_mismatch_detected():
    evidence = _make_evidence(message_id="<xyz@unrelated.example>")
    entries = build_structured_explanations(
        evidence, None, None, make_nlp_result(available=False),
        make_technical_result(available=False),
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(
            make_nlp_result(available=False), make_technical_result(available=False)
        ),
    )
    assert any(
        e.category == "unusual_header_structure" and "Message-ID" in e.reason
        for e in entries
    )


def test_missing_structural_headers_reported():
    evidence = _make_evidence(message_id=None, date=None, received_count=0)
    entries = build_structured_explanations(
        evidence, None, None, make_nlp_result(available=False),
        make_technical_result(available=False),
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(
            make_nlp_result(available=False), make_technical_result(available=False)
        ),
    )
    evidence_bits = [e.evidence for e in entries]
    assert "message_id=missing" in evidence_bits
    assert "date=missing" in evidence_bits
    assert "received_hop_count=0" in evidence_bits


def test_matching_headers_produce_no_mismatch_entries():
    evidence = _make_evidence()
    entries = build_structured_explanations(
        evidence, None, None, make_nlp_result(available=False),
        make_technical_result(available=False),
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(
            make_nlp_result(available=False), make_technical_result(available=False)
        ),
    )
    assert not [e for e in entries if e.category == "sender_mismatch"]


# ---------------------------------------------------------------------------
# URL evidence
# ---------------------------------------------------------------------------


def test_ip_literal_url_flagged():
    evidence = _make_evidence(
        urls=[URLIndicator(url="http://203.0.113.9/login", source="plain")]
    )
    entries = build_structured_explanations(
        evidence, None, None, make_nlp_result(available=False),
        make_technical_result(available=False),
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(
            make_nlp_result(available=False), make_technical_result(available=False)
        ),
    )
    url_entries = [e for e in entries if e.category == "suspicious_url"]
    assert any("ip_literal_url_count=1" in e.evidence for e in url_entries)


def test_offsite_registered_domain_flagged():
    evidence = _make_evidence(
        urls=[URLIndicator(url="https://tracker.example.net/x", source="plain")]
    )
    entries = build_structured_explanations(
        evidence, None, None, make_nlp_result(available=False),
        make_technical_result(available=False),
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(
            make_nlp_result(available=False), make_technical_result(available=False)
        ),
    )
    assert any(
        "url_registered_domain_mismatch_count=1" in e.evidence for e in entries
    )


def test_same_domain_url_not_flagged():
    evidence = _make_evidence(
        urls=[URLIndicator(url="https://www.example.test/help", source="plain")]
    )
    entries = build_structured_explanations(
        evidence, None, None, make_nlp_result(available=False),
        make_technical_result(available=False),
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(
            make_nlp_result(available=False), make_technical_result(available=False)
        ),
    )
    assert not [e for e in entries if e.category == "suspicious_url"]


def test_odd_port_url_flagged_low_impact():
    evidence = _make_evidence(
        urls=[
            URLIndicator(url="https://www.example.test:8443/a", source="plain"),
            URLIndicator(url="https://www.example.test/help", source="plain"),
        ]
    )
    entries = build_structured_explanations(
        evidence, None, None, make_nlp_result(available=False),
        make_technical_result(available=False),
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(
            make_nlp_result(available=False), make_technical_result(available=False)
        ),
    )
    assert any("hosts_with_odd_ports=1" in e.evidence for e in entries)


# ---------------------------------------------------------------------------
# Authentication + intelligence evidence
# ---------------------------------------------------------------------------


def test_authentication_failures_reported():
    auth = _authentication(spf="fail", dkim="fail", dmarc="fail")
    entries = build_structured_explanations(
        _make_evidence(), auth, None, make_nlp_result(available=False),
        make_technical_result(available=False),
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(
            make_nlp_result(available=False), make_technical_result(available=False)
        ),
    )
    failures = [e for e in entries if e.category == "authentication_failure"]
    assert {e.evidence.split(";")[0] for e in failures} >= {
        "spf_result=fail",
        "dkim_result=fail",
        "dmarc_result=fail",
    }
    assert any(e.impact == "high" for e in failures)


def test_authentication_pass_produces_no_entries():
    auth = _authentication()
    entries = build_structured_explanations(
        _make_evidence(), auth, None, make_nlp_result(available=False),
        make_technical_result(available=False),
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(
            make_nlp_result(available=False), make_technical_result(available=False)
        ),
    )
    assert not [e for e in entries if e.category == "authentication_failure"]


def test_young_domain_intelligence_flagged():
    intelligence = intelligence_with_domain_ages([5.0])
    entries = build_structured_explanations(
        _make_evidence(), None, intelligence, make_nlp_result(available=False),
        make_technical_result(available=False),
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(
            make_nlp_result(available=False), make_technical_result(available=False)
        ),
    )
    infra = [e for e in entries if e.category == "unusual_infrastructure"]
    assert len(infra) == 1
    assert "youngest_domain_age_days=" in infra[0].evidence


def test_old_domain_produces_no_infrastructure_entry():
    intelligence = intelligence_with_domain_ages([2000.0])
    entries = build_structured_explanations(
        _make_evidence(), None, intelligence, make_nlp_result(available=False),
        make_technical_result(available=False),
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(
            make_nlp_result(available=False), make_technical_result(available=False)
        ),
    )
    assert not [e for e in entries if e.category == "unusual_infrastructure"]


# ---------------------------------------------------------------------------
# Ordering, capping, determinism
# ---------------------------------------------------------------------------


def test_entries_sorted_high_impact_first_and_capped():
    nlp = make_nlp_result(suspicious=0.99, benign=0.01)
    technical = make_technical_result(suspicious=0.99, benign=0.01)
    auth = _authentication(spf="fail", dkim="fail", dmarc="fail")
    evidence = _make_evidence(
        reply_to=["attacker@evil.example"],
        urls=[URLIndicator(url="http://203.0.113.9/login", source="plain")],
    )
    entries = build_structured_explanations(
        evidence, auth, None, nlp, technical,
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(nlp, technical),
    )
    assert len(entries) <= 12
    order = {"high": 0, "medium": 1, "low": 2}
    impacts = [order[e.impact] for e in entries]
    assert impacts == sorted(impacts)


def test_explanations_are_deterministic():
    nlp = make_nlp_result(suspicious=0.9, benign=0.1)
    technical = make_technical_result(suspicious=0.4, benign=0.6)
    evidence = _make_evidence(reply_to=["attacker@evil.example"])
    kwargs = (evidence, None, None, nlp, technical)
    fuse_fn = __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse
    a = build_structured_explanations(*kwargs, fuse_fn(nlp, technical))
    b = build_structured_explanations(*kwargs, fuse_fn(nlp, technical))
    assert [e.model_dump_json() for e in a] == [e.model_dump_json() for e in b]


def test_evidence_anchor_contains_no_raw_body_text():
    nlp = make_nlp_result(suspicious=0.9, benign=0.1)
    evidence = _make_evidence(reply_to=["attacker@evil.example"])
    entries = build_structured_explanations(
        evidence, None, None, nlp, make_technical_result(available=False),
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(
            nlp, make_technical_result(available=False)
        ),
    )
    for entry in entries:
        assert "Hello there" not in entry.evidence  # body text never leaks


# ---------------------------------------------------------------------------
# Orchestrator wiring
# ---------------------------------------------------------------------------


def test_orchestrator_populates_explanations(tmp_path):
    """The full AI pipeline must populate Explainability.explanations."""

    import numpy as np

    from app.ai import model_registry
    from app.ai.orchestrator import build_ai_analysis
    from app.ai.technical_ml.inference import vector_to_array
    from app.ai.technical_ml.model import build_pipeline
    from app.core.config import AISettings, DEFAULT_TECHNICAL_MODEL_FILENAME
    from ai_fixtures.helpers import make_technical_bundle, save_bundle, zero_vector

    model_path = tmp_path / "models" / DEFAULT_TECHNICAL_MODEL_FILENAME
    rng = np.random.default_rng(42)
    X = rng.normal(size=(60, len(vector_to_array(zero_vector())[0])))
    y = np.where(X[:, 0] > 0, "suspicious", "benign")
    pipeline = build_pipeline(n_estimators=10)
    pipeline.fit(X, y)
    save_bundle(make_technical_bundle(pipeline), model_path)

    settings = AISettings(
        ai_enabled=True,
        model_dir=tmp_path / "models",
        technical_model_path=model_path,
        nlp_model_path=None,
        max_text_length=2000,
        inference_timeout_seconds=10.0,
    )
    try:
        analysis = build_ai_analysis(
            sample_evidence(), None, None, settings=settings
        )
    finally:
        model_registry.clear_caches()

    assert analysis.technical_ml.available is True
    explanations = analysis.explainability.explanations
    assert len(explanations) > 0
    # The technical model contributed an assessment entry.
    assert any(
        e.category == "model_assessment" and "technical" in e.reason.lower()
        for e in explanations
    )
    # Every entry is fully populated.
    for entry in explanations:
        assert entry.reason and entry.category and entry.evidence
        assert entry.impact in {"low", "medium", "high"}


@pytest.mark.parametrize(
    "builder", ["_header_explanations", "_url_explanations"]
)
def test_builder_failure_is_isolated(monkeypatch, builder):
    """One broken builder must not abort the whole explanation build."""

    nlp = make_nlp_result(available=False)
    technical = make_technical_result(available=False)
    # Give BOTH remaining builders something to report so the surviving one
    # is observable regardless of which builder was disabled.
    evidence = _make_evidence(
        reply_to=["attacker@evil.example"],
        urls=[URLIndicator(url="http://203.0.113.9/login", source="plain")],
    )

    def _explode(*_args, **_kwargs):
        raise RuntimeError("builder exploded")

    monkeypatch.setattr(
        f"app.ai.explainability.structured.{builder}", _explode
    )
    entries = build_structured_explanations(
        evidence, None, None, nlp, technical,
        __import__("app.ai.fusion.classifier", fromlist=["fuse"]).fuse(nlp, technical),
    )
    # The surviving builder still produced entries.
    assert len(entries) >= 1
