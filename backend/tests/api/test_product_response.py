"""Phase 5 + 5A tests: product response composition and forensic evidence."""

from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient

from app.api import dependencies
from app.authentication.rspamd_client import RspamdConnectionError
from app.main import app as fastapi_app

from helpers import SAMPLE_EML

# An .eml with a two-hop Received chain. 93.184.216.34 is a globally routable
# address; TEST-NET ranges (192.0.2.x / 203.0.113.x) classify as non-public.
SAMPLE_EML_RECEIVED = (
    b"From: Alice Sender <alice@example.test>\r\n"
    b"To: Bob Recipient <bob@example.test>\r\n"
    b"Subject: API fixture\r\n"
    b"Date: Tue, 01 Apr 2025 10:30:00 +0000\r\n"
    b"Message-ID: <api-fixture@example.test>\r\n"
    b"Received: from relay.example.test (relay.example.test [10.0.0.9]) "
    b"by mailbox.example.test; Tue, 01 Apr 2025 10:31:00 +0000\r\n"
    b"Received: from sender.example.net (sender.example.net "
    b"[93.184.216.34]) by relay.example.test; "
    b"Tue, 01 Apr 2025 10:30:00 +0000\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Visit https://example.test/api-path for details.\r\n"
)


@pytest.fixture()
def ai_disabled(tmp_path):
    """Point the AI pipeline at an empty model dir for fast, isolated runs."""

    from app.core.config import AISettings

    settings = AISettings(
        ai_enabled=True,
        model_dir=tmp_path / "models",
        technical_model_path=tmp_path / "models" / "technical_model.joblib",
        nlp_model_path=None,
    )
    fastapi_app.dependency_overrides[dependencies.get_ai_settings] = lambda: settings
    yield
    fastapi_app.dependency_overrides.pop(dependencies.get_ai_settings, None)


def _post_email(client: TestClient, content: bytes = SAMPLE_EML):
    return client.post(
        "/analyze-email",
        files={"upload": ("upload.eml", io.BytesIO(content), "message/rfc822")},
    )


def _analyze(ai_disabled, content: bytes = SAMPLE_EML) -> dict:
    with TestClient(fastapi_app) as client:
        response = _post_email(client, content)
    assert response.status_code == 200
    return response.json()


# ---------------------------------------------------------------------------
# Product response composition (Phase 5)
# ---------------------------------------------------------------------------


def test_product_response_sections(ai_disabled) -> None:
    payload = _analyze(ai_disabled)
    assert set(payload) == {
        "schema_version",
        "analysis_id",
        "email",
        "authentication",
        "intelligence",
        "ai",
        "risk",
        "forensics",
        "metadata",
    }


def test_analysis_id_is_deterministic_uuid(ai_disabled) -> None:
    import uuid

    first = _analyze(ai_disabled)
    second = _analyze(ai_disabled)
    assert first["analysis_id"] == second["analysis_id"]
    parsed = uuid.UUID(first["analysis_id"])
    assert parsed.version == 5


def test_metadata_section(ai_disabled) -> None:
    payload = _analyze(ai_disabled)
    metadata = payload["metadata"]
    assert metadata["engine_version"]
    assert metadata["processing_time_ms"] >= 0.0
    # ISO-8601 timestamp with UTC offset.
    assert "T" in metadata["timestamp"]
    # With the AI disabled, model versions stay explicitly None.
    assert metadata["model_versions"]["nlp"] is None


def test_risk_section_shape(ai_disabled) -> None:
    payload = _analyze(ai_disabled)
    risk = payload["risk"]
    assert 0.0 <= risk["risk_score"] <= 100.0
    assert risk["verdict"] in {"benign", "suspicious", "malicious", "inconclusive"}
    assert risk["severity"] in {"info", "low", "medium", "high", "critical"}
    assert 0.0 <= risk["confidence"] <= 1.0
    assert isinstance(risk["reasons"], list)
    assert isinstance(risk["limitations"], list)
    assert risk["thresholds"]["suspicious"] == 45.0


def test_forensics_section_shape(ai_disabled) -> None:
    payload = _analyze(ai_disabled, SAMPLE_EML_RECEIVED)
    forensics = payload["forensics"]
    assert forensics["schema_version"] == "1.0"
    assert len(forensics["received_chain"]) == 2
    candidate = forensics["earliest_reliable_candidate"]
    assert candidate is not None
    assert candidate["label"] == "earliest observed sending infrastructure"
    assert candidate["status"] == "success"


def test_no_email_content_in_metadata_or_risk(ai_disabled) -> None:
    payload = _analyze(ai_disabled)
    blob = (
        str(payload["metadata"]) + str(payload["risk"]) + str(payload["forensics"])
    ).casefold()
    assert "alice@example.test" not in blob
    assert "api fixture" not in blob


# ---------------------------------------------------------------------------
# Forensic evidence details (Phase 5A)
# ---------------------------------------------------------------------------


def test_received_hop_parsing(ai_disabled) -> None:
    payload = _analyze(ai_disabled, SAMPLE_EML_RECEIVED)
    hops = payload["forensics"]["received_chain"]
    # Message order: position 0 = last hop (relay -> mailbox).
    assert hops[0]["position"] == 0
    assert hops[0]["from_host"] == "relay.example.test"
    assert hops[0]["by_host"] == "mailbox.example.test"
    assert hops[0]["ip_classification"] == "private"  # 10.0.0.9
    # hop_from_origin counts from the origin side.
    assert hops[0]["hop_from_origin"] == 2
    assert hops[1]["hop_from_origin"] == 1
    assert hops[1]["from_ip"] == "93.184.216.34"
    assert hops[1]["ip_classification"] == "public"
    assert hops[1]["timestamp"].startswith("2025-04-01T10:30:00")


def test_earliest_candidate_prefers_public_ip() -> None:
    from app.forensics.received_chain import build_forensic_evidence
    from app.extractor.email_parser import extract_email_from_bytes

    raw = (
        b"From: a@example.test\r\n"
        b"Received: from internal.corp (internal.corp [10.0.0.5]) by mx.corp; "
        b"Mon, 01 Sep 2026 10:05:00 +0000\r\n"
        b"Received: from badguy.example.net (badguy.example.net "
        b"[93.184.216.34]) by internal.corp; "
        b"Mon, 01 Sep 2026 10:00:00 +0000\r\n"
        b"Subject: t\r\n\r\nbody"
    )
    evidence = extract_email_from_bytes(raw, filename="t.eml")
    forensics = build_forensic_evidence(evidence)
    candidate = forensics.earliest_reliable_candidate
    assert candidate is not None
    assert candidate.status == "success"
    assert candidate.ip == "93.184.216.34"
    assert candidate.confidence in {"medium", "high"}
    assert any("public" in reason for reason in candidate.reasoning)


def test_candidate_label_never_claims_attacker() -> None:
    from app.forensics.received_chain import build_forensic_evidence
    from app.extractor.email_parser import extract_email_from_bytes

    raw = (
        b"From: a@example.test\r\n"
        b"Received: from badguy.example.net (badguy.example.net "
        b"[93.184.216.34]) by mx.example.test; "
        b"Mon, 01 Sep 2026 10:00:00 +0000\r\n"
        b"Subject: t\r\n\r\nbody"
    )
    evidence = extract_email_from_bytes(raw, filename="t.eml")
    forensics = build_forensic_evidence(evidence)
    blob = forensics.model_dump_json().casefold()
    assert "attacker" not in blob
    assert "criminal" not in blob
    assert forensics.earliest_reliable_candidate is not None
    assert (
        forensics.earliest_reliable_candidate.label
        == "earliest observed sending infrastructure"
    )


def test_timestamp_inversion_indicator() -> None:
    from app.forensics.received_chain import build_forensic_evidence
    from app.extractor.email_parser import extract_email_from_bytes

    # The earlier hop (origin side) reports a LATER time than the next hop:
    raw = (
        b"From: a@example.test\r\n"
        b"Received: from mx1.example.net (mx1 [93.184.216.1]) by mx2; "
        b"Mon, 01 Sep 2026 10:00:00 +0000\r\n"
        b"Received: from origin.example.net (origin [93.184.216.2]) by mx1; "
        b"Mon, 01 Sep 2026 11:00:00 +0000\r\n"
        b"Subject: t\r\n\r\nbody"
    )
    evidence = extract_email_from_bytes(raw, filename="t.eml")
    forensics = build_forensic_evidence(evidence)
    names = [indicator.name for indicator in forensics.indicators]
    assert "received_timestamp_inversion" in names


def test_no_received_headers_produces_no_candidate() -> None:
    from app.forensics.received_chain import build_forensic_evidence
    from app.extractor.email_parser import extract_email_from_bytes

    raw = b"From: a@example.test\r\nSubject: t\r\n\r\nbody"
    evidence = extract_email_from_bytes(raw, filename="t.eml")
    forensics = build_forensic_evidence(evidence)
    assert forensics.received_chain == []
    assert forensics.earliest_reliable_candidate is not None
    assert forensics.earliest_reliable_candidate.status == "no_candidate"
    assert any(
        i.name == "no_received_headers" for i in forensics.indicators
    )


def test_forensics_is_deterministic() -> None:
    from app.forensics.received_chain import build_forensic_evidence
    from app.extractor.email_parser import extract_email_from_bytes

    raw = (
        b"From: a@example.test\r\n"
        b"Received: from h.example.net (h [93.184.216.7]) by mx; "
        b"Mon, 01 Sep 2026 10:00:00 +0000\r\n"
        b"Subject: t\r\n\r\nbody"
    )
    evidence = extract_email_from_bytes(raw, filename="t.eml")
    assert (
        build_forensic_evidence(evidence).model_dump_json()
        == build_forensic_evidence(evidence).model_dump_json()
    )


def test_error_tests_still_exclude_new_sections(client: TestClient, failing_rspamd) -> None:
    """Controlled errors keep the lean error shape (no risk/forensics)."""

    failing_rspamd(RspamdConnectionError("connection refused"))
    response = _post_email(client)
    assert response.status_code == 503
    payload = response.json()
    assert set(payload) == {"error"}
