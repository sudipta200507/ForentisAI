"""Regression tests for the malformed-Unicode production bug (sample-1.eml).

A phishing .eml whose Subject header carried raw non-ASCII bytes ("cartão"
as raw UTF-8) produced lone surrogates in extracted header strings (the
stdlib parses raw 8-bit headers with surrogateescape); FastAPI's JSON
rendering then failed with UnicodeEncodeError ("surrogates not allowed")
-> HTTP 500.

Contract under test, against BOTH the exact original sample-1.eml and a
self-contained invalid-byte fixture:
- extraction succeeds and NO evidence string contains a lone surrogate;
- evidence around the malformed bytes is preserved (per-code-point U+FFFD);
- the whole pipeline (Rspamd, intelligence, AI, risk, XAI, persistence)
  still runs and the JSON response serializes (HTTP 200, never 500);
- a transparency parser defect records the sanitization.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.json_response import SanitizingJSONResponse
from app.database.session import reset_engine_cache
from app.extractor.email_parser import extract_email_from_bytes
from app.extractor.unicode_safety import (
    has_lone_surrogates,
    sanitize_unicode_text,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SAMPLE_PATH = PROJECT_ROOT / "samples" / "phishing" / "sample-1.eml"


def _surrogate_evidence_bytes() -> bytes:
    """Self-contained invalid-byte fixture (bare 0x80 continuation bytes).

    Complements the exact original sample: the original's raw bytes are
    valid UTF-8 in a raw header, while this fixture uses bytes that are
    invalid in ANY encoding, so the replacement path stays covered even if
    the sample file is absent.
    """
    return b"\r\n".join(
        [
            b"From: PayPa1 Security <alerts@paypa1-\x80.com>",
            b"Reply-To: helpdesk@secure-verify\x80.net",
            b"Subject: Verify raw\x80now",
            b"Message-ID: <\x80abc@mailer.paypa1-\x80.com>",
            b"Date: Thu, 1 Oct 2026 09:15:00 +0000",
            b"Received: from mail-out\x80.evil.net ([203.0.113.77])",
            b"\tby mx.example.com; Thu, 1 Oct 2026 09:15:02 +0000",
            b"Content-Type: multipart/mixed; boundary=\"B\"",
            b"--B",
            b"Content-Type: text/plain; charset=\"utf-8\"",
            b"Content-Transfer-Encoding: 8bit",
            b"",
            b"Locked account! Verify: https://paypa1-secure\x80.com/login \x80",
            b"--B",
            b"Content-Type: application/octet-stream; name=\"invoice\x80.pdf\"",
            b"Content-Disposition: attachment; filename=\"invoice\x80.pdf\"",
            b"Content-Transfer-Encoding: base64",
            b"",
            b"JVBERi0xLjQK",
            b"--B--",
            b"",
        ]
    )


def _original_sample_bytes() -> bytes | None:
    """The exact original sample when present, else None."""
    if SAMPLE_PATH.exists():
        return SAMPLE_PATH.read_bytes()
    return None


def _find_surrogates(obj, path="evidence"):  # noqa: ANN001
    findings: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            findings.extend(_find_surrogates(value, f"{path}.{key}"))
    elif isinstance(obj, (list, tuple)):
        for index, value in enumerate(obj):
            findings.extend(_find_surrogates(value, f"{path}[{index}]"))
    elif isinstance(obj, str) and has_lone_surrogates(obj):
        findings.append(path)
    return findings


# ---------------------------------------------------------------------------
# Sanitizer unit behavior
# ---------------------------------------------------------------------------

def test_sanitizer_replaces_lone_surrogates_one_to_one():
    dirty = "alerts@paypa1-\udc80.com"
    clean = sanitize_unicode_text(dirty)
    assert clean == "alerts@paypa1-\ufffd.com"
    assert len(clean) == len(dirty)  # 1:1 replacement
    assert not has_lone_surrogates(clean)


def test_sanitizer_preserves_valid_text_including_astral():
    valid = "emoji 🚀 accént 中文 <script>"
    assert sanitize_unicode_text(valid) == valid
    # Fast path must be identity for clean strings.
    assert sanitize_unicode_text("") == ""


def test_sanitizer_handles_paired_surrogates_correctly():
    # A properly PAIRED surrogate sequence encodes an astral char and must
    # survive untouched ("🚀" = U+1F680).
    assert sanitize_unicode_text("a🚀b") == "a🚀b"


def test_sanitizing_json_response_renders_surrogates_as_replacement():
    response = SanitizingJSONResponse(
        {"subject": "bad \udc80 char", "nested": ["ok", "\udce2\udc8c"]}
    )
    body = json.loads(response.body.decode("utf-8"))
    assert body["subject"] == "bad \ufffd char"
    assert body["nested"][0] == "ok"
    assert body["nested"][1] == "\ufffd\ufffd"


def test_sanitizing_json_response_matches_stock_render_for_clean_content():
    from fastapi.responses import JSONResponse

    payload = {"a": 1, "b": [1.5, "text", None, True], "c": "🚀"}
    assert SanitizingJSONResponse(payload).body == JSONResponse(payload).body


# ---------------------------------------------------------------------------
# Extraction-level regression — exact original sample (real-world case)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    _original_sample_bytes() is None, reason="original sample-1.eml not present"
)
def test_original_sample_extraction_has_no_surrogates():
    evidence = extract_email_from_bytes(
        _original_sample_bytes(), filename="sample-1.eml"
    )
    dumped = evidence.model_dump()
    assert _find_surrogates(dumped) == []
    json.dumps(dumped, ensure_ascii=False).encode("utf-8")


@pytest.mark.skipif(
    _original_sample_bytes() is None, reason="original sample-1.eml not present"
)
def test_original_sample_extraction_is_complete():
    evidence = extract_email_from_bytes(
        _original_sample_bytes(), filename="sample-1.eml"
    )
    # The real Bradesco LIVELO phishing email: sender, subject, URL intact.
    assert evidence.sender is not None
    assert evidence.sender.address == "banco.bradesco@atendimento.com.br"
    assert evidence.message.subject is not None
    # The raw-header "cartão" bytes are sanitized (replaced), the rest of
    # the subject text is preserved.
    assert "cart" in evidence.message.subject
    assert "LIVELO" in evidence.message.subject
    assert any(
        "blog1seguimentmydomaine2bra.me" in (url.url or "") for url in evidence.urls
    ), "the phishing URL must survive extraction"
    # The transparency defect records the sanitized header value.
    assert "unicode-safety" in [defect.source for defect in evidence.parser_defects]


# ---------------------------------------------------------------------------
# Extraction-level regression — invalid-byte fixture (replacement path)
# ---------------------------------------------------------------------------

def test_invalid_byte_fixture_extraction_has_no_surrogates():
    evidence = extract_email_from_bytes(
        _surrogate_evidence_bytes(), filename="sample-1.eml"
    )
    dumped = evidence.model_dump()
    assert _find_surrogates(dumped) == []
    json.dumps(dumped, ensure_ascii=False).encode("utf-8")


def test_invalid_byte_fixture_preserves_evidence_around_malformed_byte():
    evidence = extract_email_from_bytes(
        _surrogate_evidence_bytes(), filename="sample-1.eml"
    )
    # The invalid byte inside the sender domain becomes U+FFFD; the rest of
    # the address survives (nothing is discarded).
    assert evidence.sender is not None
    assert evidence.sender.address.startswith("alerts@paypa1-")
    assert "\ufffd" in evidence.sender.address
    assert evidence.sender.address.endswith(".com")
    # Subject keeps its readable prefix with the replacement in place.
    assert evidence.message.subject is not None
    assert evidence.message.subject.startswith("Verify raw")
    assert "unicode-safety" in [defect.source for defect in evidence.parser_defects]


def test_invalid_byte_fixture_urls_and_attachments_sanitized_but_preserved():
    evidence = extract_email_from_bytes(
        _surrogate_evidence_bytes(), filename="sample-1.eml"
    )
    assert evidence.urls, "URL extraction must still find the phishing URLs"
    for url in evidence.urls:
        assert not has_lone_surrogates(url.url)
        assert "\ufffd" in url.url  # malformed byte was replaced, URL kept
    assert evidence.attachments, "attachment metadata must still be extracted"
    for attachment in evidence.attachments:
        assert not has_lone_surrogates(attachment.filename or "")


# ---------------------------------------------------------------------------
# Full-pipeline regression through the API (the production failure path)
# ---------------------------------------------------------------------------

@pytest.fixture()
def surrogate_api(monkeypatch, tmp_path):
    monkeypatch.setenv("FORENTISAI_DATABASE_URL", f"sqlite:///{tmp_path / 'surrogate.db'}")
    monkeypatch.setenv("FORENTISAI_PERSIST_ENABLED", "true")
    reset_engine_cache()
    from app.main import create_app

    with TestClient(create_app()) as client:
        yield client


def _api_fixture_bytes() -> bytes:
    return _original_sample_bytes() or _surrogate_evidence_bytes()


def test_analyze_email_returns_200_not_500_for_malformed_unicode(surrogate_api):
    response = surrogate_api.post(
        "/analyze-email",
        files={"upload": ("sample-1.eml", _api_fixture_bytes(), "message/rfc822")},
    )
    assert response.status_code == 200, response.text
    body = response.json()


def test_analyze_email_full_pipeline_survives_malformed_unicode(surrogate_api):
    response = surrogate_api.post(
        "/analyze-email",
        files={"upload": ("sample-1.eml", _api_fixture_bytes(), "message/rfc822")},
    )
    assert response.status_code == 200, response.text
    body = response.json()

    # Every pipeline section is present and coherent.
    assert body["email"]["file"]["sha256"]
    assert body["authentication"]["spf"] is not None
    assert body["intelligence"] is not None
    assert body["ai"] is not None
    assert body["risk"]["risk_score"] is not None
    assert body["forensics"] is not None

    # The email content made it through: sender extracted, URLs extracted.
    assert body["email"]["sender"]["address"]
    assert body["email"]["urls"], "URLs must be extracted from the analyzed email"

    # The serialized response itself contains no lone surrogates.
    assert _find_surrogates(body) == []


def test_analyze_email_persists_malformed_unicode_analysis(surrogate_api):
    response = surrogate_api.post(
        "/analyze-email",
        files={"upload": ("sample-1.eml", _api_fixture_bytes(), "message/rfc822")},
    )
    assert response.status_code == 200
    analysis_id = response.json()["analysis_id"]

    # Persistence still works for this email (not silently dropped).
    stored = surrogate_api.get(f"/analyses/{analysis_id}")
    assert stored.status_code == 200
    assert stored.json()["analysis_id"] == analysis_id

    # Reports can also be reconstructed from the stored record.
    report = surrogate_api.get(f"/reports/{analysis_id}?format=json")
    assert report.status_code == 200


def test_analyze_email_response_is_valid_utf8_json(surrogate_api):
    response = surrogate_api.post(
        "/analyze-email",
        files={"upload": ("sample-1.eml", _api_fixture_bytes(), "message/rfc822")},
    )
    assert response.status_code == 200
    # .decode would fail on invalid UTF-8 bytes; strict parse proves encoding.
    body = response.content.decode("utf-8")
    assert json.loads(body)["schema_version"] == "1.0"
