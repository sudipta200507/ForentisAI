"""Unit tests for the Step 2 Rspamd client, normalizers, and schema.

No live Rspamd container is required here: HTTP interactions use
``httpx.MockTransport`` and parsing is exercised directly.
"""

from __future__ import annotations

import httpx
import pytest

from app.authentication.dkim import normalize_dkim
from app.authentication.dmarc import build_authentication_evidence, normalize_dmarc
from app.authentication.rspamd_client import (
    RspamdClient,
    RspamdConnectionError,
    RspamdInvalidEmailError,
    RspamdInvalidResponseError,
    RspamdTimeoutError,
    parse_scan_response,
)
from app.authentication.spf import normalize_spf
from app.core.config import RspamdSettings, load_rspamd_settings
from app.schemas.authentication import (
    AuthenticationEvidence,
    RspamdAnalysis,
    RspamdSymbol,
)


SAMPLE_EML = (
    b"From: sender@example.test\r\n"
    b"To: recipient@example.test\r\n"
    b"Subject: Step 2 fixture\r\n"
    b"\r\n"
    b"Authentication fixture body\r\n"
)


def make_client(handler) -> RspamdClient:
    settings = RspamdSettings(url="http://rspamd.test:11333", timeout_seconds=5.0)
    return RspamdClient(settings, transport=httpx.MockTransport(handler))


# ---------------------------------------------------------------------------
# 1. Client configuration
# ---------------------------------------------------------------------------


def test_client_configuration_defaults_to_host_loopback_url() -> None:
    # Since Step 3 the API runs on the host, so the default points at the
    # loopback-published port; containerized callers override RSPAMD_URL to
    # the Compose DNS name (http://rspamd:11333).
    settings = load_rspamd_settings()
    assert settings.url == "http://127.0.0.1:11333"
    assert settings.scan_path == "/checkv2"
    assert settings.timeout_seconds > 0


def test_client_settings_are_used_for_the_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RSPAMD_URL", "http://127.0.0.1:11333/")
    settings = load_rspamd_settings()
    assert settings.url == "http://127.0.0.1:11333"


def test_client_accepts_explicit_settings_and_transport() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200, json=valid_rspamd_payload())

    client = make_client(handler)
    client.scan_bytes(SAMPLE_EML)
    assert captured["url"] == "http://rspamd.test:11333/checkv2"


# ---------------------------------------------------------------------------
# 2. Successful response parsing
# ---------------------------------------------------------------------------


def valid_rspamd_payload() -> dict[str, object]:
    return {
        "is_skipped": False,
        "score": 1.5,
        "required_score": 15.0,
        "action": "add header",
        "message-id": "<step2-fixture@example.test>",
        "symbols": {
            "R_SPF_ALLOW": {"name": "R_SPF_ALLOW", "score": -0.2},
            "R_DKIM_ALLOW": {"name": "R_DKIM_ALLOW", "score": -0.1},
            "DMARC_POLICY_ALLOW": {
                "name": "DMARC_POLICY_ALLOW",
                "score": -0.5,
                "options": ["example.test : SPF Allowed"],
            },
            "FUZZY_DENIED": {"name": "FUZZY_DENIED", "score": 0.0, "options": ["1: 1.00 / 1.00"]},
        },
    }


def test_successful_scan_returns_structured_analysis() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=valid_rspamd_payload())

    analysis = make_client(handler).scan_bytes(SAMPLE_EML)

    assert isinstance(analysis, RspamdAnalysis)
    assert analysis.action == "add header"
    assert analysis.score == 1.5
    assert analysis.required_score == 15.0
    assert analysis.message_id == "<step2-fixture@example.test>"
    assert analysis.scanned is True
    assert set(analysis.symbols) == {
        "R_SPF_ALLOW",
        "R_DKIM_ALLOW",
        "DMARC_POLICY_ALLOW",
        "FUZZY_DENIED",
    }
    assert analysis.symbols["FUZZY_DENIED"].options == ["1: 1.00 / 1.00"]


def test_symbol_shapes_are_normalized_defensively() -> None:
    payload = {
        "action": "no action",
        "score": 0.0,
        "required_score": 15.0,
        "symbols": {"R_DKIM_ALLOW": -0.1, "PLAIN": {"score": "not-a-number", "options": "oops"}},
    }
    analysis = parse_scan_response(payload)
    assert analysis.symbols["R_DKIM_ALLOW"] == RspamdSymbol(score=-0.1)
    assert analysis.symbols["PLAIN"].score == 0.0
    assert analysis.symbols["PLAIN"].options == []


# ---------------------------------------------------------------------------
# 3-5. Unavailable, timeout, invalid response
# ---------------------------------------------------------------------------


def test_rspamd_unavailable_raises_connection_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with pytest.raises(RspamdConnectionError) as excinfo:
        make_client(handler).scan_bytes(SAMPLE_EML)
    assert excinfo.value.code == "rspamd_unavailable"
    # The error must not contain the email body or headers.
    assert b"Authentication fixture body" not in str(excinfo.value).encode()
    assert "sender@example.test" not in str(excinfo.value)


def test_rspamd_timeout_raises_timeout_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    with pytest.raises(RspamdTimeoutError) as excinfo:
        make_client(handler).scan_bytes(SAMPLE_EML)
    assert excinfo.value.code == "rspamd_timeout"


def test_http_error_status_raises_connection_error() -> None:
    with pytest.raises(RspamdConnectionError, match="HTTP 503"):
        make_client(lambda request: httpx.Response(503, text="unavailable")).scan_bytes(
            SAMPLE_EML
        )


def test_non_json_body_raises_invalid_response_error() -> None:
    with pytest.raises(RspamdInvalidResponseError, match="not valid JSON"):
        make_client(
            lambda request: httpx.Response(200, text="<html>gateway error</html>")
        ).scan_bytes(SAMPLE_EML)


@pytest.mark.parametrize(
    "payload",
    [
        "not-a-dict",
        {"score": 1.0, "required_score": 15.0},  # missing action
        {"action": "no action", "required_score": 15.0},  # missing score
        {"action": "no action", "score": "high", "required_score": 15.0},  # bad score
        {"action": "no action", "score": 1.0, "required_score": 15.0, "symbols": []},
    ],
)
def test_malformed_responses_are_rejected(payload: object) -> None:
    with pytest.raises(RspamdInvalidResponseError):
        parse_scan_response(payload)


def test_empty_email_is_rejected_locally() -> None:
    with pytest.raises(RspamdInvalidEmailError):
        make_client(lambda request: httpx.Response(200, json={})).scan_bytes(b"")


# ---------------------------------------------------------------------------
# 6. SPF normalization
# ---------------------------------------------------------------------------


def _analysis(symbols: dict[str, RspamdSymbol]) -> RspamdAnalysis:
    return RspamdAnalysis(action="no action", score=0.0, required_score=15.0, symbols=symbols)


def test_spf_pass_is_normalized() -> None:
    evidence = normalize_spf(_analysis({"R_SPF_ALLOW": RspamdSymbol(score=-0.2)}))
    assert evidence.result == "pass"
    assert evidence.available == "available"
    assert evidence.symbols == ["R_SPF_ALLOW"]


@pytest.mark.parametrize(
    ("symbol_name", "expected"),
    [
        ("R_SPF_FAIL", "fail"),
        ("R_SPF_SOFTFAIL", "softfail"),
        ("R_SPF_NEUTRAL", "neutral"),
        ("R_SPF_NA", "none"),
        ("R_SPF_DNSFAIL", "temperror"),
        ("R_SPF_PERMFAIL", "permerror"),
    ],
)
def test_spf_results_map_to_rfc_vocabulary(symbol_name: str, expected: str) -> None:
    assert normalize_spf(_analysis({symbol_name: RspamdSymbol()})).result == expected


def test_spf_missing_result_is_unknown_and_unavailable() -> None:
    evidence = normalize_spf(_analysis({"R_DKIM_ALLOW": RspamdSymbol()}))
    assert evidence.result == "unknown"
    assert evidence.available == "unavailable"


def test_spf_options_are_preserved_as_explanation() -> None:
    evidence = normalize_spf(
        _analysis({"R_SPF_ALLOW": RspamdSymbol(score=-0.2, options=["example.test"])})
    )
    assert evidence.explanation == "example.test"


# ---------------------------------------------------------------------------
# 7. DKIM normalization
# ---------------------------------------------------------------------------


def test_dkim_pass_is_normalized() -> None:
    evidence = normalize_dkim(_analysis({"R_DKIM_ALLOW": RspamdSymbol(score=-0.1)}))
    assert evidence.result == "pass"
    assert evidence.available == "available"


@pytest.mark.parametrize(
    ("symbol_name", "expected"),
    [
        ("R_DKIM_REJECT", "fail"),
        ("R_DKIM_TEMPFAIL", "temperror"),
        ("R_DKIM_PERMFAIL", "permerror"),
        ("R_DKIM_NA", "none"),
    ],
)
def test_dkim_results_map_to_rfc_vocabulary(symbol_name: str, expected: str) -> None:
    assert normalize_dkim(_analysis({symbol_name: RspamdSymbol()})).result == expected


def test_dkim_signature_header_presence_alone_is_not_a_pass() -> None:
    # A scan that only knows a signature exists reports nothing about validity.
    evidence = normalize_dkim(_analysis({"R_DKIM_NA": RspamdSymbol()}))
    assert evidence.result == "none"
    assert evidence.result != "pass"


def test_dkim_domain_and_selector_extracted_from_options() -> None:
    evidence = normalize_dkim(
        _analysis({"R_DKIM_ALLOW": RspamdSymbol(options=["d:example.test:s:sel1"])})
    )
    assert evidence.domain == "example.test"
    assert evidence.selector == "sel1"


def test_dkim_missing_result_is_unknown_and_unavailable() -> None:
    evidence = normalize_dkim(_analysis({"R_SPF_ALLOW": RspamdSymbol()}))
    assert evidence.result == "unknown"
    assert evidence.available == "unavailable"


# ---------------------------------------------------------------------------
# 8-9. DMARC normalization and missing results
# ---------------------------------------------------------------------------


def test_dmarc_pass_is_normalized() -> None:
    evidence = normalize_dmarc(
        _analysis({"DMARC_POLICY_ALLOW": RspamdSymbol(score=-0.5, options=["example.test"])})
    )
    assert evidence.result == "pass"
    assert evidence.domain == "example.test"
    assert evidence.available == "available"


@pytest.mark.parametrize(
    ("symbol_name", "expected_result", "expected_policy"),
    [
        # REJECT/QUARANTINE are dispositions of a FAILED evaluation: the
        # authentication result is always "fail"; the published policy is
        # preserved separately for forensic context.
        ("DMARC_POLICY_REJECT", "fail", "reject"),
        ("DMARC_POLICY_QUARANTINE", "fail", "quarantine"),
        # SOFTFAIL: authentication failed, Rspamd suggests no action (p=none).
        ("DMARC_POLICY_SOFTFAIL", "fail", "none"),
        # No DMARC record at all.
        ("DMARC_NA", "none", "none"),
        # A pass carries no reported policy value (never fabricated as "none").
        ("DMARC_POLICY_ALLOW", "pass", None),
    ],
)
def test_dmarc_results_map_to_authentication_vocabulary(
    symbol_name: str, expected_result: str, expected_policy: str | None
) -> None:
    evidence = normalize_dmarc(_analysis({symbol_name: RspamdSymbol()}))
    assert evidence.result == expected_result
    assert evidence.policy == expected_policy


def test_dmarc_alignment_stays_none_when_not_reported() -> None:
    evidence = normalize_dmarc(_analysis({"DMARC_POLICY_ALLOW": RspamdSymbol()}))
    assert evidence.spf_aligned is None
    assert evidence.dkim_aligned is None
    assert evidence.spf_contribution is None
    assert evidence.dkim_contribution is None


def test_dmarc_alignment_parsed_when_explicitly_reported() -> None:
    evidence = normalize_dmarc(
        _analysis(
            {
                "DMARC_POLICY_ALLOW": RspamdSymbol(
                    options=["spf_aligned=true", "dkim_aligned=false"]
                )
            }
        )
    )
    assert evidence.spf_aligned is True
    assert evidence.dkim_aligned is False


def test_missing_authentication_results_stay_unknown_everywhere() -> None:
    evidence = build_authentication_evidence(
        _analysis({"HFILTER_HOSTNAME_UNKNOWN": RspamdSymbol()})
    )
    assert evidence.spf.result == "unknown"
    assert evidence.spf.available == "unavailable"
    assert evidence.dkim.result == "unknown"
    assert evidence.dmarc.result == "unknown"
    assert evidence.dmarc.available == "unavailable"


def test_no_analysis_yields_all_unknown_evidence() -> None:
    evidence = build_authentication_evidence(None)
    assert evidence.spf.result == "unknown"
    assert evidence.dkim.result == "unknown"
    assert evidence.dmarc.result == "unknown"
    assert evidence.rspamd.scanned is False


# ---------------------------------------------------------------------------
# 10. PASS never becomes SAFE
# ---------------------------------------------------------------------------


def test_fully_passing_authentication_is_still_evidence_not_a_verdict() -> None:
    analysis = parse_scan_response(valid_rspamd_payload())
    evidence = build_authentication_evidence(analysis)

    assert evidence.spf.result == "pass"
    assert evidence.dkim.result == "pass"
    assert evidence.dmarc.result == "pass"

    serialized = evidence.model_dump(mode="json")
    text = str(serialized).casefold()
    assert "safe" not in text
    assert "verdict" not in text
    assert "risk" not in text
    assert "threat" not in text
    # And the schema cannot silently grow a verdict-like field.
    assert not any(
        field in AuthenticationEvidence.model_fields for field in ("is_safe", "verdict", "risk_score")
    )


# ---------------------------------------------------------------------------
# 11. Original email bytes are sent unchanged
# ---------------------------------------------------------------------------


def test_original_bytes_are_posted_unchanged() -> None:
    captured: dict[str, bytes] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read()
        return httpx.Response(200, json=valid_rspamd_payload())

    original = bytes(SAMPLE_EML)
    make_client(handler).scan_bytes(original)

    assert captured["body"] == original
    assert original == SAMPLE_EML  # caller's buffer untouched
