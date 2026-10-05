"""Tests 22-24 of the Step 4 plan: resilience and security guarantees."""

from __future__ import annotations

import dns.resolver
import io
import logging

import pytest
from fastapi.testclient import TestClient

from app.api import dependencies
from app.authentication.rspamd_client import RspamdAnalysis, RspamdSymbol
from app.intelligence.dns import DNSSettings
from app.intelligence.geolocation import GeoIPSettings
from app.intelligence.orchestrator import (
    IntelligenceSettings,
    build_intelligence_evidence,
)
from app.main import app as fastapi_app
from app.schemas.intelligence import IntelligenceEvidence

from fixtures import FakeResolver, sample_evidence


def _offline_settings() -> IntelligenceSettings:
    return IntelligenceSettings(perform_dns=False, perform_rdap=False)


# ---------------------------------------------------------------------------
# 22. intelligence failure does not destroy EmailEvidence
# ---------------------------------------------------------------------------


class TestFailureResilience:
    def test_dns_timeout_degrades_not_destroys(self) -> None:
        # Every DNS query times out; the email evidence is untouched.
        script = {
            ("example.test", rdtype): dns.resolver.LifetimeTimeout()
            for rdtype in ("A", "AAAA", "MX", "TXT", "NS", "CNAME")
        }
        result = build_intelligence_evidence(
            sample_evidence(),
            settings=IntelligenceSettings(dns=DNSSettings(timeout_seconds=0.2)),
            resolver=FakeResolver(script),
        )
        assert all(d.dns is not None and d.dns.status == "timeout" for d in result.domains)
        assert result.domains[0].normalized_domain == "example.test"
        # Failure is never rewritten into "no record".
        assert result.domains[0].dns.status != "no_record"

    def test_geoip_off_keeps_ip_evidence(self) -> None:
        result = build_intelligence_evidence(
            sample_evidence(),
            settings=IntelligenceSettings(
                perform_dns=False, perform_rdap=False, geoip=GeoIPSettings(mode="off")
            ),
        )
        assert len(result.ips) == 2
        assert all(ip.geolocation.reason == "not_configured" for ip in result.ips)
        assert result.counts["ips"] == 2

    def test_provider_boom_does_not_raise(self) -> None:
        class ExplodingResolver:
            def resolve(self, name: str, rdtype: str) -> object:
                raise RuntimeError("resolver bug")

        result = build_intelligence_evidence(
            sample_evidence(),
            settings=IntelligenceSettings(),
            resolver=ExplodingResolver(),
        )
        # The run completed and the email-side data is intact.
        assert result.counts["domains"] == 1

    def test_email_evidence_never_mutated_by_intelligence(self) -> None:
        evidence = sample_evidence()
        before = evidence.model_dump_json()
        build_intelligence_evidence(evidence, settings=_offline_settings())
        assert evidence.model_dump_json() == before

    def test_empty_email_still_produces_valid_evidence(self) -> None:
        from app.extractor.email_parser import extract_email_from_bytes

        bare = extract_email_from_bytes(b"Subject: nothing\r\n\r\n\r\n")
        result = build_intelligence_evidence(bare, settings=_offline_settings())
        assert result.indicators == []
        assert result.counts == {"indicators": 0, "urls": 0, "ips": 0, "domains": 0}

    def test_api_responds_with_all_three_sections(self) -> None:
        from app.main import app as fastapi_app

        with TestClient(fastapi_app, raise_server_exceptions=False) as client:
            response = client.post(
                "/analyze-email",
                files={
                    "upload": (
                        "step1_synthetic.eml",
                        io.BytesIO(sample_evidence_bytes()),
                        "message/rfc822",
                    )
                },
            )
        assert response.status_code == 200
        payload = response.json()
        # Step 5 adds the ``ai`` section; Phases 3/5/5A add ``analysis_id``,
        # ``risk``, ``forensics``, and ``metadata``.
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
        # Step 1 and Step 2 data still present and shaped as before.
        assert payload["email"]["file"]["filename"] == "step1_synthetic.eml"
        assert payload["email"]["sender"]["address"] == "sender@example.test"
        assert payload["authentication"]["rspamd"]["scanned"] in {True, False}


def sample_evidence_bytes() -> bytes:
    from fixtures import SAMPLE_PATH

    return SAMPLE_PATH.read_bytes()


# ---------------------------------------------------------------------------
# 23. no arbitrary URL fetching
# ---------------------------------------------------------------------------


class TestNoArbitraryUrlFetching:
    def test_url_indicators_never_produce_http_calls(self, monkeypatch) -> None:
        calls: list[str] = []

        def _forbidden(*args: object, **kwargs: object) -> None:
            calls.append(str(args))

        monkeypatch.setattr("httpx.Client.send", _forbidden, raising=False)
        monkeypatch.setattr("httpx.request", _forbidden, raising=False)
        monkeypatch.setattr("httpx.get", _forbidden, raising=False)
        monkeypatch.setattr("httpx.post", _forbidden, raising=False)

        build_intelligence_evidence(sample_evidence(), settings=_offline_settings())
        assert calls == []

    def test_no_generic_fetch_url_symbol_exists(self) -> None:
        import app.intelligence as package_modules

        for name in dir(package_modules):
            if name.startswith("_"):
                continue
        for module_name in (
            "app.intelligence.url_intelligence",
            "app.intelligence.indicator_extractor",
        ):
            module = __import__(module_name, fromlist=["x"])
            for attribute in dir(module):
                if "fetch" in attribute.casefold():
                    pytest.fail(f"Forbidden generic URL-fetch symbol: {module_name}.{attribute}")

    def test_rdap_urls_built_only_from_known_endpoints(self) -> None:
        # The RDAP module builds URLs exclusively from endpoint + /domain/<name>.
        from app.intelligence import rdap

        source = open(rdap.__file__, encoding="utf-8").read()
        assert 'f"{endpoint}/domain/{domain}"' in source
        # No generic URL-fetch helper exists.
        assert "def fetch_url" not in source

    def test_malicious_urls_in_body_are_parsed_not_contacted(self, monkeypatch) -> None:
        from app.extractor.email_parser import extract_email_from_bytes

        def _blocked(*args: object, **kwargs: object) -> None:
            raise AssertionError("network access attempted during URL parsing")

        monkeypatch.setattr("socket.socket.connect", _blocked, raising=False)
        raw = (
            b"From: a@example.test\r\n\r\n"
            b"Visit http://192.0.2.99/x http://[2001:db8::1]/y https://evil.test/z\r\n"
        )
        evidence = extract_email_from_bytes(raw)
        parsed_urls = [
            u.indicator.value
            for u in build_intelligence_evidence(evidence, settings=_offline_settings()).urls
        ]
        assert "http://192.0.2.99/x" in parsed_urls
        assert "https://evil.test/z" in parsed_urls


# ---------------------------------------------------------------------------
# 24. no sensitive logging
# ---------------------------------------------------------------------------


class TestNoSensitiveLogging:
    def test_intelligence_modules_never_log_email_content(self, caplog) -> None:
        # Evidence is built OUTSIDE the capture window: mail-parser (Step 1's
        # dependency) has its own chatty DEBUG logger, which is not part of
        # the Step 4 boundary under test here.
        evidence = sample_evidence()
        with caplog.at_level(logging.DEBUG):
            build_intelligence_evidence(evidence, settings=_offline_settings())
        joined = " ".join(record.getMessage() for record in caplog.records).casefold()
        for secret in ("sender@example.test", "step1-fixture", "visit https"):
            assert secret not in joined

    def test_intelligence_modules_have_no_logging_calls(self) -> None:
        import pathlib

        from app.intelligence import dns as _dns_module

        package_dir = pathlib.Path(_dns_module.__file__).parent
        for source_file in package_dir.glob("*.py"):
            text = source_file.read_text(encoding="utf-8")
            assert "print(" not in text, f"{source_file.name} contains print()"
            assert "logging.getLogger" not in text, (
                f"{source_file.name} creates loggers; Step 4 modules are silent"
            )

    def test_provider_error_messages_contain_no_email_content(self) -> None:
        script = {
            ("example.test", rdtype): OSError("network unreachable")
            for rdtype in ("A", "AAAA", "MX", "TXT", "NS", "CNAME")
        }
        result = build_intelligence_evidence(
            sample_evidence(),
            settings=IntelligenceSettings(),
            resolver=FakeResolver(script),
        )
        exported = result.model_dump_json().casefold()
        assert "sender@example.test" not in exported
        assert "step1-fixture" not in exported
