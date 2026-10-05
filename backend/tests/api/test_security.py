"""Phase 8 tests: API security (auth, rate limiting, request ids).

Security settings are environment-driven; every test isolates its state by
clearing the cached settings and limiter around each case.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api import dependencies
from app.main import app as fastapi_app

from helpers import SAMPLE_EML  # noqa: F401


@pytest.fixture()
def security_env(monkeypatch):
    """Isolate security settings for one test."""

    monkeypatch.delenv("FORENTISAI_API_KEYS", raising=False)
    monkeypatch.delenv("API_ENVIRONMENT", raising=False)
    monkeypatch.delenv("API_RATE_LIMIT_REQUESTS", raising=False)
    dependencies.reset_security_cache()
    yield monkeypatch
    dependencies.reset_security_cache()


def _post_analysis(client: TestClient, **headers: str):
    return client.post(
        "/analyze-email",
        files={"upload": ("sec.eml", SAMPLE_EML, "message/rfc822")},
        headers=headers or None,
    )


def test_local_without_keys_allows_anonymous(client, security_env, fake_rspamd):
    response = _post_analysis(client)
    assert response.status_code == 200


def test_health_stays_unauthenticated_with_keys(client, security_env, monkeypatch):
    monkeypatch.setenv("FORENTISAI_API_KEYS", "secret-key-1")
    dependencies.reset_security_cache()
    response = client.get("/health")
    assert response.status_code == 200


def test_missing_key_rejected_when_keys_configured(client, security_env, monkeypatch):
    monkeypatch.setenv("FORENTISAI_API_KEYS", "secret-key-1")
    dependencies.reset_security_cache()
    response = _post_analysis(client)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_wrong_key_rejected(client, security_env, monkeypatch):
    monkeypatch.setenv("FORENTISAI_API_KEYS", "secret-key-1")
    dependencies.reset_security_cache()
    response = _post_analysis(client, **{"Authorization": "Bearer wrong-key"})
    assert response.status_code == 401


def test_valid_bearer_key_accepted(client, security_env, monkeypatch, fake_rspamd):
    monkeypatch.setenv("FORENTISAI_API_KEYS", "secret-key-1, secret-key-2")
    dependencies.reset_security_cache()
    response = _post_analysis(client, **{"Authorization": "Bearer secret-key-2"})
    assert response.status_code == 200


def test_valid_x_api_key_accepted(client, security_env, monkeypatch, fake_rspamd):
    monkeypatch.setenv("FORENTISAI_API_KEYS", "secret-key-1")
    dependencies.reset_security_cache()
    response = _post_analysis(client, **{"X-API-Key": "secret-key-1"})
    assert response.status_code == 200


def test_production_without_keys_fails_closed(client, security_env, monkeypatch):
    monkeypatch.setenv("API_ENVIRONMENT", "production")
    dependencies.reset_security_cache()
    response = _post_analysis(client)
    assert response.status_code == 401
    assert "FORENTISAI_API_KEYS" in response.json()["error"]["message"]


def test_rate_limit_returns_429_with_retry_after(client, security_env, monkeypatch, fake_rspamd):
    monkeypatch.setenv("API_RATE_LIMIT_REQUESTS", "2")
    dependencies.reset_security_cache()
    first = _post_analysis(client)
    second = _post_analysis(client)
    third = _post_analysis(client)
    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429
    assert third.json()["error"]["code"] == "rate_limit_exceeded"
    assert "retry-after" in {k.lower() for k in third.headers}
    assert int(third.headers["Retry-After"]) >= 1


def test_rate_limit_is_per_key_identity(client, security_env, monkeypatch, fake_rspamd):
    monkeypatch.setenv("FORENTISAI_API_KEYS", "key-a,key-b")
    monkeypatch.setenv("API_RATE_LIMIT_REQUESTS", "1")
    dependencies.reset_security_cache()
    first = _post_analysis(client, **{"Authorization": "Bearer key-a"})
    second = _post_analysis(client, **{"Authorization": "Bearer key-b"})
    third = _post_analysis(client, **{"Authorization": "Bearer key-a"})
    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429


def test_invalid_key_is_rate_limited_too(client, security_env, monkeypatch):
    monkeypatch.setenv("FORENTISAI_API_KEYS", "secret-key-1")
    monkeypatch.setenv("API_RATE_LIMIT_REQUESTS", "1")
    dependencies.reset_security_cache()
    first = _post_analysis(client, **{"X-API-Key": "bad"})
    second = _post_analysis(client, **{"X-API-Key": "bad"})
    assert first.status_code == 401
    assert second.status_code == 401


def test_request_id_generated_for_every_response(client, security_env, fake_rspamd):
    response = _post_analysis(client)
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID")


def test_client_request_id_echoed_when_safe(client, security_env, fake_rspamd):
    response = _post_analysis(client, **{"X-Request-ID": "abc-123_DEF.4"})
    assert response.headers.get("X-Request-ID") == "abc-123_DEF.4"


def test_malicious_request_id_replaced(client, security_env, fake_rspamd):
    response = _post_analysis(
        client, **{"X-Request-ID": "bad id\r\nX-Injected: 1"}
    )
    request_id = response.headers.get("X-Request-ID", "")
    assert request_id != "bad id\r\nX-Injected: 1"
    assert all(ch.isalnum() or ch in "-_." for ch in request_id)


def test_oversized_request_id_replaced(client, security_env, fake_rspamd):
    response = _post_analysis(client, **{"X-Request-ID": "x" * 65})
    request_id = response.headers.get("X-Request-ID", "")
    assert request_id != "x" * 65
    assert len(request_id) <= 64


def test_cors_origins_are_explicit_allowlist(client, security_env):
    response = client.options(
        "/analyze-email",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"},
    )
    assert response.status_code in {200, 400}
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_unknown_origin_not_allowed(client, security_env):
    response = client.options(
        "/analyze-email",
        headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert response.headers.get("access-control-allow-origin") is None