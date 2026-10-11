"""Live integration test: API + real Dockerized Rspamd.

Skips automatically when the Rspamd container is not running, so the unit
test suite never requires Docker.
"""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app as fastapi_app

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SAMPLE_PATH = PROJECT_ROOT / "samples" / "safe" / "step1_synthetic.eml"
RSPAMD_URL = os.environ.get("RSPAMD_URL", "http://127.0.0.1:11333")


def _rspamd_reachable() -> bool:
    try:
        return httpx.get(f"{RSPAMD_URL}/ping", timeout=2.0).status_code == 200
    except httpx.TransportError:
        return False


pytestmark = pytest.mark.skipif(
    not _rspamd_reachable(),
    reason="Rspamd container is not running (docker compose up -d rspamd)",
)


def test_live_end_to_end_analysis() -> None:
    # Defense in depth: this test's purpose is the REAL Rspamd path, so any
    # leftover fake override from another module would invalidate it silently.
    from app.api import dependencies

    fastapi_app.dependency_overrides.pop(dependencies.get_rspamd_client, None)

    raw_email = SAMPLE_PATH.read_bytes()
    original = bytes(raw_email)

    with TestClient(fastapi_app) as client:
        response = client.post(
            "/analyze-email",
            files={"upload": ("step1_synthetic.eml", io.BytesIO(original), "message/rfc822")},
        )

    assert response.status_code == 200
    payload = response.json()

    email = payload["email"]
    for section in ("file", "message", "sender", "recipients", "body", "headers", "received_chain", "urls", "attachments", "mime", "parser_defects"):
        assert section in email
    assert email["file"]["sha256"] == hashlib.sha256(original).hexdigest()
    assert email["file"]["filename"] == "step1_synthetic.eml"
    assert email["message"]["subject"] == "Step 1 extraction fixture"
    assert email["sender"]["address"] == "sender@example.test"
    assert len(email["received_chain"]) == 2
    assert len(email["urls"]) == 2
    assert len(email["attachments"]) == 1

    auth = payload["authentication"]
    for section in ("spf", "dkim", "dmarc", "rspamd"):
        assert section in auth
    assert auth["rspamd"]["action"]
    assert auth["rspamd"]["score"] is not None
    assert auth["rspamd"]["required_score"] is not None
    # The fixture has no real authentication infrastructure: results must be
    # recorded as none/unknown, never invented as pass or fail.
    assert auth["spf"]["result"] in {"none", "unknown"}
    assert auth["dkim"]["result"] in {"none", "unknown"}
    assert auth["dmarc"]["result"] in {"none", "unknown"}
    assert auth["rspamd"]["message_id"] == "step1-fixture@example.test"
