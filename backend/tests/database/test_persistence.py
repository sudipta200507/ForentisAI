"""Phase 6 tests: privacy-first persistence with SQLAlchemy.

Every test uses an isolated SQLite database in tmp_path via environment
overrides; no test touches a real database or stores email content.
"""

from __future__ import annotations

import io

import pytest
from sqlalchemy import select
from fastapi.testclient import TestClient

from app.api import dependencies
from app.core.config import AISettings
from app.database import repositories
from app.database.models import (
    Analysis,
    AnalysisEvent,
    EmailMetadata,
    Evidence,
    Indicator,
    ThreatAssessment,
)
from app.database.session import (
    create_all,
    purge_expired_analyses,
    reset_engine_cache,
    session_scope,
)
from app.main import app as fastapi_app

# Small local .eml fixture (kept independent of tests/api/helpers.py).
SAMPLE_EML = (
    b"From: Alice Sender <alice@example.test>\r\n"
    b"To: Bob Recipient <bob@example.test>\r\n"
    b"Subject: API fixture\r\n"
    b"Date: Tue, 01 Apr 2025 10:30:00 +0000\r\n"
    b"Message-ID: <api-fixture@example.test>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Visit https://example.test/api-path for details.\r\n"
)


@pytest.fixture()
def db_env(tmp_path, monkeypatch):
    """Isolated SQLite DB + disabled AI models for fast tests."""

    monkeypatch.setenv(
        "FORENTISAI_DATABASE_URL", f"sqlite:///{(tmp_path / 'test.db').as_posix()}"
    )
    monkeypatch.setenv("FORENTISAI_RETENTION_DAYS", "30")
    monkeypatch.setenv("FORENTISAI_PERSIST_ENABLED", "true")
    settings = AISettings(
        ai_enabled=True,
        model_dir=tmp_path / "models",
        technical_model_path=tmp_path / "models" / "technical_model.joblib",
        nlp_model_path=None,
    )
    fastapi_app.dependency_overrides[dependencies.get_ai_settings] = lambda: settings
    reset_engine_cache()
    create_all()
    yield
    fastapi_app.dependency_overrides.pop(dependencies.get_ai_settings, None)
    reset_engine_cache()


@pytest.fixture()
def persist_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "FORENTISAI_DATABASE_URL", f"sqlite:///{(tmp_path / 'off.db').as_posix()}"
    )
    monkeypatch.setenv("FORENTISAI_PERSIST_ENABLED", "false")
    reset_engine_cache()
    create_all()  # tables exist; nothing may be written
    yield
    reset_engine_cache()


def _post(client: TestClient) -> dict:
    response = client.post(
        "/analyze-email",
        files={"upload": ("upload.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")},
    )
    assert response.status_code == 200
    return response.json()


def _client() -> TestClient:
    return TestClient(fastapi_app)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_analysis_response_is_persisted(db_env) -> None:
    payload = _post(_client())

    with session_scope() as session:
        stored = session.execute(
            select(Analysis).where(Analysis.analysis_id == payload["analysis_id"])
        ).scalar_one_or_none()
        assert stored is not None
        assert stored.email_sha256 == payload["email"]["file"]["sha256"]
        assert stored.risk_score == pytest.approx(payload["risk"]["risk_score"])
        assert stored.verdict == payload["risk"]["verdict"]


def test_persistence_is_idempotent(db_env) -> None:
    client = _client()
    payload = _post(client)
    _post(client)  # same bytes → same analysis_id → no duplicate rows

    with session_scope() as session:
        rows = session.execute(
            select(Analysis).where(Analysis.analysis_id == payload["analysis_id"])
        ).scalars().all()
        assert len(rows) == 1


def test_email_metadata_stores_hashes_not_content(db_env) -> None:
    payload = _post(_client())

    with session_scope() as session:
        row = session.execute(select(EmailMetadata)).scalar_one_or_none()
        assert row is not None
        assert row.analysis_id is not None
        # Privacy: derived fields only.
        assert row.subject_length == len(payload["email"]["message"]["subject"] or "")
        assert row.subject_sha256
        assert row.sender_domain == "example.test"
        assert row.sender_sha256
        assert "alice@example.test" not in str(row.__dict__)
        assert row.received_hop_count == 0
        assert row.url_count == 1


def test_indicators_are_stored_with_provenance(db_env) -> None:
    _post(_client())

    with session_scope() as session:
        rows = session.execute(select(Indicator)).scalars().all()
        values = {row.value for row in rows}
        assert "https://example.test/api-path" in values
        assert all(row.type in {"ipv4", "ipv6", "hostname", "domain", "url"} for row in rows)
        assert all(row.source_kind for row in rows)


def test_evidence_rows_exclude_raw_content(db_env) -> None:
    _post(_client())

    with session_scope() as session:
        rows = session.execute(select(Evidence)).scalars().all()
        assert rows, "at least one evidence row is expected"
        blob = " ".join(row.detail for row in rows).casefold()
        assert "visit https" not in blob  # body text never stored


def test_threat_assessment_snapshot(db_env) -> None:
    payload = _post(_client())

    with session_scope() as session:
        rows = session.execute(select(ThreatAssessment)).scalars().all()
        assert len(rows) == 1
        assessment = rows[0]
        assert assessment.risk_score == pytest.approx(payload["risk"]["risk_score"])
        assert assessment.thresholds["suspicious"] == 45.0
        assert isinstance(assessment.contributing_signals, list)
        assert isinstance(assessment.model_contributions, list)


def test_analysis_event_recorded(db_env) -> None:
    _post(_client())

    with session_scope() as session:
        rows = session.execute(select(AnalysisEvent)).scalars().all()
        assert len(rows) == 1
        assert rows[0].event_type == "analyzed"


def test_persist_disabled_writes_nothing(persist_disabled) -> None:
    _post(_client())

    with session_scope() as session:
        assert session.execute(select(Analysis)).scalars().first() is None


def test_repository_persist_failure_is_contained(db_env, monkeypatch) -> None:
    """A database failure must never propagate to callers."""

    payload = _post(_client())  # type: ignore[arg-type]

    def _explode(_session, _response):
        raise RuntimeError("db exploded")

    monkeypatch.setattr(repositories, "_persist", _explode)
    assert repositories.persist_analysis(payload) is False


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------


def test_retention_purge_removes_old_analyses(db_env, monkeypatch) -> None:
    client = _client()
    payload = _post(client)

    from datetime import datetime, timedelta, timezone

    # Re-read with a 'now' far in the future: everything is expired.
    with session_scope() as session:
        stored = session.execute(
            select(Analysis).where(Analysis.analysis_id == payload["analysis_id"])
        ).scalar_one_or_none()
        assert stored is not None
        # Simulate age by moving created_at back beyond retention.
        stored.created_at = datetime.now(timezone.utc) - timedelta(days=60)

    removed = purge_expired_analyses()
    assert removed == 1

    with session_scope() as session:
        assert (
            session.execute(
                select(Analysis).where(Analysis.analysis_id == payload["analysis_id"])
            ).scalar_one_or_none()
            is None
        )
        # Children cascade: nothing orphaned.
        assert session.execute(select(EmailMetadata)).scalars().first() is None
        assert session.execute(select(Indicator)).scalars().first() is None
        assert session.execute(select(Evidence)).scalars().first() is None
        assert session.execute(select(ThreatAssessment)).scalars().first() is None
        assert session.execute(select(AnalysisEvent)).scalars().first() is None


def test_retention_zero_keeps_everything(db_env, monkeypatch) -> None:
    monkeypatch.setenv("FORENTISAI_RETENTION_DAYS", "0")
    _post(_client())
    assert purge_expired_analyses() == 0
    with session_scope() as session:
        assert session.execute(select(Analysis)).scalars().first() is not None


def test_recent_analyses_listing(db_env) -> None:
    _post(_client())
    rows = repositories.recent_analyses(limit=10)
    assert len(rows) == 1
    assert rows[0].analysis_id


def test_no_raw_body_in_any_table(db_env) -> None:
    _post(_client())
    body_text = "Visit https://example.test/api-path for details."
    with session_scope() as session:
        for model in (Analysis, EmailMetadata, Indicator, Evidence, ThreatAssessment, AnalysisEvent):
            rows = session.execute(select(model)).scalars().all()
            for row in rows:
                exported = {
                    key: str(value)
                    for key, value in row.__dict__.items()
                    if not key.startswith("_")
                }
                blob = str(exported).casefold()
                assert "for details" not in blob
