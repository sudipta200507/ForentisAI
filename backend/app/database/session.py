"""Database engine and session management (Phase 6).

PostgreSQL-compatible SQLAlchemy architecture; SQLite is the default for
local development (``FORENTISAI_DATABASE_URL``). Privacy-first:

- persistence is configurable (``FORENTISAI_PERSIST_ENABLED``);
- raw email bodies are NEVER stored;
- retention is enforced by :func:`purge_expired_analyses`
  (``FORENTISAI_RETENTION_DAYS``, 0 = keep indefinitely).
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, delete, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import load_database_settings

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def _is_sqlite(url: str) -> bool:
    return url.strip().casefold().startswith("sqlite")


def get_engine(url: str | None = None) -> Engine:
    """Build (or return the cached) engine for the configured database URL.

    SQLite connections get foreign_keys enabled per connection so referential
    integrity matches PostgreSQL behavior.
    """

    global _engine, _session_factory
    if _engine is not None and url is None:
        return _engine

    settings = load_database_settings()
    effective_url = url or settings.url
    engine_kwargs: dict = {"future": True}
    if _is_sqlite(effective_url):
        engine_kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(effective_url, **engine_kwargs)

    if _is_sqlite(effective_url):

        @event.listens_for(engine, "connect")
        def _enable_sqlite_fk(dbapi_connection, _record):  # pragma: no cover
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    _session_factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    _engine = engine
    return engine


def create_all(engine: Engine | None = None) -> None:
    """Create all tables (idempotent; used for local dev and tests)."""

    from app.database.models import Base

    target = engine or get_engine()
    Base.metadata.create_all(target)


@contextmanager
def session_scope() -> Session:
    """Transactional scope: commit on success, roll back on any error."""

    if _session_factory is None:
        get_engine()
    assert _session_factory is not None
    session = _session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def reset_engine_cache() -> None:
    """Drop the cached engine/session factory (used by tests)."""

    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None


def purge_expired_analyses(
    *,
    now: datetime | None = None,
    session: Session | None = None,
) -> int:
    """Delete analyses (and children, via FK cascade) older than retention.

    ``FORENTISAI_RETENTION_DAYS=0`` disables purging (keep indefinitely).
    Returns the number of analyses removed.
    """

    from app.database.models import Analysis

    settings = load_database_settings()
    if settings.retention_days <= 0:
        return 0

    current = now or datetime.now(timezone.utc)
    cutoff = current - timedelta(days=settings.retention_days)

    own_session = session is None
    if own_session:
        session = session_scope().__enter__()  # type: ignore[assignment]
    assert session is not None
    try:
        result = session.execute(
            delete(Analysis).where(Analysis.created_at < cutoff)
        )
        if own_session:
            session.commit()
        return int(result.rowcount or 0)
    except Exception:
        if own_session:
            session.rollback()
        raise
    finally:
        if own_session:
            session.close()


__all__ = [
    "create_all",
    "get_engine",
    "purge_expired_analyses",
    "reset_engine_cache",
    "session_scope",
]
