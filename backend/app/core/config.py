"""Environment-based configuration without hard-coded secrets."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


DEFAULT_RSPAMD_URL = "http://127.0.0.1:11333"
DEFAULT_RSPAMD_TIMEOUT_SECONDS = 30.0
DEFAULT_RSPAMD_SCAN_PATH = "/checkv2"
DEFAULT_API_CORS_ORIGINS: tuple[str, ...] = (
    "http://localhost:5173",
    "http://localhost:3000",
)

# Step 5 AI defaults. Model artifacts live under <project>/ai/models; paths
# are always derived from the repository layout or environment variables,
# never from machine-specific hard-coded locations.
DEFAULT_AI_MODEL_DIR = Path("ai") / "models"
# Official fine-tuned DeBERTa-v3 email-threat classifier artifact directory
# (relative to the project root; trained on ForentisAI_DeBERTa_Dataset_V2).
# This is the DEFAULT NLP artifact location: it is resolved against the
# project root and stays a local, git-ignored deployment artifact.
DEFAULT_NLP_MODEL_DIR = Path("ai") / "models" / "nlp" / "forentisai_deberta_v3"
DEFAULT_NLP_MODEL_NAME = "microsoft/deberta-v3-base"
DEFAULT_TECHNICAL_MODEL_FILENAME = "technical_model.joblib"
DEFAULT_AI_MAX_TEXT_LENGTH = 6000
DEFAULT_AI_INFERENCE_TIMEOUT_SECONDS = 20.0


def _env_float(name: str, default: float) -> float:
    raw_value = os.environ.get(name)
    if raw_value is None or not raw_value.strip():
        return default
    try:
        return float(raw_value)
    except ValueError:
        return default


@dataclass(frozen=True, slots=True)
class RspamdSettings:
    """Rspamd connection settings sourced from environment variables.

    ``RSPAMD_URL`` defaults to the host loopback publish of the Compose
    service (ports are bound to 127.0.0.1 only). Code running INSIDE the
    Docker Compose network must instead set ``RSPAMD_URL=http://rspamd:11333``
    to reach the service by its internal DNS name.
    """

    url: str = DEFAULT_RSPAMD_URL
    timeout_seconds: float = DEFAULT_RSPAMD_TIMEOUT_SECONDS
    scan_path: str = DEFAULT_RSPAMD_SCAN_PATH


def load_rspamd_settings() -> RspamdSettings:
    """Build Rspamd settings from ``RSPAMD_URL`` and ``RSPAMD_TIMEOUT_SECONDS``."""

    raw_url = (os.environ.get("RSPAMD_URL") or "").strip()
    return RspamdSettings(
        url=raw_url.rstrip("/") or DEFAULT_RSPAMD_URL,
        timeout_seconds=max(
            _env_float("RSPAMD_TIMEOUT_SECONDS", DEFAULT_RSPAMD_TIMEOUT_SECONDS),
            0.1,
        ),
        scan_path=DEFAULT_RSPAMD_SCAN_PATH,
    )


@dataclass(frozen=True, slots=True)
class AuthSettings:
    """Authentication orchestration mode (Phase 4 degraded mode).

    ``strict_mode=True`` (default) preserves the historical behavior: when
    Rspamd cannot be reached the analysis request fails with a controlled
    503 — authentication is mandatory.

    ``strict_mode=False`` (``FORENTISAI_AUTH_STRICT=false``) enables
    DEGRADED mode: a Rspamd infrastructure failure becomes an explicit
    ``unavailable`` authentication status and the analysis continues with
    the remaining evidence. Model and risk-engine confidence is reduced and
    the response states the limitation. Authentication failure is NEVER
    converted into a passing result.
    """

    strict_mode: bool = True


def load_auth_settings() -> AuthSettings:
    """Build auth-mode settings from ``FORENTISAI_AUTH_STRICT``."""

    return AuthSettings(
        strict_mode=_env_bool("FORENTISAI_AUTH_STRICT", True),
    )


@dataclass(frozen=True, slots=True)
class IntelligenceEnvSettings:
    """Step 4 intelligence bounds sourced from environment variables.

    All values are defensive bounds: timeouts cap each external lookup and
    the ``max_*`` caps bound how many indicators are enriched per analysis.
    """

    dns_timeout_seconds: float = 3.0
    dns_lifetime_seconds: float = 6.0
    rdap_timeout_seconds: float = 10.0
    max_ips: int = 32
    max_domains: int = 32
    max_urls: int = 64
    perform_dns: bool = True
    perform_rdap: bool = True


def _env_bool(name: str, default: bool) -> bool:
    raw_value = os.environ.get(name)
    if raw_value is None or not raw_value.strip():
        return default
    return raw_value.strip().casefold() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    raw_value = os.environ.get(name)
    if raw_value is None or not raw_value.strip():
        return default
    try:
        return max(minimum, int(raw_value))
    except ValueError:
        return default


def load_intelligence_env_settings() -> IntelligenceEnvSettings:
    """Build intelligence settings from ``DNS_INTELLIGENCE_*``/``RDAP_*`` env vars."""

    return IntelligenceEnvSettings(
        dns_timeout_seconds=max(
            _env_float("DNS_INTELLIGENCE_TIMEOUT_SECONDS", 3.0),
            0.1,
        ),
        dns_lifetime_seconds=max(
            _env_float("DNS_INTELLIGENCE_LIFETIME_SECONDS", 6.0),
            0.1,
        ),
        rdap_timeout_seconds=max(
            _env_float("RDAP_INTELLIGENCE_TIMEOUT_SECONDS", 10.0),
            0.1,
        ),
        max_ips=_env_int("INTELLIGENCE_MAX_IPS", 32),
        max_domains=_env_int("INTELLIGENCE_MAX_DOMAINS", 32),
        max_urls=_env_int("INTELLIGENCE_MAX_URLS", 64),
        perform_dns=_env_bool("INTELLIGENCE_PERFORM_DNS", True),
        perform_rdap=_env_bool("INTELLIGENCE_PERFORM_RDAP", True),
    )


@dataclass(frozen=True, slots=True)
class AISettings:
    """Step 5 AI pipeline settings sourced from environment variables.

    ``model_dir`` is the default location for the technical model artifact;
    explicit ``technical_model_path``/``nlp_model_path`` overrides win when
    set. ``nlp_model_path`` defaults to the official fine-tuned ForentisAI
    artifact directory (``ai/models/nlp/forentisai_deberta_v3``, resolved
    against the project root); when that artifact is absent the NLP
    component reports an explicit ``model_not_found`` state — it never
    downloads anything. Relative paths are resolved against the project
    root (the parent of the ``backend`` package), so no machine-specific
    paths are hard-coded.
    """

    ai_enabled: bool = True
    model_dir: Path = DEFAULT_AI_MODEL_DIR
    technical_model_path: Path | None = None
    nlp_model_path: Path | None = None
    nlp_model_name: str = DEFAULT_NLP_MODEL_NAME
    max_text_length: int = DEFAULT_AI_MAX_TEXT_LENGTH
    inference_timeout_seconds: float = DEFAULT_AI_INFERENCE_TIMEOUT_SECONDS


def _project_root() -> Path:
    """Project root: the parent directory of the ``backend`` folder."""

    return Path(__file__).resolve().parents[3]


def _resolve_model_path(raw_value: str | None, default: Path) -> Path:
    """Resolve a configured model path against the project root when relative."""

    candidate = Path(raw_value) if raw_value and raw_value.strip() else default
    if not candidate.is_absolute():
        candidate = _project_root() / candidate
    return candidate


def load_ai_settings() -> AISettings:
    """Build AI settings from the ``AI_*`` environment variables."""

    model_dir = _resolve_model_path(
        os.environ.get("AI_MODEL_DIR"), DEFAULT_AI_MODEL_DIR
    )
    raw_technical = (os.environ.get("TECHNICAL_MODEL_PATH") or "").strip()
    raw_nlp = (os.environ.get("NLP_MODEL_PATH") or "").strip()
    return AISettings(
        ai_enabled=_env_bool("AI_ENABLED", True),
        model_dir=model_dir,
        technical_model_path=(
            _resolve_model_path(raw_technical, model_dir / DEFAULT_TECHNICAL_MODEL_FILENAME)
        ),
        # NLP defaults to the official fine-tuned ForentisAI artifact
        # directory; NLP_MODEL_PATH overrides it (relative paths resolve
        # against the project root). Never None: a missing artifact is an
        # explicit model_not_found state, not a silent skip.
        nlp_model_path=_resolve_model_path(raw_nlp, DEFAULT_NLP_MODEL_DIR),
        nlp_model_name=(os.environ.get("NLP_MODEL_NAME") or "").strip()
        or DEFAULT_NLP_MODEL_NAME,
        max_text_length=max(_env_int("AI_MAX_TEXT_LENGTH", DEFAULT_AI_MAX_TEXT_LENGTH), 256),
        inference_timeout_seconds=max(
            _env_float("AI_INFERENCE_TIMEOUT_SECONDS", DEFAULT_AI_INFERENCE_TIMEOUT_SECONDS),
            0.5,
        ),
    )


@dataclass(frozen=True, slots=True)
class DatabaseSettings:
    """Persistence settings (Phase 6).

    ``url`` defaults to a local SQLite file; any SQLAlchemy URL (e.g.
    PostgreSQL) is accepted. ``retention_days`` bounds how long derived
    analysis records are kept (0 = keep indefinitely). Raw email bodies are
    never stored regardless of these settings.
    """

    url: str = "sqlite:///./forentisai.db"
    retention_days: int = 30
    persist_enabled: bool = True


def load_database_settings() -> DatabaseSettings:
    """Build database settings from the ``FORENTISAI_DATABASE_*`` env vars."""

    raw_url = (os.environ.get("FORENTISAI_DATABASE_URL") or "").strip()
    retention_raw = (os.environ.get("FORENTISAI_RETENTION_DAYS") or "").strip()
    retention = 30
    if retention_raw:
        try:
            retention = max(0, int(retention_raw))
        except ValueError:
            retention = 30
    return DatabaseSettings(
        url=raw_url or "sqlite:///./forentisai.db",
        retention_days=retention,
        persist_enabled=_env_bool("FORENTISAI_PERSIST_ENABLED", True),
    )


@dataclass(frozen=True, slots=True)
class ApiSettings:
    """API process settings (CORS etc.) sourced from environment variables.

    CORS origins are restricted to known local development origins by default.
    Unrestricted origins combined with credentials are never enabled; change
    ``API_CORS_ORIGINS`` explicitly when the deployment topology changes.
    """

    cors_origins: tuple[str, ...] = DEFAULT_API_CORS_ORIGINS
    environment: str = "local"


def load_api_settings() -> ApiSettings:
    """Build API settings from ``API_CORS_ORIGINS`` and ``API_ENVIRONMENT``."""

    raw_origins = (os.environ.get("API_CORS_ORIGINS") or "").strip()
    origins = tuple(
        origin.strip().rstrip("/")
        for origin in raw_origins.split(",")
        if origin.strip()
    )
    environment = (os.environ.get("API_ENVIRONMENT") or "local").strip().casefold()
    return ApiSettings(
        cors_origins=origins or DEFAULT_API_CORS_ORIGINS,
        environment=environment,
    )


@dataclass(frozen=True, slots=True)
class SecuritySettings:
    """Phase 8 API security settings sourced from environment variables.

    ``api_keys`` comes from ``FORENTISAI_API_KEYS`` (comma-separated; empty
    by default). ``API_ENVIRONMENT=local`` (default) with no keys permits
    unauthenticated local development; any other environment fails closed.
    Rate limiting bounds requests per identity per window (in-memory).
    """

    api_keys: tuple[str, ...] = ()
    environment: str = "local"
    rate_limit_requests: int = 60
    rate_limit_window_seconds: float = 60.0


def load_security_settings() -> "SecuritySettings":
    """Build security settings from ``FORENTISAI_API_KEYS``/``API_*`` env vars."""

    from app.core.security import SecuritySettings as _SecuritySettings

    raw_keys = (os.environ.get("FORENTISAI_API_KEYS") or "").strip()
    keys = tuple(
        key.strip() for key in raw_keys.split(",") if key.strip()
    )
    environment = (os.environ.get("API_ENVIRONMENT") or "local").strip().casefold()
    return _SecuritySettings(
        api_keys=keys,
        environment=environment,
        rate_limit_requests=max(
            1, _env_int("API_RATE_LIMIT_REQUESTS", 60)
        ),
        rate_limit_window_seconds=max(
            0.1,
            _env_float("API_RATE_LIMIT_WINDOW_SECONDS", 60.0),
        ),
    )
