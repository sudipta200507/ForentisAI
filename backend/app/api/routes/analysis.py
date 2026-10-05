"""Analysis routes: the combined extraction + authentication + intelligence endpoint."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, UploadFile

import time
import uuid

from app.ai.orchestrator import build_ai_analysis
from app.ai.risk.scorer import assess_risk
from app.forensics.received_chain import build_forensic_evidence
from app.api import errors
from app.api.dependencies import (
    get_ai_settings,
    get_auth_settings,
    get_intelligence_settings,
    get_max_upload_bytes,
    get_rspamd_client,
)
from app.api.schemas import AnalysisMetadata, AnalysisResponse
from app.core.constants import APP_VERSION
from app.authentication.dmarc import build_authentication_evidence
from app.authentication.rspamd_client import (
    RspamdAnalysis,
    RspamdClient,
    RspamdError,
    RspamdInvalidEmailError,
    RspamdInvalidResponseError,
    RspamdTimeoutError,
)
from app.core.config import AISettings, AuthSettings, IntelligenceEnvSettings
from app.schemas.ai import AIAnalysis
from app.schemas.authentication import (
    AuthenticationEvidence,
    DkimEvidence,
    DmarcEvidence,
    SpfEvidence,
)
from app.extractor.email_parser import (
    EmailExtractionError,
    extract_email_from_bytes,
)
from app.intelligence.orchestrator import (
    IntelligenceSettings,
    build_intelligence_evidence,
)
from app.schemas.intelligence import IntelligenceEvidence

router = APIRouter(prefix="/analyze-email", tags=["analysis"])


def _validate_extension(filename: str | None) -> None:
    """Reject non-.eml uploads using the Step 1 strategy.

    The filename is treated as display metadata only; it is never used in any
    filesystem, shell, or network operation.
    """

    name = (filename or "").replace("\\", "/").rsplit("/", maxsplit=1)[-1]
    suffix = Path(name).suffix.casefold()
    if suffix != ".eml":
        raise errors.api_error("unsupported_format")


async def _read_upload(upload: UploadFile, max_upload_bytes: int) -> bytes:
    """Read the uploaded part while enforcing the single Step 1 file limit."""

    buffer = bytearray()
    while True:
        chunk = await upload.read(1024 * 1024)
        if not chunk:
            break
        buffer.extend(chunk)
        if len(buffer) > max_upload_bytes:
            raise errors.api_error("file_too_large")
    return bytes(buffer)


def _perform_rspamd_scan(client: RspamdClient, raw_email: bytes) -> RspamdAnalysis:
    """Scan the ORIGINAL bytes; controlled Rspamd failures become ApiErrors."""

    try:
        return client.scan_bytes(raw_email)
    except RspamdInvalidEmailError as error:
        raise errors.api_error("invalid_email") from error
    except RspamdTimeoutError as error:
        raise errors.api_error("rspamd_timeout") from error
    except RspamdInvalidResponseError as error:
        raise errors.api_error("rspamd_invalid_response") from error
    except RspamdError as error:
        raise errors.api_error("rspamd_unavailable") from error


# Rspamd INFRASTRUCTURE failures that degraded mode may tolerate (the email
# itself is still scannable later; nothing about the message was learned).
_DEGRADABLE_RSPAMD_CODES = frozenset(
    {"rspamd_unavailable", "rspamd_timeout", "rspamd_invalid_response"}
)


def _unavailable_authentication(reason: str) -> AuthenticationEvidence:
    """Explicit 'could not scan' authentication evidence — never a pass.

    Used ONLY in degraded mode when Rspamd itself could not be reached. Every
    protocol stays ``result=unknown``/``available=unavailable`` so downstream
    consumers can distinguish 'not scanned' from 'scanned and passed'.
    """

    return AuthenticationEvidence(
        spf=SpfEvidence(result="unknown", available="unavailable"),
        dkim=DkimEvidence(result="unknown", available="unavailable"),
        dmarc=DmarcEvidence(result="unknown", available="unavailable"),
        rspamd=RspamdAnalysis(
            scanned=False,
            error=f"rspamd_scan_skipped:{reason}",
        ),
    )


def _intelligence_settings_from_env(
    env_settings: IntelligenceEnvSettings,
) -> IntelligenceSettings:
    """Translate cached env settings into one orchestrator settings object."""

    from app.intelligence.dns import DNSSettings
    from app.intelligence.rdap import RDAPSettings

    return IntelligenceSettings(
        dns=DNSSettings(
            timeout_seconds=env_settings.dns_timeout_seconds,
            lifetime_seconds=env_settings.dns_lifetime_seconds,
        ),
        rdap=RDAPSettings(timeout_seconds=env_settings.rdap_timeout_seconds),
        max_ips=env_settings.max_ips,
        max_domains=env_settings.max_domains,
        max_urls=env_settings.max_urls,
        perform_dns=env_settings.perform_dns,
        perform_rdap=env_settings.perform_rdap,
    )


@router.post("", response_model=AnalysisResponse, name="analyze_email")
async def analyze_email(
    upload: UploadFile = File(..., description="An original .eml file (multipart/form-data)."),
    client: RspamdClient = Depends(get_rspamd_client),
    max_upload_bytes: int = Depends(get_max_upload_bytes),
    intelligence_env: IntelligenceEnvSettings = Depends(get_intelligence_settings),
    ai_settings: "AISettings" = Depends(get_ai_settings),
    auth_settings: "AuthSettings" = Depends(get_auth_settings),
) -> AnalysisResponse:
    """Analyze one original .eml upload and return the product response.

    The uploaded bytes are passed byte-for-byte to four independent
    pipelines: Step 1 extraction (``EmailEvidence``), Step 2 Rspamd
    authentication (``AuthenticationEvidence``), Step 4 infrastructure
    intelligence (``IntelligenceEvidence``), and Step 5 AI model analysis
    (``AIAnalysis`` — model evidence only, never a verdict). The Phase 3
    risk engine composes the deterministic ``risk`` assessment from all
    available evidence, and Phase 5A derives forensic transport-path
    evidence (``forensics``, including the earliest reliable candidate).
    The email is never reconstructed, modified, or persisted. The upload
    limit is 25 MiB (the Step 1 limit; there is no second, conflicting
    API limit).

    ``analysis_id`` is a privacy-preserving deterministic identifier:
    UUIDv5 over the email's SHA-256 and the response schema version, so the
    same original bytes always map to the same analysis id without storing
    content.

    Intelligence, AI, and authentication providers degrade gracefully: a DNS
    timeout, an unconfigured GeoIP database, a missing AI model, or (in
    degraded auth mode) an unreachable Rspamd becomes an explicit status
    inside the respective section while ``email`` remains fully valid.
    """

    started_at = time.perf_counter()

    _validate_extension(upload.filename)

    raw_email = await _read_upload(upload, max_upload_bytes)
    if not raw_email:
        raise errors.api_error("empty_file")
    if len(raw_email) > max_upload_bytes:
        raise errors.api_error("file_too_large")

    try:
        evidence = extract_email_from_bytes(
            raw_email,
            filename=upload.filename or "uploaded.eml",
            max_size_bytes=max_upload_bytes,
        )
    except EmailExtractionError as error:
        raise errors.map_exception_to_api_error(error) from error

    try:
        analysis = _perform_rspamd_scan(client, raw_email)
    except errors.ApiError as error:
        # Phase 4 degraded mode: when auth is non-strict, an infrastructure
        # failure of the authentication SERVICE (not of the email) becomes an
        # explicit unavailable status and the analysis continues. Strict mode
        # (default) re-raises the controlled 503/504/502 unchanged.
        if (
            not auth_settings.strict_mode
            and error.code in _DEGRADABLE_RSPAMD_CODES
        ):
            analysis = None
            authentication = _unavailable_authentication(error.code)
        else:
            raise
    else:
        authentication = build_authentication_evidence(analysis)

    # Step 4 runs after authentication and never aborts the response: every
    # provider failure degrades to an explicit status inside IntelligenceEvidence.
    try:
        intelligence = build_intelligence_evidence(
            evidence,
            settings=_intelligence_settings_from_env(intelligence_env),
        )
    except Exception:
        # A total orchestrator failure still must not destroy the analysis.
        intelligence = IntelligenceEvidence()

    # Step 5 runs last: AI model failures are isolated to the ``ai`` section
    # and can never destroy the Step 1-4 evidence.
    try:
        ai_analysis = build_ai_analysis(
            evidence,
            authentication,
            intelligence,
            settings=ai_settings,
        )
    except Exception:
        # Defensive: build_ai_analysis is total, but a failure here must
        # still not destroy the analysis.
        ai_analysis = AIAnalysis()

    # Phase 3: deterministic risk assessment over ALL available evidence.
    try:
        risk = assess_risk(evidence, ai_analysis, authentication, intelligence)
    except Exception:
        # Defensive: assess_risk is total, but a failure must never destroy
        # the Step 1-5 evidence already collected.
        from app.schemas.risk import RiskAssessment

        risk = RiskAssessment(
            risk_score=0.0,
            verdict="inconclusive",
            severity="info",
            confidence=0.0,
            limitations=["Risk assessment failed unexpectedly; no score available."],
        )

    # Phase 5A: forensic transport-path evidence (never attacker attribution).
    try:
        forensics = build_forensic_evidence(evidence)
    except Exception:
        from app.schemas.forensics import ForensicEvidence

        forensics = ForensicEvidence(
            limitations=["Forensic analysis failed unexpectedly."],
        )

    # Phase 5 metadata. The analysis id is UUIDv5 over the content hash —
    # deterministic, privacy-preserving, no content stored or logged.
    analysis_id = str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"forentisai:{evidence.file.sha256}")
    )
    elapsed_ms = round((time.perf_counter() - started_at) * 1000.0, 2)
    metadata = AnalysisMetadata(
        timestamp=datetime.now(timezone.utc).isoformat(),
        processing_time_ms=elapsed_ms,
        engine_version=APP_VERSION,
        model_versions={
            "nlp": ai_analysis.nlp.model_name if ai_analysis.nlp.available else None,
            "technical_ml": (
                ai_analysis.technical_ml.model_name
                if ai_analysis.technical_ml.available
                else None
            ),
        },
    )

    response = AnalysisResponse(
        analysis_id=analysis_id,
        email=evidence,
        authentication=authentication,
        intelligence=intelligence,
        ai=ai_analysis,
        risk=risk,
        forensics=forensics,
        metadata=metadata,
    )

    # Phase 6: persist derived data (privacy-first; best-effort). A database
    # failure NEVER breaks the analysis response. No raw email content is
    # ever passed to the persistence layer.
    try:
        from app.core.config import load_database_settings

        database_settings = load_database_settings()
        if database_settings.persist_enabled:
            from app.database.repositories import persist_analysis

            persist_analysis(response)
    except Exception:  # noqa: BLE001 - persistence must never break delivery
        pass

    return response
