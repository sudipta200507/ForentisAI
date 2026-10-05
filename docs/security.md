# Security & Privacy

## Threat model for this MVP

ForentisAI processes UNTRUSTED email content. The design treats every part
of an uploaded email — headers, bodies, HTML, attachments, URLs — as
attacker-controlled input.

## Hard guarantees implemented in the backend

1. **No attachment execution.** Attachments are parsed as metadata
   (filename, size, content type) only; contents are never written to disk,
   executed, or opened.
2. **No arbitrary URL fetching.** URLs from emails are never visited or
   retrieved by the analysis pipeline. Intelligence lookups are restricted
   to DNS (A/AAAA/MX/TXT/NS for extracted domains) and RDAP/GeoIP for
   extracted IPs/domains — strict allowlist of protocols, bounded counts
   (`INTELLIGENCE_MAX_IPS/DOMAINS/URLS`) and timeouts.
3. **No raw email logging.** Logs and error responses never include email
   bodies, raw headers, or credentials; controlled error codes only.
4. **Bounded uploads.** 25 MiB per file enforced while streaming the upload;
   a transport-level guard bounds total request size; `.eml` extension
   check; the filename is display metadata only.
5. **Models are local.** The backend never downloads models at request time;
   NLP artifacts without the official `forentisai_model.json` manifest are
   refused.
6. **Fail-closed authentication posture.** Rspamd unavailability in strict
   mode (default) fails the request with 503 — a missing scan is never
   reported as a pass. Degraded mode (`FORENTISAI_AUTH_STRICT=false`) marks
   every protocol `unknown/unavailable` and continues with reduced
   confidence and an explicit limitation.

## API security (Phase 8)

- **API keys** come only from the environment (`FORENTISAI_API_KEYS`,
  comma-separated). Verified in constant time; compared with
  `Authorization: Bearer` or `X-API-Key`.
- **Fail-closed rule:** any non-local `API_ENVIRONMENT` with no configured
  keys rejects all security-scoped requests. Unauthenticated use is allowed
  only for `local`/`development` environments with zero keys configured.
- **Rate limiting:** per-identity sliding window (in-memory, single process;
  put a gateway limiter in front for horizontal deployments). Identities are
  SHA-256 hashed before storage — raw keys/IPs are never retained.
- **CORS:** explicit origin list from `API_CORS_ORIGINS`; credentials are
  never enabled, so a wildcard misconfiguration cannot become dangerous.
- **Request IDs:** client-supplied `X-Request-ID` values are sanitized to
  URL-safe characters (≤64 chars) or replaced — no header injection.
- **Error hygiene:** stable machine-readable codes; no stack traces,
  internal paths, or environment details in responses.

## Privacy architecture (Phase 6)

The database stores DERIVED data only:

| Never stored | Stored instead |
| --- | --- |
| Email body / HTML | body presence + lengths (as features) |
| Raw headers | hop count, parsed anomaly counts |
| Email addresses | `(domain, sha256-of-address)` pairs |
| Subject text | `(length, sha256)` |
| Attachment contents | filename/type/size metadata |

- `analysis_id` = UUIDv5(email SHA-256) — deterministic, content-derived;
  the same bytes map to the same id without revealing content.
- Indicators (IPs, domains, URL hosts) ARE stored in normalized form: they
  are the operational IOC data of the product and are required for
  correlation.
- Retention: `FORENTISAI_RETENTION_DAYS` (0 = keep) purges expired analyses
  and cascades to all child rows.
- Persistence is best-effort and can be disabled entirely with
  `FORENTISAI_PERSIST_ENABLED=false`.

## Chrome extension security posture

- Reads ONLY the Gmail message id from the URL hash; message content is
  fetched through the official Gmail API with the minimal
  `gmail.readonly` scope (browser-managed OAuth; no client secret exists in
  the extension).
- Sends raw email bytes only to the user-configured backend origin.
  Non-default origins require an explicit MV3 permission grant.
- Never executes attachments, never visits URLs, never stores message
  content (analysis results live in `chrome.storage.session`, cleared when
  the browser closes).
- The DeBERTa model is never bundled into the extension; inference is
  server-side only.

## Operational checklist before any shared deployment

1. Set `API_ENVIRONMENT` to a non-local value AND configure
   `FORENTISAI_API_KEYS` (generate with
   `python -c "import secrets; print(secrets.token_urlsafe(32))"`).
2. Override the PostgreSQL credentials from the local defaults.
3. Restrict `API_CORS_ORIGINS` to the exact dashboard/extension origins.
4. Put the stack behind TLS; the local compose binds to loopback only.
5. Size `API_RATE_LIMIT_*` for the real user base and add a gateway limiter
   for multi-worker deployments.

## Known limitations

- The in-memory rate limiter does not span processes.
- Correlation overlap is observational evidence only — it does not prove
  common attacker ownership (stated in every correlation response).
- Model metrics are synthetic/corpus-only; see
  [model_compatibility.md](model_compatibility.md) and the model disclosure
  in the README. No real-world detection-performance claim is made.
