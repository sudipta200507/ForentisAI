# API Reference (local MVP)

Base URL (local stack): `http://127.0.0.1:8000` — interactive docs at
`http://127.0.0.1:8000/docs` (OpenAPI). All endpoints except `/health*` are
security-scoped: with `FORENTISAI_API_KEYS` configured or a non-local
`API_ENVIRONMENT` they require `Authorization: Bearer <key>` or
`X-API-Key: <key>`.

## POST /analyze-email

Analyze one original `.eml` file through the complete pipeline.

- Request: `multipart/form-data`, field `upload` (max 25 MiB).
- Success: `200` with the product response.
- Controlled errors (machine-readable `error.code`):
  `unsupported_format` (415), `empty_file` (400), `file_too_large` (413),
  `malformed_email` (422), `invalid_email` (400), `rspamd_unavailable`
  (503, strict mode), `rspamd_timeout` (504), `rspamd_invalid_response`
  (502), `unauthorized` (401), `rate_limit_exceeded` (429).

Response sections (all derived; raw email never persisted):

| Section | Content |
| --- | --- |
| `analysis_id` | UUIDv5 over the email SHA-256 (deterministic) |
| `email` | Step 1 evidence: headers, body presence, URLs, attachments metadata, received chain, SHA-256 |
| `authentication` | SPF/DKIM/DMARC results + Rspamd scan facts; PASS ≠ SAFE |
| `intelligence` | DNS/RDAP/GeoIP/domain/URL intel with provenance; explicit failure states |
| `ai` | `nlp`, `technical_ml`, `fusion` (with `mode` + `model_status`), `explainability` (SHAP contributions, textual + structured explanations) |
| `risk` | 0–100 `risk_score`, `verdict`, `severity`, `confidence`, threat types, reasons, contributing signals, model contributions, limitations |
| `forensics` | Received-chain hop classification (no attribution) |
| `metadata` | Timestamp, processing time, engine + model versions |

Degraded operation: with `FORENTISAI_AUTH_STRICT=false` an unreachable Rspamd
becomes `authentication.* = unknown/unavailable` and analysis continues with
an explicit limitation; in strict mode (default) it is a 503.

## GET /analyses

Recent stored analyses (derived data only). `?limit=1..200` (default 50).
Returns summary rows: `analysis_id`, `created_at`, `filename`, `risk_score`,
`verdict`, `severity`, `confidence`, `primary_threat_type`,
`sender_domain`, `url_count`, `model_status`, …

## GET /analyses/{analysis_id}

The full persisted derived record: risk snapshot (`threat_assessment`),
indicators, evidence (explanations, risk signals, forensic hops), and
privacy-safe email metadata. `404 not_found` when absent.

## POST /reports/generate?format=json|html

Generate a FULL report from an analysis response the caller already holds
(the body is the complete `/analyze-email` response JSON).

## GET /reports/{analysis_id}?format=json|html

Reconstruct a PARTIAL report from the stored derived record; explicitly
lists what was not retained. `404 not_found` when absent.

## Correlation (Phase 16) — overlap evidence, NOT attribution

| Endpoint | Description |
| --- | --- |
| `GET /correlation/indicators/{type}?value=` | Analyses observing one indicator. `type` ∈ `ipv4, ipv6, domain, hostname, url`; URL values correlate by host. `?limit=` |
| `GET /correlation/analyses/{analysis_id}?limit=` | Analyses sharing ≥1 normalized indicator (incl. sender/Reply-To/Message-ID domains) |
| `GET /correlation/graph?max_analyses=&max_indicators=` | Bipartite analysis↔indicator graph |
| `GET /correlation/similarity?analysis_id_a=&analysis_id_b=` | Jaccard overlap of two analyses |

Every correlation response carries an `interpretation` field stating that
overlap does not prove common attacker ownership.
Error: `invalid_indicator_type` (400).

## GET /health

API liveness only: `{"status": "ok", "service": "forentisai-api"}`.

## GET /health/rspamd

Dependency status: `{"rspamd_available": true|false, "detail": ...}`. The
API can be healthy while Rspamd is down; this endpoint distinguishes the two.

## Headers

- Every response carries `X-Request-Id` (client-supplied values are
  sanitized to URL-safe characters or replaced by a UUID).
- Rate limiting (per identity): `API_RATE_LIMIT_REQUESTS` per
  `API_RATE_LIMIT_WINDOW_SECONDS` → `429 rate_limit_exceeded`.
