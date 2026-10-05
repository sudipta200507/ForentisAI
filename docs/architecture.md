# Architecture

ForentisAI analyzes an original .eml file through independent, failure-isolated
pipelines and composes the results into one product response. This document
describes the current implemented system (local MVP).

## Data flow

```
original .eml bytes (never modified, never re-parsed)
   │
   ├─► Step 1  Email extraction        → EmailEvidence (headers, body, URLs,
   │                                     attachments metadata, received chain,
   │                                     SHA-256 of the original bytes)
   ├─► Step 2  Rspamd authentication   → AuthenticationEvidence (SPF/DKIM/DMARC
   │                                     symbol interpretation; PASS ≠ SAFE)
   ├─► Step 4  Intelligence            → IntelligenceEvidence (DNS, RDAP,
   │                                     geolocation, domain/URL intel; every
   │                                     failure degrades to an explicit state)
   ├─► Step 5  AI models               → AIAnalysis (MODEL EVIDENCE ONLY)
   │     ├─ 48-feature deterministic vector (app/features)
   │     ├─ Technical ML: RandomForest, v3 artifact, 28 features, θ=0.33
   │     ├─ NLP: fine-tuned DeBERTa-v3 (local-only, manifest-checked)
   │     ├─ Fusion: mode-aware weighted combination (full/degraded/rule-based)
   │     └─ Explainability: SHAP (technical model), textual + structured reasons
   │
   ├─► Phase 3  Risk engine            → RiskAssessment (deterministic 0–100,
   │                                     verdict/severity/confidence; model
   │                                     probability ≠ final risk)
   ├─► Phase 5A Forensics              → ForensicEvidence (received-chain hop
   │                                     classification; no attribution)
   └─► Phase 6  Persistence            → PostgreSQL/SQLite (derived data only)
         └─► Phase 7  Reports          → JSON/HTML (full or stored-derived)
               └─► Phase 16 Correlation → indicator overlap between stored
                                          analyses (NOT attribution)
```

## Isolation guarantees

- **Step isolation:** a failure in one step never destroys evidence already
  collected by another. Intelligence, AI, risk and forensics each degrade to
  explicit statuses inside their response sections.
- **Model isolation:** model load or inference failures become
  `unavailable`/`error` states — never a benign prediction. Inference runs
  under a per-model timeout in a worker thread.
- **Persistence isolation:** persistence is best-effort; a database outage
  never breaks an analysis response.
- **Fusion honesty:** the response states which models contributed
  (`fusion.model_status`) and the fusion `mode` (full / degraded).
- **Risk separation:** model probabilities and the final risk score are
  distinct fields; the risk engine is a documented deterministic composite.

## Privacy architecture

- Raw email bodies, full HTML, and raw headers are NEVER persisted.
- Sender/recipient identity is stored as `(domain, sha256-of-address)` pairs.
- Subjects are stored as `(length, sha256)`.
- `analysis_id` is UUIDv5 over the email SHA-256 — deterministic,
  content-derived, no content stored.
- Retention (`FORENTISAI_RETENTION_DAYS`) purges expired derived records.
- The extension sends email content only to the user-configured backend.

See [security.md](security.md) for the API-security model and
[DASHBOARD_AND_EXTENSION.md](DASHBOARD_AND_EXTENSION.md) for the client
architecture.

## Repository layout

```
backend/app/
  extractor/        Step 1 email parsing (mail-parser, 25 MiB limit)
  authentication/   Step 2 Rspamd client + SPF/DKIM/DMARC interpretation
  intelligence/     Step 4 DNS / RDAP / GeoIP / domain / URL intelligence
  features/         48-feature deterministic vector
  ai/               Step 5: technical_ml/, nlp/, fusion/, explainability/,
                    orchestrator, model registry
  ai/risk/          Phase 3 deterministic risk engine
  forensics/        Phase 5A received-chain forensics
  database/         Phase 6 SQLAlchemy models, repositories, retention
  reports/          Phase 7 report payloads + HTML renderer
  correlation/      Phase 16 indicator correlation (V1)
  api/routes/       analysis, analyses, reports, correlation, health
  core/             config, security (API keys, rate limit), constants
  schemas/          Pydantic contracts (email, authentication, intelligence,
                    ai, risk, forensics, features)
ai/models/          Production artifacts (DeBERTa directory + RF joblib) —
                    mounted read-only into containers, never baked into images
extension/          Chrome MV3 extension (Phases 10–14)
frontend/           React dashboard (Phase 15)
samples/            Synthetic test emails
docs/               This documentation set
```

## Deployment topology (local)

`docker compose up -d` starts:

- **postgres 16** (loopback-only 5432) — derived records;
- **rspamd** (loopback-only 11333/11334) — authentication scanning;
- **backend** (loopback-only 8000) — FastAPI/uvicorn with the AI models
  mounted read-only from `./ai/models`.

The React dashboard (`npm run dev` in `frontend/`) proxies `/api` to the
backend; the Chrome extension talks to the backend origin directly.
