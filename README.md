<<<<<<< HEAD
# ForentisAI

**AI-powered email threat detection and forensic intelligence platform.**
Upload an email (`.eml`) and get back evidence-based analysis: header
forensics, SPF/DKIM/DMARC authentication, DNS/RDAP infrastructure
intelligence, two AI models (DeBERTa-v3 NLP + technical RandomForest),
explainable fusion, and a deterministic, documented risk assessment.

Built for Smart India Hackathon 2026 (problem statement SIH26106).

---

## What it does

```text
                ┌──────────────────────────────────────────────────┐
 .eml upload ──►│  Step 1  Extraction        → EmailEvidence      │
 (bytes kept    │  Step 2  Rspamd auth       → AuthenticationEvidence
  intact)       │  Step 4  DNS/RDAP/GeoIP    → IntelligenceEvidence│
                │  Step 5  DeBERTa + RF +    → AIAnalysis          │
                │          fusion + SHAP                           │
                │  Step 3  Risk engine       → RiskAssessment      │
                │  Reports (JSON/HTML)       → forensic report     │
                └──────────────────────────────────────────────────┘
```

- **Extraction** — safe `.eml` parsing to derived JSON; original bytes are
  never modified, executed, or persisted.
- **Authentication** — Rspamd (Docker) scans the message; SPF/DKIM/DMARC
  results are normalized with authentication **result** and published
  **policy** kept as separate concepts (a domain publishing `p=quarantine`
  never makes a passing message fail).
- **Intelligence** — validated indicator extraction, bounded DNS/RDAP
  lookups, optional local MaxMind GeoIP. URLs are parsed, never visited.
- **AI models** — a fine-tuned DeBERTa-v3 artifact and a RandomForest over a
  28-feature contract, fused by a documented weighted mean, explained via
  SHAP and structured evidence rules. Model failures are explicit states,
  never silent benign guesses.
- **Risk engine** — deterministic, fully documented point system (see below).
- **Persistence & reports** — privacy-safe derived records in PostgreSQL
  (SQLite fallback for local dev); JSON/HTML forensic reports.

## What it does NOT do

Read this before trusting any number:

- Model artifacts were trained on **synthetic datasets**. The reported
  metrics are synthetic-corpus metrics only and establish **no real-world
  performance**. Independent evaluation on real email is still required.
- A model prediction, an authentication `pass`, or a risk score is
  **evidence, never a final security verdict**. The platform never claims an
  email is definitively malicious or safe.
- No URL fetching, no attachment execution, no email content sent to
  external services, no attacker attribution.
- GeoIP requires a local MaxMind database; without one the module reports
  `not_configured` instead of guessing.

## Repository layout

```text
backend/       FastAPI application, AI modules, tests (pytest)
frontend/      React + Vite operator dashboard
extension/     Chrome MV3 extension (Gmail + side panel)
ai/            model artifacts (Git LFS) and training scripts
samples/       .eml fixtures used by tests and manual runs
scripts/       dev utilities (fixture builder, icon generator)
infrastructure/  Dockerfiles + docker-compose note
docs/          architecture, API, deployment, security documentation
```

## Quick start

Prerequisites: **Python 3.11+**, **Node 18+**, **Docker Desktop**,
**Git LFS** (model artifacts are stored in LFS — install it *before*
cloning, then `git lfs pull` if files show as pointers).

### 1. Backend

```bash
cd backend
python -m venv .venv
.venv/Scripts/activate          # Windows (Git Bash: source .venv/Scripts/activate)
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

> PyTorch note: on CPU-only machines you can install the CPU wheel first —
> `pip install torch --index-url https://download.pytorch.org/whl/cpu` —
> then `pip install -r requirements.txt`.

```bash
# start the API (http://127.0.0.1:8000, docs at /docs)
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Without configuration the API runs with local defaults (SQLite persistence,
models from `ai/models/`). Copy `.env.example` to `.env` to configure
PostgreSQL, API keys, CORS, rate limits, and intelligence timeouts.

### 2. Rspamd (authentication analysis)

```bash
docker compose up -d rspamd      # 127.0.0.1:11333 (API), 11334 (UI)
docker compose stop rspamd       # to stop
```

While Rspamd is down, `POST /analyze-email` returns a controlled `503
rspamd_unavailable` (strict mode); degraded mode can be enabled explicitly.

### 3. Frontend dashboard

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173, proxies /api to :8000
```

### 4. Chrome extension

Load `extension/` via `chrome://extensions` → *Load unpacked*. Gmail
analysis uses OAuth — create your own Google Cloud OAuth client and put its
id in `extension/manifest.json` (the checked-in value is an intentional
`REPLACE_WITH_YOUR_OAUTH_CLIENT_ID` placeholder; the extension reports it as
unconfigured instead of failing silently). Full setup:
[extension/README.md](extension/README.md).

### 5. Analyze an email

```bash
curl -s -X POST http://127.0.0.1:8000/analyze-email \
  -F "upload=@samples/phishing/sample-1.eml" | python -m json.tool
```

Or open the dashboard and drop the file onto the upload zone.

## API

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/health` | GET | API liveness (never contacts Rspamd) |
| `/health/rspamd` | GET | Rspamd dependency availability |
| `/analyze-email` | POST | Full pipeline: upload → evidence → risk |
| `/analyses` | GET | Stored (privacy-safe derived) analyses |
| `/analyses/{id}` | GET | One stored analysis |
| `/reports/{id}?format=json\|html` | GET | Stored forensic report |
| `/reports/generate` | POST | Report from a client-held analysis |
| `/docs` | GET | Interactive OpenAPI documentation |

Controlled errors (never stack traces or content leaks): `400 empty_file`,
`413 file_too_large` (25 MiB), `415 unsupported_format`, `422
malformed_email`, `502/503/504` for Rspamd failures. See
[docs/api.md](docs/api.md).

## Risk engine (documented, deterministic)

The score is a capped sum of documented point tables
(`backend/app/ai/risk/scorer.py` docstring is the normative reference):

| Evidence | Points |
| --- | --- |
| NLP suspicious probability × 30 | max 30 |
| Technical-ML suspicious probability × 15 | max 15 |
| *(Fusion adds 0 — it is the weighted mean of the two, counted once)* | — |
| DMARC failed evaluation | 8 (published policy never scores by itself) |
| SPF fail / softfail | 6 / 3 |
| DKIM fail | 5 |
| Header anomalies (reply-to, return-path, message-id, missing date) | max 15 |
| URL indicators (IP literals, off-site domains, odd ports) | max 16 |
| Young linked domain (< 30 d / < 90 d) | 6 / 3 |
| Text keywords (credential / payment / urgency) | 10 / 5 / 3 |

Verdicts: `≥ 75 malicious`, `≥ 45 suspicious`, else `benign`; verdict is
`inconclusive` when neither models nor authentication produced evidence.
Confidence reflects corroborating sources and drops when evidence is
missing. Identical inputs always produce identical output. The score is a
heuristic composite — not a statistically calibrated detector.

## Models

Artifacts are tracked via **Git LFS** and loaded strictly locally:

- `ai/models/nlp/forentisai_deberta_v3/` — fine-tuned DeBERTa-v3
  (184M parameters, trained from `microsoft/deberta-v3-base`). Loaded only
  with a valid `forentisai_model.json` manifest; missing/invalid artifacts
  produce explicit `model_not_found` states, never fake predictions.
- `ai/models/technical_model.joblib` — RandomForest with the exact
  `technical-30-eml-v1` feature contract; contract mismatches are
  controlled `incompatible_model` states.

Retraining scripts and honesty rules: [docs/model_compatibility.md](docs/model_compatibility.md)
and `ai/training/`.

## Testing

```bash
cd backend
python -m pytest            # unit + integration (live tests excluded)
python -m pytest -m live    # opt-in live tests (need Rspamd / network)
```

The suite covers extraction, authentication normalization (including DMARC
result-vs-policy regression tests), intelligence, features, models, fusion,
explainability, the risk engine, API endpoints, security (rate limiting,
API keys), correlation, persistence, and reports. Live tests skip honestly
when their dependencies are unavailable.

## Security & privacy boundaries

- Original email bytes are analyzed in memory and never persisted; only
  derived, privacy-safe metadata is stored.
- No email content is logged; error responses never leak internals.
- Outbound requests are limited to DNS, RDAP (IANA bootstrap), and optional
  local GeoIP reads. User-supplied URLs are parsed, never fetched.
- API keys (fail-closed when configured), per-identity rate limiting,
  environment-based secrets. Details: [docs/security.md](docs/security.md).

## Documentation

- [docs/architecture.md](docs/architecture.md) — modules and data flow
- [docs/api.md](docs/api.md) — endpoints, schemas, errors
- [docs/deployment.md](docs/deployment.md) — configuration and production checklist
- [docs/security.md](docs/security.md) — threat-model-aligned boundaries
- [docs/model_compatibility.md](docs/model_compatibility.md) — model artifacts & contracts

## License

Released under the [MIT License](LICENSE).
=======
# ForentisAI
>>>>>>> origin/main
