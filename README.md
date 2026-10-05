# SIH 2026 Project
## AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform


## Step 5 — AI/ML Threat Analysis

Step 5 adds an AI layer that consumes the Step 1–4 evidence and produces
structured **model evidence** — never a final verdict, risk score, or
severity value. Those belong to later phases.

```text
EmailEvidence + AuthenticationEvidence + IntelligenceEvidence
      │
      ▼
Feature extraction (backend/app/features/, 48 deterministic features)
      │
      ├────────────────┬──────────────────────┐
      ▼                                       ▼
Technical ML (scikit-learn)          NLP (DeBERTa-v3, fine-tuned)
RandomForest over features           local inference on prepared text
      │                                       │
      └────────────────┬──────────────────────┘
                       ▼
               Fusion (deterministic weighted mean)
                       │
                       ▼
     Explainability (SHAP for the technical model;
     textual model signals for both)
                       │
                       ▼
                 AIAnalysis (model evidence only)
```

### Implementation status (read this before trusting any number)

| Component | Status |
| --- | --- |
| Feature pipeline | **Implemented** and deterministic |
| Technical ML (RandomForest) | **Implemented**; trained **only on a synthetic pipeline-validation fixture** — not a production model |
| DeBERTa-v3 NLP | **Implemented with the fine-tuned ForentisAI artifact** (`forentisai_deberta_v3`, 184,423,682 parameters, trained from `microsoft/deberta-v3-base`). Loaded strictly locally; the backend refuses any artifact without the official `forentisai_model.json` manifest |
| Fusion | **Implemented** (documented weighted mean) |
| Explainability | **Implemented** (SHAP TreeExplainer; linear fallback; graceful degradation) |
| Production validation | **Pending**: independent evaluation on REAL emails is still required — see `ai/datasets/README.md` |

**Evaluation honesty:** the NLP artifact was trained on
`ForentisAI_DeBERTa_Dataset_V2`, which is a **synthetic** dataset. Its
held-out V2 test metrics (accuracy/precision/recall/F1/ROC-AUC = 1.000 on
4,499 synthetic samples) are **synthetic-dataset metrics only**. They do
**not** establish real-world deployment performance, and no
"100% accurate phishing detector" claim may be made. Independent
real-email evaluation is still required before any production claim.

### Feature pipeline (`backend/app/features/`)

48 features with stable dotted names (contract:
`app.schemas.features.feature_names()`):

- `text.*` — subject/body lengths, HTML presence, credential/payment/urgency
  keyword counts (pattern signals, not verdicts);
- `header.*` — Received hop count, parser defects, sender/Reply-To /
  Return-Path / Message-ID domain mismatches (flagged only when both sides
  are determinable);
- `auth.*` — one-hot SPF/DKIM/DMARC results (all-zero = unknown, never
  guessed), Rspamd score as a Step 2 signal;
- `url.*` — URL counts, HTTPS ratio, IP-literal URLs, suspicious ports,
  registered-domain mismatches (reuses Step 4 decomposition when present);
- `intelligence.*` — public/non-public IP counts, DNS/RDAP/GeoIP outcome
  counts, youngest RDAP domain age (sentinel `-1.0` = not determinable).

Extraction is local-only, deterministic, exception-isolated per section, and
performs **no network requests**. Raw email text never crosses the feature
boundary — only numbers.

### Technical ML (`backend/app/ai/technical_ml/`)

`RandomForestClassifier` (200 trees, fixed seed, `n_jobs=1`) chosen because
the mixed-scale features need no preprocessing, interactions matter, and
feature importances give an honest fallback explanation. The artifact is a
custom bundle recording the exact feature contract; loading an artifact
trained against a different contract is a controlled `incompatible_model`
state, never a wrong prediction.

### DeBERTa-v3 NLP (`backend/app/ai/nlp/`)

Text preparation (subject + plain body, or subject + locally normalized
HTML-derived text, bounded to `AI_MAX_TEXT_LENGTH`), local inference with
`local_files_only=True` (never downloads at request time), and deterministic
keyword-pattern indicators (urgency, credential request, payment request,
authority claims, BEC-style requests, …) phrased as **model indicators**,
never "confirmed" findings.

The trained model's raw classes are `0 = benign`, `1 = malicious`. The
backend intentionally exposes the second class as **"suspicious"**, because
a model prediction is model evidence, not a final security verdict — the
raw label "malicious" is never surfaced as a verdict. The DeBERTa
probability alone decides the predicted class; keyword indicators are
supplementary signals and do not claim to explain the transformer's
internal reasoning.

### Fusion (`backend/app/ai/fusion/`)

`p_fused(suspicious) = Σ wᵢ·pᵢ / Σ wᵢ` over available components only
(equal 0.5 default weights, renormalized when one is missing; threshold 0.5
between model classes). Both unavailable → fusion `unavailable` (never a
benign guess). Disagreement between components is surfaced as a note, not
hidden.

### Explainability (`backend/app/ai/explainability/`)

SHAP `TreeExplainer` for the forest (relative to the suspicious class);
documented coefficient×value fallback for linear models (SHAP marked
unavailable there); explicit `unsupported_model` / `dependency_unavailable` /
`explanation_failed` states. SHAP is deliberately **not** claimed for the
transformer. Textual reasons are model signals, not verdicts.

### Model loading & resource safety (Phase O)

- Models load **once per artifact version** (path+size+mtime cache key) and
  are reused across requests; load failures are cached too.
- Retraining is picked up without a process restart.
- No training or downloads at import time or API startup; inference never
  downloads models.
- Inference runs under `AI_INFERENCE_TIMEOUT_SECONDS` and degrades to an
  explicit `inference_timeout` state.

### Configuration (environment variables)

| Variable | Default | Meaning |
| --- | --- | --- |
| `AI_ENABLED` | `true` | Master switch; `false` → explicit `not_enabled` states |
| `AI_MODEL_DIR` | `ai/models` | Base directory for artifacts (relative paths resolve against the project root) |
| `TECHNICAL_MODEL_PATH` | `$AI_MODEL_DIR/technical_model.joblib` | Technical artifact |
| `NLP_MODEL_PATH` | `ai/models/nlp/forentisai_deberta_v3` | Fine-tuned ForentisAI artifact directory (relative paths resolve against the project root; missing/invalid artifact → explicit `unavailable`, never a download) |
| `NLP_MODEL_NAME` | `microsoft/deberta-v3-base` | Base model the artifact was trained from (the base model itself is never used for prediction) |
| `AI_MAX_TEXT_LENGTH` | `6000` | Character bound on prepared model text |
| `AI_INFERENCE_TIMEOUT_SECONDS` | `20.0` | Per-model inference timeout |

### API integration

`POST /analyze-email` now returns `{schema_version, email, authentication,
intelligence, ai}`. The `ai` section carries model evidence with explicit
`available` / `unavailable` / `error` states. AI failures are isolated to
the `ai` section and can never destroy Step 1–4 evidence. There is **no**
`risk_score`, threat verdict, severity, or forensic report at this phase.

### Training commands (from `backend/`, venv active)

```bash
# Technical model — synthetic pipeline-validation fixture (NOT production):
python ../ai/training/generate_technical_fixture.py
python ../ai/training/train_technical_model.py --use-fixture

# Technical model — real dataset (default mode; refuses without one):
python ../ai/training/train_technical_model.py --dataset ../ai/datasets/external/<dataset>.json

# Transformer — requires a real labeled dataset (no fixture mode by design):
python ../ai/training/train_transformer.py --dataset ../ai/datasets/external/<labeled_text>.json
```

Artifacts land in `ai/models/` (git-ignored; large binaries are never
committed). Dataset requirements and the honesty rules are documented in
`ai/datasets/README.md`.

### Step 5 limitations

- **Real-world NLP performance is unproven.** The fine-tuned DeBERTa-v3
  artifact was trained and evaluated on the synthetic
  `ForentisAI_DeBERTa_Dataset_V2` (held-out V2 metrics: 1.000 across
  accuracy/precision/recall/F1/ROC-AUC on 4,499 samples). These are
  synthetic-dataset metrics only; independent real-email evaluation is
  still required.
- The technical RandomForest remains a synthetic pipeline-validation
  fixture model, not a production model.
- NLP keyword indicators are surface patterns; they complement — never
  replace — the model probability, and they do not explain the
  transformer's internal reasoning.
- SHAP contributions are attributions relative to the model's suspicious
  class, not evidence about the world.
- The registered-domain heuristic is conservative (no Public Suffix List),
  inherited from Step 4.
- Fusion weights are fixed and equal; a learned or calibrated fusion belongs
  to a later phase, together with real training data.

### Step 5 safety boundary

The AI layer never fetches URLs, never sends email content to any external
API, never executes attachments or downloaded content, never logs raw email
bodies/subjects/headers, and never turns a model failure into a benign
prediction. Model evidence is an input for later risk-scoring and reporting
phases — nothing in Step 5 decides whether an email is malicious or safe.

## Step 4 — Intelligence & Enrichment

Step 4 adds a modular infrastructure-intelligence layer on top of the
Step 1 evidence. It produces **evidence only** — never a threat verdict,
risk score, or confidence value:

```text
EmailEvidence (Step 1)
    │
    ├── IP extraction            (Received chain, validated)
    ├── Domain extraction        (sender, Reply-To, Return-Path, headers)
    └── URL parsing              (URLs already extracted by Step 1)
             │
             ▼
      Intelligence layer (backend/app/intelligence/)
             │
     ┌───────┼────────┐
     ▼       ▼        ▼
    DNS     RDAP    GeoIP (only if configured)
     │       │        │
     └───────┼────────┘
             ▼
   IntelligenceEvidence (normalized JSON)
```

### Modules

| Module | Responsibility |
| --- | --- |
| `intelligence/indicator_extractor.py` | Validated extraction of candidate IPs (IPv4/IPv6), domains, and URL indicators from `EmailEvidence`, each with provenance (`IndicatorSource`) |
| `intelligence/url_intelligence.py` | Parse-only URL decomposition: scheme, hostname, port, path, query, normalized hostname, conservative registered-domain guess. **URLs are never visited.** |
| `intelligence/ip_intelligence.py` | Local IP normalization and classification (public / RFC1918-private / loopback / link-local / multicast / reserved) |
| `intelligence/dns.py` | Bounded dnspython lookups (A, AAAA, MX, TXT, NS, CNAME) with explicit states |
| `intelligence/rdap.py` | Domain registration metadata via RDAP (IANA bootstrap), privacy-safe subset |
| `intelligence/geolocation.py` | MaxMind GeoLite2 lookups — active only when configured |
| `intelligence/domain_intelligence.py` | Combines normalized domain + DNS + RDAP evidence |
| `intelligence/orchestrator.py` | Composes everything into `IntelligenceEvidence`, per-run caps, graceful degradation |

### Lookup states (failure ≠ absence)

Every external lookup reports an explicit status; a failed query is **never**
reported as "no record":

| Status | Meaning |
| --- | --- |
| `success` | The lookup answered and returned data |
| `no_record` | The lookup answered: nothing exists (e.g. NXDOMAIN, HTTP 404) |
| `timeout` | The lookup did not answer in time |
| `error` / `unavailable` | Resolver/registry/HTTP-level failure |

The same contract applies per provider: a DNS timeout sets
`intelligence.domains[n].dns.status = "timeout"` and leaves the email and
authentication blocks untouched. GeoIP not configured yields
`available = false, reason = "not_configured"`. **An intelligence provider
failing never destroys the email analysis.**

### Provenance

Every indicator carries its origin, e.g.:

- IP `192.0.2.10` → `source: received_header, location: "received_header[0]"`
- URL `https://example.test/html-path` → `location: "body.html"`

Received-chain IPs are **candidate IPs only**. Step 4 makes no
"originating IP" or "attacker IP" claim; attribution reasoning belongs to a
later phase.

### Configuration (environment variables)

| Variable | Default | Purpose |
| --- | --- | --- |
| `DNS_INTELLIGENCE_TIMEOUT_SECONDS` | `3` | Per-query DNS timeout |
| `DNS_INTELLIGENCE_LIFETIME_SECONDS` | `6` | Total DNS resolution lifetime |
| `RDAP_INTELLIGENCE_TIMEOUT_SECONDS` | `10` | RDAP request timeout |
| `INTELLIGENCE_MAX_IPS` / `_DOMAINS` / `_URLS` | `32` / `32` / `64` | Per-analysis enrichment caps |
| `INTELLIGENCE_PERFORM_DNS` / `INTELLIGENCE_PERFORM_RDAP` | `true` | Provider kill switches |
| `MAXMIND_DB_PATH` | *(unset)* | GeoLite2-City.mmdb path; **unset = GeoIP disabled** |
| `MAXMIND_ASN_DB_PATH` | *(unset)* | GeoLite2-ASN.mmdb path (optional) |

### External network access — strict allowlist

Step 4 introduces controlled external lookups. **Only** these outgoing
requests exist:

1. DNS queries for validated domain/hostname indicators (dnspython);
2. RDAP queries built exclusively as `<IANA-bootstrap endpoint>/domain/<validated domain>`;
3. Local MaxMind database file reads (no network when configured).

There is no generic `fetch_url()`; user-supplied URLs never become HTTP
requests. URLs are parsed, never visited; redirects are never followed
(`follow_redirects=False`); attachments are never executed. RDAP HTTP 429 is
honored with its `Retry-After` hint. The IANA bootstrap file is cached
per process (one fetch per run).

### Privacy considerations

- RDAP evidence stores registrar, dates, nameservers, statuses, and entity
  **roles** only — registrant names, e-mails, and phone numbers are never
  copied into evidence;
- no email content (bodies, subjects, addresses) is logged by the
  intelligence modules;
- IP geolocation is approximate infrastructure intelligence — no exact
  physical-location claim is made;
- RDAP/DNS/GeoIP data is registration and infrastructure evidence only; it
  never proves who controls a domain or whether anything is malicious.

### Limitations

- Registered-domain extraction uses a conservative heuristic (common
  compound suffixes such as `co.uk` are refused rather than guessed); a
  Public Suffix List library is a deliberate future addition;
- GeoIP webservice mode is accepted in configuration but not implemented —
  only local `.mmdb` databases are read;
- reverse-DNS (PTR) lookups and DNS-based blocklists are out of scope;
- no caching layer yet (by design — see Step 4 plan §16);
- candidate IPs are not yet ranked by Received-chain reliability.

### Step 4 tests

153 unit tests in `backend/tests/intelligence/` cover all 24 plan sections
(extraction, provenance, DNS states, RDAP mocking, GeoIP degradation, schema
validation, resilience, and security guarantees). All external services are
faked; the unit suite never touches the network. A small set of controlled
live tests (only `example.com`/IANA domains, marked `live`) is excluded by
default and can be run explicitly:

```powershell
Push-Location backend
.\.venv\Scripts\python.exe -m pytest tests/intelligence -m live -v
Pop-Location
```

Live tests skip honestly (with the observed reason) when DNS, RDAP, or a
MaxMind database is unavailable — results are never fabricated.

## Step 3 — FastAPI Integration

The API composes the two evidence pipelines behind one endpoint:

```text
Upload (.eml, multipart/form-data)
    → Step 1 Email Extraction      → EmailEvidence
    → Step 2 Rspamd Authentication → AuthenticationEvidence
    → Combined JSON response
```

The uploaded bytes are passed byte-for-byte to both pipelines; the email is
never reconstructed, modified, persisted, or executed.

### Run the stack locally

```powershell
# 1. Start Rspamd (first run pulls rspamd/rspamd:latest)
docker compose up -d rspamd

# 2. Start the API
Push-Location backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
Pop-Location

# 3. Open the interactive API documentation
#    http://127.0.0.1:8000/docs
```

In `/docs`, use **POST /analyze-email** and upload a `.eml` file. The response
contains an `email` block (file, message, sender, recipients, body, headers,
received_chain, mime, urls, attachments, parser_defects), an
`authentication` block (spf, dkim, dmarc, rspamd), and an `intelligence`
block (indicators, urls, ips, domains, counts — see Step 4 above).

### Endpoints

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/health` | GET | API process liveness (never contacts Rspamd) |
| `/health/rspamd` | GET | Rspamd dependency availability (separate concern) |
| `/analyze-email` | POST | Combined extraction + authentication analysis |
| `/docs`, `/openapi.json` | GET | Automatic API documentation |

### Configuration (environment variables, see `.env.example`)

- `RSPAMD_URL` — default `http://127.0.0.1:11333` (host-side callers). Code
  inside the Compose network must set `http://rspamd:11333`.
- `RSPAMD_TIMEOUT_SECONDS` — scan timeout (default 30).
- `API_CORS_ORIGINS` — comma-separated allowed origins (default: local dev
  origins only). Never use `*` together with credentials.
- `API_ENVIRONMENT` — deployment label (default `local`).

### Upload limits and errors

The single upload limit is **25 MiB** (the Step 1 limit; the API defines no
second, conflicting limit). Common controlled errors:

| HTTP | `error.code` | Meaning |
| --- | --- | --- |
| 400 | `empty_file` | The uploaded file is empty |
| 400 | `invalid_file` / `invalid_email` | The upload could not be processed |
| 413 | `file_too_large` | The upload exceeds 25 MiB |
| 415 | `unsupported_format` | Only `.eml` files are accepted |
| 422 | `malformed_email` | Not a parseable RFC 5322 message |
| 502 | `rspamd_invalid_response` | Rspamd returned an invalid response |
| 503 | `rspamd_unavailable` | Rspamd is stopped or unreachable (start it with `docker compose up -d rspamd`) |
| 504 | `rspamd_timeout` | Rspamd did not answer in time |
| 500 | `internal_error` | Unexpected server error (no details leaked) |

Error responses never contain stack traces, raw email content, credentials, or
internal paths.

## Step 2 — Authentication Verification (Rspamd)

Step 2 runs Rspamd as a local Dockerized service and converts its scan output
into normalized authentication evidence:

```text
Raw Email (original bytes, never modified or reconstructed)
    ↓
Rspamd  (POST /checkv2, Dockerized service)
    ↓
SPF / DKIM / DMARC / Rspamd analysis symbols
    ↓
AuthenticationEvidence (normalized JSON)
```

The two pipelines stay separate and clean:

- original bytes → mail-parser → `EmailEvidence` (Step 1)
- original bytes → Rspamd → `AuthenticationEvidence` (Step 2)

### Authentication PASS is not "safe"

SPF/DKIM/DMARC results are **evidence, not a verdict**. A message with passing
authentication can still be malicious: legitimate accounts get compromised and
phishing is regularly sent from correctly authenticated infrastructure. Step 2
never converts authentication results into a safety statement, a risk score, or
a threat verdict — those belong to later phases.

### Start and stop Rspamd (local Docker)

```powershell
# Start (first run pulls rspamd/rspamd:latest)
docker compose up -d rspamd

# Verify it is running
docker ps

# Stop
docker compose stop rspamd
```

Both published ports are bound to host loopback only:
`127.0.0.1:11333` (normal worker `/checkv2` scanning API) and
`127.0.0.1:11334` (controller web interface). Inside the Compose network the
service is reachable as `rspamd`.

Configuration uses environment variables (see `.env.example`):

- `RSPAMD_URL` — default `http://rspamd:11333` for containerized callers; use
  `http://127.0.0.1:11333` for host-side processes.
- `RSPAMD_TIMEOUT_SECONDS` — scan request timeout (default 30).

### Step 2 tests

Unit tests mock all HTTP interaction; two integration tests run against the
live container and skip automatically when Rspamd is not running.

```powershell
Push-Location backend
.\.venv\Scripts\python.exe -m pytest -v
Pop-Location
```

## Step 1 — Email Data Extraction

This step converts a local `.eml` file into derived, normalized ForentisAI JSON:

```text
.eml → validation → SHA-256 → mail-parser/MIME parsing →
header, body, attachment, and URL extraction → normalized JSON
```

The original file bytes are never modified. The SHA-256 and file size are
calculated before parsing, while the normalized `EmailEvidence` object remains
a separate derived representation.

### Setup (PowerShell)

Python 3.11 or later is required. Python 3.13.5 was used to verify this
workspace.

```powershell
py -3.13 -m venv backend/.venv
.\backend\.venv\Scripts\Activate.ps1
python -m pip install -r backend/requirements.txt
```

### Run automated tests

```powershell
Push-Location backend
.\.venv\Scripts\python.exe -m pytest
Pop-Location
```

### Run a safe manual extraction summary

The command deliberately prints only filename, evidence hash, address fields,
subject/date, and counts. It does not print an email body or complete headers.

```powershell
Push-Location backend
.\.venv\Scripts\python.exe -m app.extractor.email_parser ..\samples\safe\step1_synthetic.eml
Pop-Location
```

### File-format support

`.eml` is supported. The installed `mail-parser 4.6.4` package has an optional
Outlook `.msg` conversion path, but it requires the uninstalled
`mail-parser[outlook]` / `extract-msg` backend (or its deprecated `msgconvert`
fallback). Therefore `.msg` files are explicitly rejected in Step 1 instead of
being parsed unreliably.

### Step 1 safety boundary

The extractor never executes attachments, visits URLs, or sends content to an
external service. Authentication headers are only preserved as evidence; no
SPF, DKIM, DMARC, ARC, threat-intelligence, AI, scoring, or reporting work is
performed in this phase.
