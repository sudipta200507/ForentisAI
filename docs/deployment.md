# Deployment Guide

ForentisAI runs as three cooperating services:

```
Chrome Extension / Web Dashboard
        |
        v
FastAPI backend (uvicorn)  <--->  Rspamd (authentication scanning)
        |
        v
PostgreSQL (derived data only)
```

## 1. Local (no Docker)

Prerequisites: Python 3.11+, Docker (for Rspamd only).

```bash
# 1. Rspamd (loopback-bound ports 11333/11334)
docker compose up -d rspamd

# 2. Backend
cd backend
pip install -r requirements.txt
# CPU-only torch wheel:
#   pip install torch==2.14.0+cpu --index-url https://download.pytorch.org/whl/cpu
cp ../.env.example ../.env    # then edit
uvicorn app.main:app --reload --port 8000
```

API docs: http://127.0.0.1:8000/docs

The default `FORENTISAI_DATABASE_URL=sqlite:///./forentisai.db` is fine for
local development; the API creates tables at startup automatically.

## 2. Docker Compose stack (PostgreSQL + Rspamd + backend)

```bash
cp .env.example .env
# Set POSTGRES_PASSWORD and (for non-local use) FORENTISAI_API_KEYS in .env.
# Add the Chrome extension origin to API_CORS_ORIGINS if you use it.
docker compose up --build
```

| Service | Endpoint | Notes |
| --- | --- | --- |
| backend | http://127.0.0.1:8000 | FastAPI + AI pipeline |
| rspamd | http://127.0.0.1:11333 | scan API (`/checkv2`) |
| rspamd UI | http://127.0.0.1:11334 | local inspection only |
| postgres | 127.0.0.1:5432 | derived analysis records |

All published ports bind to the host loopback interface only.

## 3. Model artifacts (IMPORTANT)

The fine-tuned DeBERTa-v3 artifact is approximately **700+ MB**. It is a
deployment artifact and is **never** committed to Git, **never** baked into
the backend image, and **never** shipped inside the Chrome extension.

The backend reports missing artifacts explicitly (`model_not_found` in the
`ai.nlp` / `ai.technical_ml` sections of `/analyze-email`); it never
downloads models at request time and never silently substitutes a base
model as a phishing classifier.

Recommended artifact strategies (pick one):

1. **Git LFS** — store `ai/models/**` via Git LFS for a small team. Clone
   with `git lfs install && git lfs pull`. Do not enable LFS for the
   extension package.
2. **Release asset / model registry** — publish `forentisai_deberta_v3/`
   and `technical_model.joblib` as versioned release assets (or to an
   object store / model registry), then materialize them on the host:

   ```bash
   mkdir -p ai/models/nlp
   # example (release asset):
   curl -L -o ai/models/technical_model.joblib \
     https://<your-release-host>/forentisai/technical_model.joblib
   # example (archive containing the DeBERTa directory):
   unzip forentisai_deberta_v3.zip -d ai/models/nlp/
   ```

   Verify integrity against the SHA-256 values published with the release.
3. **Read-only volume mount (used by docker-compose.yml)** — keep the
   artifacts on the host at `./ai/models` and mount them into the backend
   container at `/models:ro`, with `AI_MODEL_DIR=/models`,
   `NLP_MODEL_PATH=/models/nlp/forentisai_deberta_v3`, and
   `TECHNICAL_MODEL_PATH=/models/technical_model.joblib`.

Required files for the NLP artifact directory:

```
ai/models/nlp/forentisai_deberta_v3/
  config.json
  model.safetensors
  tokenizer.json
  tokenizer_config.json
  forentisai_model.json      # official ForentisAI manifest (required)
  deployment_info.json
```

Without `forentisai_model.json` the loader refuses the artifact — a base
`microsoft/deberta-v3-base` directory is never accepted as a phishing
classifier.

The technical model is a single scikit-learn joblib artifact saved with
scikit-learn 1.6.x (`ai/models/technical_model.joblib`, 28-feature
contract, threshold 0.33; see `docs/model_compatibility.md`).

## 4. Environment variables

See `.env.example` for the annotated list. The most important:

| Variable | Purpose | Default |
| --- | --- | --- |
| `RSPAMD_URL` | Rspamd scan endpoint | `http://127.0.0.1:11333` |
| `FORENTISAI_AUTH_STRICT` | `false` enables degraded mode when Rspamd is down | `true` |
| `FORENTISAI_DATABASE_URL` | SQLAlchemy URL (SQLite or PostgreSQL) | `sqlite:///./forentisai.db` |
| `FORENTISAI_RETENTION_DAYS` | Derived-record retention (`0` = forever) | `30` |
| `FORENTISAI_API_KEYS` | Comma-separated API keys | empty (local only) |
| `API_ENVIRONMENT` | `local` allows anonymous; anything else fails closed | `local` |
| `API_CORS_ORIGINS` | Explicit CORS allowlist | localhost dev origins |
| `AI_MODEL_DIR` / `NLP_MODEL_PATH` / `TECHNICAL_MODEL_PATH` | Artifact locations | repo `ai/models` |

Secrets are only ever read from the environment and are never logged.

## 5. Production checklist

- [ ] `API_ENVIRONMENT=production` and `FORENTISAI_API_KEYS` set (fail-closed).
- [ ] `API_CORS_ORIGINS` restricted to the dashboard/extension origins.
- [ ] PostgreSQL backed by managed storage; `FORENTISAI_DATABASE_URL` set.
- [ ] Model artifacts materialized and verified by SHA-256.
- [ ] TLS terminated in front of the backend (reverse proxy / platform).
- [ ] Rate limiting either kept in-process (single worker) or moved to the
      gateway for horizontal scaling.
- [ ] Retention policy (`FORENTISAI_RETENTION_DAYS`) matched to policy.
- [ ] Logs reviewed: they must contain no email content, credentials, or keys.

## 6. Platform deployment files

`infrastructure/deployment/render.yaml` and `infrastructure/deployment/vercel.json`
are starting points for hosted frontend/backend deployments. They must be
adapted to the artifact strategy and secret management of the target
platform before use.
