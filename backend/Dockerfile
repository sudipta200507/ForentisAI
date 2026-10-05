# ForentisAI backend image.
#
# DESIGN:
# - CPU-only PyTorch is installed from the official CPU index first; the
#   remaining requirements then resolve against the already-satisfied pin.
# - Model artifacts (the 700+ MB DeBERTa directory and the technical
#   joblib) are NEVER baked into the image: they are mounted read-only at
#   /models (see docker-compose.yml) or fetched by the deployment's model
#   artifact strategy (docs/deployment.md). A missing artifact is reported
#   by the API as an explicit model_not_found state.
# - Runs as an unprivileged user.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System dependencies kept minimal; no compilers are needed for the wheels
# used here.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# CPU-only torch wheel (~200 MB) from the official CPU index.
RUN pip install --no-cache-dir "torch==2.14.0+cpu" \
    --index-url https://download.pytorch.org/whl/cpu

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY tests ./tests
COPY pyproject.toml ./

# Unprivileged runtime user; /data is the writable location for a local
# SQLite fallback database when no external PostgreSQL is configured.
RUN useradd --create-home --uid 10001 forentisai \
    && mkdir -p /data \
    && chown -R forentisai:forentisai /data /app
USER forentisai

ENV FORENTISAI_DATABASE_URL=sqlite:////data/forentisai.db \
    AI_MODEL_DIR=/models \
    NLP_MODEL_PATH=/models/nlp/forentisai_deberta_v3 \
    TECHNICAL_MODEL_PATH=/models/technical_model.joblib \
    RSPAMD_URL=http://rspamd:11333

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
