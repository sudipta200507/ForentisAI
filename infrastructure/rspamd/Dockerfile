# Optional custom Rspamd image for ForentisAI.
#
# The local stack (repository-root docker-compose.yml) uses the official
# rspamd/rspamd image directly, which is sufficient for local development.
# Build this image only when the deployment needs custom Rspamd
# configuration, extra rules, or a pinned version:
#
#   docker build -t forentisai-rspamd ./infrastructure/rspamd
#
# then switch the compose service from `image: rspamd/rspamd:latest` to
# `build: ./infrastructure/rspamd`.
FROM rspamd/rspamd:latest

# Custom configuration files (if any) belong in ./config/ next to this
# Dockerfile and are copied to the Rspamd config overrides directory.
# COPY config/ /etc/rspamd/local.d/
