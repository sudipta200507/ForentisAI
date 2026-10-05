"""Shared application constants (single source of truth for limits)."""

# Engine version reported in analysis metadata and reports.
APP_VERSION = "0.1.0"

# Step 1 email size limit. The API reuses this limit; it must not define a
# second, conflicting value.
DEFAULT_MAX_UPLOAD_SIZE_BYTES = 25 * 1024 * 1024

# Multipart requests carry boundaries and part headers in addition to the
# file bytes, so the transport-level request guard allows a small margin above
# the file limit.
UPLOAD_REQUEST_OVERHEAD_BYTES = 1 * 1024 * 1024
MAX_ANALYZE_REQUEST_BYTES = DEFAULT_MAX_UPLOAD_SIZE_BYTES + UPLOAD_REQUEST_OVERHEAD_BYTES
