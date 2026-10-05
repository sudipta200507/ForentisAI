"""Serialization safety net for API responses (production bug fix).

FastAPI's default ``JSONResponse`` renders with ``ensure_ascii=False`` and
then encodes UTF-8. Any lone surrogate that reaches the response — from a
bug in an evidence path we have not sanitized — would raise
``UnicodeEncodeError: surrogates not allowed`` and turn a finished analysis
into an HTTP 500.

``SanitizingJSONResponse`` renders identically for all well-formed content.
Only when the encoded payload actually contains unpaired surrogates does it
replace them 1:1 with U+FFFD and still deliver the FULL analysis. This is a
deterministic normalization, not error handling: no analysis is discarded,
no exception is swallowed, no fallback body is invented.

The primary fix for the reported bug lives at the extraction boundary
(``app.extractor.unicode_safety``); this class guarantees the invariant
"the API never emits non-UTF-8-encodable JSON" systemically.
"""

from __future__ import annotations

import json

from fastapi.responses import JSONResponse

from app.extractor.unicode_safety import sanitize_unicode_text


class SanitizingJSONResponse(JSONResponse):
    """JSONResponse that cannot fail on unpaired surrogate code points."""

    def render(self, content) -> bytes:  # noqa: ANN001 - matches stdlib signature
        # Identical rendering to the stock JSONResponse (fastapi JSONResponse
        # uses compact separators and ensure_ascii=False).
        raw = json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=None,
            separators=(",", ":"),
        )
        try:
            return raw.encode("utf-8")
        except UnicodeEncodeError:
            # Unpaired surrogates present: replace each one 1:1 with U+FFFD
            # using the same sanitizer as the extraction boundary, keeping
            # every other character (including astral/emoji) byte-identical.
            return sanitize_unicode_text(raw).encode("utf-8")


__all__ = ["SanitizingJSONResponse"]
