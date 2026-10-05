"""Unicode safety for evidence strings (production bug fix).

Emails routinely carry malformed bytes. The standard-library parser decodes
raw 8-bit header content with ``surrogateescape``, which leaves UNPAIRED
UTF-16 surrogates (U+D800–U+DFFF) inside extracted Python strings. Such
strings cannot be UTF-8 encoded, so any downstream JSON response fails with
``UnicodeEncodeError: surrogates not allowed`` — a production 500.

Policy (deterministic, evidence-preserving):

- A lone surrogate is replaced 1:1 by U+FFFD (REPLACEMENT CHARACTER), the
  same convention the body decoder already applies via ``errors="replace"``.
- Everything else — valid text, emoji/astral characters, control characters —
  is preserved byte-for-byte.
- Nothing is discarded: one malformed character never destroys the evidence
  around it.

This module is the single definition of "safe evidence text" for every
extraction surface: headers (raw and typed), addresses, subjects,
Message-IDs, Received chains, bodies, attachment filenames, URLs and
parser-defect descriptions.
"""

from __future__ import annotations

_REPLACEMENT = "\ufffd"


def has_lone_surrogates(value: str) -> bool:
    """True when ``value`` contains unpaired UTF-16 surrogate code points."""

    if isinstance(value, str):
        return any(0xD800 <= ord(char) <= 0xDFFF for char in value)
    return False


def sanitize_unicode_text(value: str) -> str:
    """Return ``value`` with every unpaired surrogate replaced by U+FFFD.

    Replacement is exactly 1:1 (one U+FFFD per surrogate code point), so
    string length and every other character are preserved. Fast path:
    strings without surrogates (the overwhelming majority) are returned
    unchanged with zero allocations.
    """

    if not isinstance(value, str) or not has_lone_surrogates(value):
        return value
    # Per-code-point replacement: encode/decode round-trips would expand a
    # single surrogate into several U+FFFD (UTF-8 resync), which would distort
    # evidence lengths; the explicit map keeps the replacement deterministic.
    return "".join(
        _REPLACEMENT if 0xD800 <= ord(char) <= 0xDFFF else char for char in value
    )


__all__ = ["has_lone_surrogates", "sanitize_unicode_text"]
