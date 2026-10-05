"""Extract and organize headers without performing authentication checks."""

from __future__ import annotations

from collections import defaultdict
from email.message import Message

from app.extractor.unicode_safety import sanitize_unicode_text
from app.schemas.email import HeaderSummary


def extract_headers(message: Message) -> HeaderSummary:
    """Return important headers and every original header value.

    ``raw_items`` is deliberately used so duplicate values (especially
    ``Received``) and folded source values are retained. This function only
    extracts authentication-related headers; it never verifies them.
    """

    raw_headers: dict[str, list[str]] = defaultdict(list)
    casefolded: dict[str, list[str]] = defaultdict(list)
    for name, value in message.raw_items():
        # Raw 8-bit header content can carry unpaired surrogates (the stdlib
        # parses it with surrogateescape); sanitize here so NO header string
        # that reaches evidence (raw, typed, or derived) can break UTF-8
        # serialization downstream. All other characters are preserved.
        safe_value = sanitize_unicode_text(value)
        raw_headers[name].append(safe_value)
        # Header field names are case-insensitive. Keep values from differently
        # cased duplicate fields in source order instead of overwriting them.
        casefolded[name.casefold()].append(safe_value)
    mime_headers = {
        name: values
        for name, values in raw_headers.items()
        if name.casefold().startswith("content-")
        or name.casefold() == "mime-version"
    }
    arc_headers = {
        name: values
        for name, values in raw_headers.items()
        if name.casefold().startswith("arc-")
    }

    def values(name: str) -> list[str]:
        return list(casefolded.get(name.casefold(), []))

    def first(name: str) -> str | None:
        header_values = values(name)
        return header_values[0] if header_values else None

    return HeaderSummary(
        raw=dict(raw_headers),
        from_header=values("from"),
        to=values("to"),
        cc=values("cc"),
        bcc=values("bcc"),
        reply_to=values("reply-to"),
        return_path=values("return-path"),
        message_id=values("message-id"),
        date=values("date"),
        received=values("received"),
        authentication_results=values("authentication-results"),
        received_spf=values("received-spf"),
        dkim_signature=values("dkim-signature"),
        arc_headers=arc_headers,
        mime_headers=mime_headers,
        content_type=first("content-type"),
        mime_version=first("mime-version"),
        content_transfer_encoding=first("content-transfer-encoding"),
        user_agent=first("user-agent"),
        x_mailer=first("x-mailer"),
    )
