"""Decode text body parts while keeping the original message untouched."""

from __future__ import annotations

from dataclasses import dataclass
from email.message import Message

from app.extractor.unicode_safety import sanitize_unicode_text
from app.schemas.email import ParserDefect


@dataclass(frozen=True, slots=True)
class BodyExtraction:
    """Decoded body data and non-fatal decoding issues."""

    plain_text_parts: list[str]
    html_parts: list[str]
    defects: list[ParserDefect]

    @property
    def plain_text(self) -> str | None:
        return "\n".join(self.plain_text_parts) if self.plain_text_parts else None

    @property
    def html(self) -> str | None:
        return "\n".join(self.html_parts) if self.html_parts else None


def _decode_part(part: Message) -> tuple[str | None, str | None]:
    """Decode one MIME part without raising on malformed encodings."""

    try:
        payload = part.get_payload(decode=True)
    except (TypeError, ValueError) as error:
        return None, f"Unable to decode MIME payload: {type(error).__name__}"

    if payload is None:
        source_payload = part.get_payload()
        if isinstance(source_payload, str):
            return sanitize_unicode_text(source_payload), None
        if isinstance(source_payload, bytes):
            payload = source_payload
        else:
            return None, "MIME part did not contain a decodable text payload"

    charset = part.get_content_charset() or "utf-8"
    try:
        return sanitize_unicode_text(payload.decode(charset)), None
    except LookupError:
        return payload.decode("utf-8", errors="replace"), (
            f"Unknown declared charset {charset!r}; decoded as UTF-8 with replacement"
        )
    except UnicodeDecodeError:
        return payload.decode(charset, errors="replace"), (
            f"Unable to decode declared charset {charset!r} cleanly; replacement used"
        )


def extract_bodies(message: Message) -> BodyExtraction:
    """Extract plain-text and HTML body parts, excluding attachment parts."""

    plain_text_parts: list[str] = []
    html_parts: list[str] = []
    defects: list[ParserDefect] = []

    for part in message.walk():
        if part.is_multipart():
            continue

        content_type = part.get_content_type().casefold()
        disposition = (part.get_content_disposition() or "").casefold()
        if disposition == "attachment" or part.get_filename() is not None:
            continue
        if content_type not in {"text/plain", "text/html"}:
            continue

        text, error = _decode_part(part)
        if error:
            defects.append(ParserDefect(source="body", message=error))
        if text is None:
            continue
        if content_type == "text/plain":
            plain_text_parts.append(text)
        else:
            html_parts.append(text)

    return BodyExtraction(
        plain_text_parts=plain_text_parts,
        html_parts=html_parts,
        defects=defects,
    )
