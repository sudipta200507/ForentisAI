"""Extract attachment metadata without writing, executing, or uploading data."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from email.message import Message

from app.extractor.unicode_safety import sanitize_unicode_text
from app.schemas.email import AttachmentMetadata, ParserDefect


@dataclass(frozen=True, slots=True)
class AttachmentExtraction:
    """Attachment metadata with non-fatal extraction problems."""

    attachments: list[AttachmentMetadata]
    defects: list[ParserDefect]


def _is_attachment(part: Message, filename: str | None, content_id: str | None) -> bool:
    """Identify conventional and inline MIME attachments."""

    disposition = (part.get_content_disposition() or "").casefold()
    content_type = part.get_content_type().casefold()
    return (
        disposition in {"attachment", "inline"}
        or filename is not None
        or (content_id is not None and not content_type.startswith("text/"))
    )


def extract_attachments(message: Message) -> AttachmentExtraction:
    """Calculate metadata and hashes for decoded attachment bytes in memory."""

    attachments: list[AttachmentMetadata] = []
    defects: list[ParserDefect] = []

    for part in message.walk():
        if part.is_multipart():
            continue

        try:
            # Attachment filenames and Content-IDs are display metadata decoded
            # from attacker-controlled header bytes; sanitize unpaired
            # surrogates so they can never break downstream UTF-8 output.
            filename = part.get_filename()
            filename = sanitize_unicode_text(filename) if filename else None
            content_id = part.get("Content-ID")
            content_id = sanitize_unicode_text(content_id) if content_id else None
            if not _is_attachment(part, filename, content_id):
                continue

            mime_type = part.get_content_type()
            payload = part.get_payload(decode=True)
            errors: list[str] = []
            if isinstance(payload, bytes):
                size = len(payload)
                sha256 = hashlib.sha256(payload).hexdigest()
            else:
                size = 0
                sha256 = None
                errors.append("Attachment payload could not be decoded to bytes")

            attachment = AttachmentMetadata(
                filename=filename,
                mime_type=mime_type,
                size=size,
                content_id=content_id,
                sha256=sha256,
                errors=errors,
            )
            attachments.append(attachment)
            defects.extend(
                ParserDefect(source="attachment", message=error) for error in errors
            )
        except (TypeError, ValueError, UnicodeError) as error:
            defects.append(
                ParserDefect(
                    source="attachment",
                    message=f"Unable to extract attachment metadata: {type(error).__name__}",
                )
            )

    return AttachmentExtraction(attachments=attachments, defects=defects)
