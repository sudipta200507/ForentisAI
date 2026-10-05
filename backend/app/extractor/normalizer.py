"""Build normalized evidence from parsed MIME data without retaining raw bytes."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from email.message import Message
from email.utils import getaddresses
from typing import Any

from app.extractor.attachment_parser import extract_attachments
from app.extractor.body_parser import extract_bodies
from app.extractor.header_parser import extract_headers
from app.extractor.url_extractor import extract_urls
from app.extractor.unicode_safety import has_lone_surrogates, sanitize_unicode_text
from app.schemas.email import (
    EmailAddress,
    EmailBody,
    EmailEvidence,
    FileMetadata,
    MessageMetadata,
    MimeInformation,
    MimePart,
    ParserDefect,
    RecipientGroups,
)


def calculate_sha256(raw_bytes: bytes) -> str:
    """Return the SHA-256 digest for the original, unmodified input bytes."""

    return hashlib.sha256(raw_bytes).hexdigest()


def build_file_metadata(raw_bytes: bytes, filename: str) -> FileMetadata:
    """Create evidence metadata before the email content is parsed."""

    safe_filename = filename.replace("\\", "/").rsplit("/", maxsplit=1)[-1].strip()
    return FileMetadata(
        filename=safe_filename or "uploaded.eml",
        size=len(raw_bytes),
        sha256=calculate_sha256(raw_bytes),
    )


def _header_value(message: Message, name: str) -> str | None:
    value = message.get(name)
    # Raw 8-bit headers can carry unpaired surrogates; sanitize at the read
    # point so subject/date/message-id/return-path are always UTF-8 safe.
    return sanitize_unicode_text(str(value)) if value is not None else None


def _parse_addresses(values: Iterable[str]) -> list[EmailAddress]:
    """Parse mailbox values while raw source headers remain available separately."""

    addresses: list[EmailAddress] = []
    for display_name, address in getaddresses(list(values)):
        clean_display_name = sanitize_unicode_text(display_name).strip() or None
        clean_address = sanitize_unicode_text(address).strip() or None
        if clean_display_name is None and clean_address is None:
            continue
        addresses.append(
            EmailAddress(display_name=clean_display_name, address=clean_address)
        )
    return addresses


def _describe_defect(defect: object) -> str:
    detail = sanitize_unicode_text(str(defect)).strip()
    return f"{type(defect).__name__}: {detail}" if detail else type(defect).__name__


def _mail_parser_defects(mail_message: Any | None) -> list[ParserDefect]:
    """Collect defects exposed by mail-parser without depending on its internals."""

    if mail_message is None:
        return []

    defects: list[ParserDefect] = []
    for attribute in ("defects", "defects_categories"):
        try:
            value = getattr(mail_message, attribute, None)
        except Exception:
            continue
        # Defect messages may embed raw header fragments; keep them UTF-8 safe.
        if not value:
            continue
        if isinstance(value, dict):
            for key, item in value.items():
                defects.append(
                    ParserDefect(
                        source="mail-parser",
                        message=sanitize_unicode_text(f"{attribute}.{key}: {item}"),
                    )
                )
        elif isinstance(value, (list, tuple, set)):
            defects.extend(
                ParserDefect(source="mail-parser", message=_describe_defect(item))
                for item in value
            )
        else:
            defects.append(
                ParserDefect(source="mail-parser", message=_describe_defect(value))
            )
    return defects


def _count_malformed_unicode_surfaces(message: Message) -> int:
    """Count raw header values that contained unpaired surrogates.

    Used only for the transparency defect; the actual sanitization happens at
    each extraction read point (header_parser, body_parser, attachment_parser,
    normalizer). Bodies are already replace-decoded by body_parser.
    """

    count = 0
    for _name, value in message.raw_items():
        if has_lone_surrogates(value):
            count += 1
    return count


def _mime_information(message: Message) -> MimeInformation:
    """Describe MIME layout without storing or executing attachment content."""

    parts: list[MimePart] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        parts.append(
            MimePart(
                content_type=part.get_content_type(),
                content_disposition=part.get_content_disposition(),
                charset=part.get_content_charset(),
                filename=(
                    sanitize_unicode_text(part.get_filename())
                    if part.get_filename()
                    else None
                ),
                content_id=(
                    sanitize_unicode_text(part.get("Content-ID"))
                    if part.get("Content-ID")
                    else None
                ),
            )
        )

    return MimeInformation(
        content_type=message.get_content_type(),
        mime_version=_header_value(message, "MIME-Version"),
        content_transfer_encoding=_header_value(message, "Content-Transfer-Encoding"),
        is_multipart=message.is_multipart(),
        parts=parts,
    )


def normalize_email(
    *,
    file_metadata: FileMetadata,
    message: Message,
    mail_message: Any | None = None,
    parser_defects: list[ParserDefect] | None = None,
) -> EmailEvidence:
    """Normalize a parsed EML message into the stable Step 1 schema.

    The raw source bytes are intentionally absent from the returned object.
    They remain the caller's original evidence; this is only a derived JSON
    representation.
    """

    headers = extract_headers(message)
    body_result = extract_bodies(message)
    attachment_result = extract_attachments(message)

    sender_candidates = _parse_addresses(headers.from_header)
    recipients = RecipientGroups(
        to=_parse_addresses(headers.to),
        cc=_parse_addresses(headers.cc),
        bcc=_parse_addresses(headers.bcc),
    )
    body = EmailBody(
        plain_text=body_result.plain_text,
        html=body_result.html,
        plain_text_parts=body_result.plain_text_parts,
        html_parts=body_result.html_parts,
    )

    defects = list(parser_defects or [])
    defects.extend(
        ParserDefect(source="python-email", message=_describe_defect(defect))
        for defect in message.defects
    )
    defects.extend(_mail_parser_defects(mail_message))
    defects.extend(body_result.defects)
    defects.extend(attachment_result.defects)

    # Transparency: record (without failing) when malformed Unicode was
    # encountered so consumers know replacement characters may be present.
    malformed_unicode_surfaces = _count_malformed_unicode_surfaces(message)
    if malformed_unicode_surfaces:
        defects.append(
            ParserDefect(
                source="unicode-safety",
                message=(
                    "Malformed Unicode in the original email: unpaired surrogate "
                    "code points in "
                    f"{malformed_unicode_surfaces} header value(s) were replaced "
                    "with U+FFFD during extraction (evidence preserved)."
                ),
            )
        )

    return EmailEvidence(
        file=file_metadata,
        message=MessageMetadata(
            subject=_header_value(message, "Subject"),
            date=_header_value(message, "Date"),
            message_id=_header_value(message, "Message-ID"),
            reply_to=_parse_addresses(headers.reply_to),
            return_path=_header_value(message, "Return-Path"),
        ),
        sender=sender_candidates[0] if sender_candidates else None,
        recipients=recipients,
        body=body,
        headers=headers,
        received_chain=list(headers.received),
        mime=_mime_information(message),
        urls=extract_urls(body.plain_text, body.html),
        attachments=attachment_result.attachments,
        parser_defects=defects,
    )
