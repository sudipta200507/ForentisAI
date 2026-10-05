"""Build a phishing-style .eml containing malformed (surrogate-producing) Unicode.

Reproduces the production UnicodeEncodeError: raw invalid UTF-8 bytes in
headers, body, attachment filename and URLs survive parsing as lone
surrogates (U+DC80-U+DCFF) and break FastAPI's JSON encoding.

Usage: python scripts/make_sample1_fixture.py [output.eml]
"""

import sys
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent.parent / "samples" / "phishing" / "sample-1.eml")

# Raw invalid UTF-8 bytes: a bare 0x80 continuation byte and a truncated
# 3-byte sequence. Under surrogateescape decoding each becomes a lone
# surrogate (U+DC80, U+DC8C) that cannot be UTF-8 encoded later.
BAD1 = b"\x80"          # -> U+DC80
BAD2 = b"\xe2\x8c"      # truncated "⌌" -> U+DC8C U+DC8C? (2 stray bytes)

header_block = b"\r\n".join(
    [
        b"From: PayPa1 Security <alerts@paypa1-" + BAD1 + b".com>",
        b'To: "Victim" <victim@example.com>',
        b"Reply-To: helpdesk@secure-verify" + BAD2 + b".net",
        b"Subject: =?utf-8?q?Urgent:=_Verify_Your_Account_?= raw" + BAD1 + b"now",
        b"Message-ID: <" + BAD1 + b"abc123@mailer.paypa1-" + BAD1 + b".com>",
        b"Date: Thu, 1 Oct 2026 09:15:00 +0000",
        b"MIME-Version: 1.0",
        b'Received: from mail-out' + BAD1 + b'.evil.net (mail-out.evil.net [203.0.113.77])',
        b"\tby mx.example.com with ESMTPS id x123" + BAD1 + b";",
        b"\tThu, 1 Oct 2026 09:15:02 +0000",
        b"Content-Type: multipart/mixed; boundary=\"BOUND1\"",
        b"",
    ]
)

body_text = (
    b"Dear Customer,\r\n\r\n"
    b"Your account has been LOCKED due to unusual activity" + BAD1 + b".\r\n"
    b"Verify within 24 hours: https://paypa1-secure" + BAD1 + b".com/login?token=abc\r\n"
    b"Or click http://203.0.113.77/verify" + BAD2 + b"/user\r\n\r\n"
    b"Sincerely,\r\nSecurity Team\r\n"
)

html_body = (
    b"<html><head><meta charset=\"utf-8\"></head><body>"
    b"<p>Verify now: <a href=\"https://paypa1-secure" + BAD1 + b".com/login\">click</a></p>"
    b"</body></html>"
)

attachment_part = b"\r\n".join(
    [
        b"--BOUND1",
        b"Content-Type: application/octet-stream; name=\"invoice" + BAD1 + b".pdf\"",
        b"Content-Disposition: attachment; filename=\"invoice" + BAD1 + b".pdf\"",
        b"Content-Transfer-Encoding: base64",
        b"",
        b"JVBERi0xLjQKJcTl8uXrp/Og0MTGCjEgMCBvYmoKPDwvVHlwZS9DYXRhbG9nL1BhZ2VzIDIgMCBSPj4K",
    ]
)

plain_part = b"\r\n".join(
    [
        b"--BOUND1",
        b"Content-Type: text/plain; charset=\"utf-8\"",
        b"Content-Transfer-Encoding: 8bit",
        b"",
        body_text,
    ]
)

html_part = b"\r\n".join(
    [
        b"--BOUND1",
        b"Content-Type: text/html; charset=\"utf-8\"",
        b"Content-Transfer-Encoding: 8bit",
        b"",
        html_body,
    ]
)

message = b"\r\n".join(
    [
        header_block,
        plain_part,
        html_part,
        attachment_part,
        b"--BOUND1--",
        b"",
    ]
)


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(message)
    print(f"wrote {OUT} ({len(message)} bytes)")
    # Show where the invalid bytes are.
    for index, byte in enumerate(message):
        if byte >= 0x80:
            print(f"  byte 0x{byte:02x} at offset {index}")
    print("total invalid-byte count:", sum(1 for b in message if b >= 0x80))


if __name__ == "__main__":
    main()
