"""Local URL extraction only; this module never connects to a URL."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

from app.extractor.unicode_safety import sanitize_unicode_text
from app.schemas.email import URLIndicator


_URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
_TRAILING_PUNCTUATION = ".,;:!?"
_HTML_URL_ATTRIBUTES = {"href", "src", "action", "formaction"}


def _strip_trailing_punctuation(value: str) -> str:
    """Remove punctuation commonly adjacent to URLs in prose."""

    value = value.rstrip(_TRAILING_PUNCTUATION)
    paired_delimiters = (("(", ")"), ("[", "]"), ("{", "}"))
    for opening, closing in paired_delimiters:
        while value.endswith(closing) and value.count(closing) > value.count(opening):
            value = value[:-1]
    return value


def _make_indicator(candidate: str, source: str) -> URLIndicator | None:
    """Return a structured HTTP(S) indicator if the candidate is parseable."""

    url = sanitize_unicode_text(_strip_trailing_punctuation(candidate.strip()))
    if not url:
        return None

    parse_target = f"http://{url}" if url.casefold().startswith("www.") else url
    parsed = urlsplit(parse_target)
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.netloc:
        return None

    try:
        hostname = parsed.hostname
    except ValueError:
        hostname = None
    return URLIndicator(
        url=url,
        source=source,
        hostname=sanitize_unicode_text(hostname) if hostname else None,
    )


def _urls_in_text(text: str, source: str) -> list[URLIndicator]:
    indicators: list[URLIndicator] = []
    for match in _URL_PATTERN.finditer(text):
        indicator = _make_indicator(match.group(0), source)
        if indicator is not None:
            indicators.append(indicator)
    return indicators


class _HTMLURLCollector(HTMLParser):
    """Collect URL-bearing attributes and visible text from HTML safely."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.candidates: list[str] = []

    def handle_starttag(self, _tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name.casefold() in _HTML_URL_ATTRIBUTES and value:
                self.candidates.append(value)

    def handle_data(self, data: str) -> None:
        self.candidates.extend(match.group(0) for match in _URL_PATTERN.finditer(data))


def extract_urls(plain_text: str | None, html: str | None) -> list[URLIndicator]:
    """Extract URL occurrences from body content without resolving them."""

    indicators = _urls_in_text(plain_text, "plain") if plain_text else []
    if not html:
        return indicators

    collector = _HTMLURLCollector()
    try:
        collector.feed(html)
        collector.close()
    except Exception:
        # HTML may be malformed. Text-level extraction remains safe and local.
        collector.candidates.extend(match.group(0) for match in _URL_PATTERN.finditer(html))

    for candidate in collector.candidates:
        indicator = _make_indicator(candidate, "html")
        if indicator is not None:
            indicators.append(indicator)
    return indicators
