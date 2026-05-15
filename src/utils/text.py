from __future__ import annotations

import html
import re
from urllib.parse import urlparse

TAG_RE = re.compile(r"<[^>]+>")
WHITESPACE_RE = re.compile(r"\s+")


def strip_html(text: str) -> str:
    if not text:
        return ""
    unescaped = html.unescape(text)
    without_tags = TAG_RE.sub(" ", unescaped)
    return WHITESPACE_RE.sub(" ", without_tags).strip()


def shorten(text: str, limit: int = 260) -> str:
    clean_text = (text or "").strip()
    if len(clean_text) <= limit:
        return clean_text

    cut = clean_text[:limit]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return f"{cut}…"


def host_of(url: str) -> str:
    parsed_url = urlparse(url)
    return parsed_url.netloc.lower()


def uniq_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique_values: list[str] = []

    for value in values:
        clean_value = (value or "").strip()
        if not clean_value:
            continue

        key = clean_value.lower()
        if key in seen:
            continue

        seen.add(key)
        unique_values.append(clean_value)

    return unique_values
