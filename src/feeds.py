from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from typing import Any

import feedparser

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def strip_html(text: str) -> str:
    text = html.unescape(text or "")
    text = _TAG_RE.sub(" ", text)
    return _WS_RE.sub(" ", text).strip()


def shorten(text: str, limit: int = 360) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return f"{cut}…"


def _entry_date(entry: Any) -> str:
    parsed = getattr(entry, "published_parsed", None) or getattr(entry, "updated_parsed", None)
    if parsed:
        return datetime(*parsed[:6], tzinfo=timezone.utc).isoformat()
    return datetime.now(timezone.utc).isoformat()


def parse_feed(xml_text: str, fallback_source: str) -> list[dict[str, str]]:
    parsed = feedparser.parse(xml_text)
    output: list[dict[str, str]] = []
    for entry in parsed.entries:
        title = strip_html(getattr(entry, "title", ""))
        if not title:
            continue
        summary = shorten(strip_html(getattr(entry, "summary", "") or getattr(entry, "description", "")))
        link = (getattr(entry, "link", "") or fallback_source).strip()
        output.append({"title": title, "summary": summary, "source_url": link, "created_at": _entry_date(entry)})
    return output
