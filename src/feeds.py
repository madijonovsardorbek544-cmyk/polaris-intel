from __future__ import annotations

import html
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any


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


def _tag_value(block: str, tag: str) -> str:
    match = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", block, re.IGNORECASE | re.DOTALL)
    return strip_html(match.group(1)) if match else ""


def _parse_feed_fallback(xml_text: str, fallback_source: str) -> list[dict[str, str]]:
    blocks = re.findall(r"<item[^>]*>(.*?)</item>", xml_text, re.IGNORECASE | re.DOTALL)
    blocks += re.findall(r"<entry[^>]*>(.*?)</entry>", xml_text, re.IGNORECASE | re.DOTALL)
    output: list[dict[str, str]] = []
    for block in blocks:
        title = _tag_value(block, "title")
        if not title:
            continue
        link = _tag_value(block, "link") or fallback_source
        summary = shorten(_tag_value(block, "summary") or _tag_value(block, "description"))
        output.append({"title": title, "summary": summary, "source_url": link.strip(), "created_at": datetime.now(timezone.utc).isoformat()})
    return output


KEV_RECENT_DAYS = 14


def parse_kev(json_text: str, recent_days: int = KEV_RECENT_DAYS) -> list[dict[str, str]]:
    """CISA Known Exploited Vulnerabilities catalog: only recent additions, so the full catalog doesn't flood the store."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=recent_days)).date().isoformat()
    output: list[dict[str, str]] = []
    for vuln in json.loads(json_text).get("vulnerabilities", []):
        added = str(vuln.get("dateAdded", ""))
        cve = str(vuln.get("cveID", "")).strip()
        if not cve or added < cutoff:
            continue
        product = f"{vuln.get('vendorProject', '')} {vuln.get('product', '')}".strip()
        summary = f"{vuln.get('vulnerabilityName', '')}. {vuln.get('shortDescription', '')} Required action: {vuln.get('requiredAction', '')} CISA remediation due date: {vuln.get('dueDate', '')}."
        if str(vuln.get("knownRansomwareCampaignUse", "")).lower() == "known":
            summary += " Known to be used in ransomware campaigns."
        output.append({
            "title": f"Actively exploited: {cve} in {product}",
            "summary": shorten(strip_html(summary), 600),
            "source_url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}",
            "created_at": f"{added}T00:00:00+00:00",
        })
    return output


def parse_feed(xml_text: str, fallback_source: str) -> list[dict[str, str]]:
    if xml_text.lstrip().startswith("{"):
        return parse_kev(xml_text)
    try:
        import feedparser
    except ModuleNotFoundError:
        return _parse_feed_fallback(xml_text, fallback_source)

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
