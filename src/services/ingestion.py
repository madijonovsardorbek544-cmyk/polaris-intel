from __future__ import annotations

import asyncio
import importlib
import logging
import time
from dataclasses import asdict, dataclass
from typing import Any

from ..config import settings
from ..database import (
    deduplicate_items,
    list_items,
    list_watchlists,
    record_source_failure,
    record_source_success,
    replace_memory_items,
    save_items,
)
from ..feeds import parse_feed
from ..models import IntelligenceItem
from .analysis import analyze_item, now_iso

logger = logging.getLogger(__name__)

_LAST_REFRESH_STATUS = "cold"
_LAST_REFRESH_TS = 0.0
_LAST_FAILED_FEEDS = 0
_LOCK = asyncio.Lock()


@dataclass
class FeedFetchResult:
    feed_url: str
    items: list[IntelligenceItem]
    ok: bool
    error: str = ""


async def fetch_feed(client: Any, feed_url: str) -> FeedFetchResult:
    try:
        response = await client.get(
            feed_url,
            timeout=settings.http_timeout,
            headers={"User-Agent": "POLARIS-Intel/1.1"},
            follow_redirects=True,
        )
        response.raise_for_status()
        await record_source_success(feed_url, now_iso())
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        logger.warning("Feed fetch failed url=%s error_type=%s message=%s", feed_url, type(exc).__name__, str(exc))
        await record_source_failure(feed_url, error, now_iso())
        return FeedFetchResult(feed_url=feed_url, items=[], ok=False, error=error)

    watchlists = await list_watchlists()
    items = [
        analyze_item(entry["title"], entry["summary"], entry["source_url"], watchlists, entry["created_at"])
        for entry in parse_feed(response.text, feed_url)
    ]
    return FeedFetchResult(feed_url=feed_url, items=items, ok=True)


async def refresh_store(force: bool = False) -> dict[str, Any]:
    global _LAST_FAILED_FEEDS, _LAST_REFRESH_STATUS, _LAST_REFRESH_TS
    async with _LOCK:
        now = time.time()
        cached_items = await list_items(settings.max_items)
        if not force and cached_items and now - _LAST_REFRESH_TS < settings.auto_refresh_seconds:
            return {"ok": True, "status": "cached", "items": len(cached_items), "failed_feeds": _LAST_FAILED_FEEDS}
        logger.info("Refresh started feed_count=%s force=%s", len(settings.feeds), force)
        _LAST_REFRESH_STATUS = "loading"
        _LAST_REFRESH_TS = now

    try:
        httpx = importlib.import_module("httpx")
        async with httpx.AsyncClient() as client:
            results = await asyncio.gather(*(fetch_feed(client, feed) for feed in settings.feeds))
    except Exception as exc:
        _LAST_REFRESH_STATUS = "FAILED"
        logger.warning("Refresh failed error_type=%s message=%s", type(exc).__name__, str(exc))
        return {"ok": False, "status": _LAST_REFRESH_STATUS, "items": len(await list_items(settings.max_items)), "failed_feeds": len(settings.feeds)}

    _LAST_FAILED_FEEDS = sum(1 for result in results if not result.ok)
    merged: list[IntelligenceItem] = []
    for result in results:
        merged.extend(result.items)

    merged = deduplicate_items(merged)
    merged.sort(key=lambda item: (item.risk_score, item.ingested_at), reverse=True)
    merged = merged[: settings.max_items]

    if merged:
        await save_items(merged)
        _LAST_REFRESH_STATUS = "OK"
        item_count = len(await list_items(settings.max_items))
        logger.info("Refresh success items=%s failed_feeds=%s", item_count, _LAST_FAILED_FEEDS)
    else:
        existing = await list_items(settings.max_items)
        await replace_memory_items(existing)
        _LAST_REFRESH_STATUS = "OK" if existing else "EMPTY"
        item_count = len(existing)
        logger.info("Refresh empty status=%s items=%s failed_feeds=%s", _LAST_REFRESH_STATUS, item_count, _LAST_FAILED_FEEDS)

    return {"ok": True, "status": _LAST_REFRESH_STATUS, "items": item_count, "failed_feeds": _LAST_FAILED_FEEDS}


async def seed_demo_items() -> list[IntelligenceItem]:
    watchlists = await list_watchlists()
    demo = [
        analyze_item(
            "CISA warns CVE-2026-12345 is actively exploited in government networks",
            "A critical remote code execution vulnerability is being actively exploited against government and energy organizations in the USA and Ukraine.",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/sample-cve-2026-12345",
            watchlists,
            now_iso(),
        ),
        analyze_item(
            "Ransomware campaign targets healthcare logistics providers",
            "A malware and credential leak campaign is disrupting healthcare logistics operations and may expand to telecom providers.",
            "https://www.bleepingcomputer.com/news/security/sample-ransomware-healthcare-logistics/",
            watchlists,
            now_iso(),
        ),
        analyze_item(
            "Missile strike raises Russia Ukraine escalation risk near energy infrastructure",
            "Military escalation and drone activity near energy infrastructure increases operational risk for regional organizations.",
            "https://www.reuters.com/world/sample-russia-ukraine-energy-risk/",
            watchlists,
            now_iso(),
        ),
    ]
    await save_items(demo)
    return demo


async def background_refresh_loop() -> None:
    while True:
        try:
            await refresh_store(force=True)
        except Exception as exc:
            logger.warning("Background refresh failed error_type=%s message=%s", type(exc).__name__, str(exc))
        await asyncio.sleep(settings.auto_refresh_seconds)


def refresh_status() -> str:
    return _LAST_REFRESH_STATUS


def failed_feeds_count() -> int:
    return _LAST_FAILED_FEEDS


def item_to_dict(item: IntelligenceItem) -> dict[str, Any]:
    return asdict(item)
