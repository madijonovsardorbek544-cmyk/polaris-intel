from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import asdict
from typing import Any


from ..config import settings
from ..database import deduplicate_items, list_items, list_source_health, list_watchlists, record_source_failure, record_source_success, replace_memory_items, save_items
from ..feeds import parse_feed
from ..models import IntelligenceItem
from .analysis import analyze_item, now_iso

_LAST_REFRESH_STATUS = "cold"
_LAST_REFRESH_TS = 0.0
_LOCK = asyncio.Lock()
logger = logging.getLogger(__name__)


async def fetch_feed(client: object, feed_url: str) -> list[IntelligenceItem]:
    try:
        response = await client.get(
            feed_url,
            timeout=settings.http_timeout,
            headers={"User-Agent": "POLARIS-Intel/1.0"},
            follow_redirects=True,
        )
        response.raise_for_status()
        entries = parse_feed(response.text, feed_url)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        logger.warning(
            "Feed fetch failed url=%s error_type=%s message=%s",
            feed_url,
            type(exc).__name__,
            str(exc),
        )
        await record_source_failure(feed_url, now_iso(), error)
        return []

    await record_source_success(feed_url, now_iso())
    watchlists = await list_watchlists()
    return [
        analyze_item(entry["title"], entry["summary"], entry["source_url"], watchlists, entry["created_at"])
        for entry in entries
    ]


async def fetch_feed_result(client: object, feed_url: str) -> dict[str, object]:
    items = await fetch_feed(client, feed_url)
    failed = False
    for source in await list_source_health():
        if source.source_url == feed_url and source.last_error:
            failed = True
            break
    return {"items": items, "failed": failed}


async def refresh_store(force: bool = False) -> dict[str, Any]:
    global _LAST_REFRESH_STATUS, _LAST_REFRESH_TS
    async with _LOCK:
        now = time.time()
        cached_items = await list_items(settings.max_items)
        if not force and cached_items and now - _LAST_REFRESH_TS < settings.auto_refresh_seconds:
            return {"ok": True, "status": "cached", "items": len(cached_items)}
        _LAST_REFRESH_STATUS = "loading"
        _LAST_REFRESH_TS = now
        logger.info("Feed refresh started feeds=%s", len(settings.feeds))

    import httpx

    async with httpx.AsyncClient() as client:
        feed_results = await asyncio.gather(*(fetch_feed_result(client, feed) for feed in settings.feeds))

    merged: list[IntelligenceItem] = []
    for result in feed_results:
        merged.extend(result["items"])

    merged = deduplicate_items(merged)
    merged.sort(key=lambda item: (item.risk_score, item.ingested_at), reverse=True)
    merged = merged[: settings.max_items]

    failed_feeds = sum(1 for result in feed_results if result["failed"])

    if merged:
        await save_items(merged)
        _LAST_REFRESH_STATUS = "OK"
        logger.info("Feed refresh success items=%s failed_feeds=%s", len(merged), failed_feeds)
    else:
        existing = await list_items(settings.max_items)
        await replace_memory_items(existing)
        _LAST_REFRESH_STATUS = "OK" if existing else "EMPTY"
        if existing:
            logger.info("Feed refresh success from cache items=%s failed_feeds=%s", len(existing), failed_feeds)
        else:
            logger.warning("Feed refresh empty failed_feeds=%s", failed_feeds)

    return {"ok": True, "status": _LAST_REFRESH_STATUS, "items": len(await list_items(settings.max_items)), "failed_feeds": failed_feeds}


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
            logger.warning("Background feed refresh failed error_type=%s message=%s", type(exc).__name__, str(exc))
        await asyncio.sleep(settings.auto_refresh_seconds)


def refresh_status() -> str:
    return _LAST_REFRESH_STATUS


def item_to_dict(item: IntelligenceItem) -> dict[str, Any]:
    return asdict(item)
