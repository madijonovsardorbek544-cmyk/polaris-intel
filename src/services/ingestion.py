from __future__ import annotations

import asyncio
import time
from dataclasses import asdict
from typing import Any

import httpx

from ..config import settings
from ..database import deduplicate_items, list_items, list_watchlists, replace_memory_items, save_items
from ..feeds import parse_feed
from ..models import IntelligenceItem
from .analysis import analyze_item, now_iso

_LAST_REFRESH_STATUS = "cold"
_LAST_REFRESH_TS = 0.0
_LOCK = asyncio.Lock()


async def fetch_feed(client: httpx.AsyncClient, feed_url: str) -> list[IntelligenceItem]:
    try:
        response = await client.get(
            feed_url,
            timeout=settings.http_timeout,
            headers={"User-Agent": "POLARIS-Intel/1.0"},
            follow_redirects=True,
        )
        response.raise_for_status()
    except Exception:
        return []

    watchlists = await list_watchlists()
    return [
        analyze_item(entry["title"], entry["summary"], entry["source_url"], watchlists, entry["created_at"])
        for entry in parse_feed(response.text, feed_url)
    ]


async def refresh_store(force: bool = False) -> dict[str, Any]:
    global _LAST_REFRESH_STATUS, _LAST_REFRESH_TS
    async with _LOCK:
        now = time.time()
        cached_items = await list_items(settings.max_items)
        if not force and cached_items and now - _LAST_REFRESH_TS < settings.auto_refresh_seconds:
            return {"ok": True, "status": "cached", "items": len(cached_items)}
        _LAST_REFRESH_STATUS = "loading"
        _LAST_REFRESH_TS = now

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*(fetch_feed(client, feed) for feed in settings.feeds))

    merged: list[IntelligenceItem] = []
    for result in results:
        merged.extend(result)

    merged = deduplicate_items(merged)
    merged.sort(key=lambda item: (item.risk_score, item.ingested_at), reverse=True)
    merged = merged[: settings.max_items]

    if merged:
        await save_items(merged)
        _LAST_REFRESH_STATUS = "OK"
    else:
        existing = await list_items(settings.max_items)
        await replace_memory_items(existing)
        _LAST_REFRESH_STATUS = "OK" if existing else "EMPTY"

    return {"ok": True, "status": _LAST_REFRESH_STATUS, "items": len(await list_items(settings.max_items))}


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
        except Exception:
            pass
        await asyncio.sleep(settings.auto_refresh_seconds)


def refresh_status() -> str:
    return _LAST_REFRESH_STATUS


def item_to_dict(item: IntelligenceItem) -> dict[str, Any]:
    return asdict(item)
