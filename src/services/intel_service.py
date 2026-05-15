from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from src.core import database
from src.core.config import settings
from src.models.intel import IntelItem
from src.services.risk_engine import classify_category, extract_tags, risk_level, score_risk
from src.services.rss import parse_rss_or_atom
from src.utils.text import shorten, strip_html

logger = logging.getLogger(__name__)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def dedupe_items(items: list[IntelItem]) -> list[IntelItem]:
    seen: set[tuple[str, str]] = set()
    unique_items: list[IntelItem] = []

    for item in items:
        key = (item.title.strip().lower(), item.source.strip().lower())
        if key in seen:
            continue
        seen.add(key)
        unique_items.append(item)

    return unique_items


class IntelService:
    def __init__(self) -> None:
        self._store: list[IntelItem] = []
        self._last_refresh_status = "cold"
        self._last_refresh_ts = 0.0
        self._lock = asyncio.Lock()
        self._background_task_started = False

    @property
    def background_task_started(self) -> bool:
        return self._background_task_started

    async def startup(self) -> None:
        await database.init_db()
        db_items = await database.load_items(settings.max_items)

        async with self._lock:
            if db_items:
                self._store = db_items
                self._last_refresh_status = "OK"

        asyncio.create_task(self.refresh_store(force=True))

        if not self._background_task_started:
            self._background_task_started = True
            asyncio.create_task(self.background_refresh_loop())

    async def snapshot(self) -> tuple[list[IntelItem], str]:
        async with self._lock:
            return list(self._store), self._last_refresh_status

    async def health(self) -> dict[str, object]:
        async with self._lock:
            return {
                "ok": True,
                "app": settings.app_name,
                "version": settings.app_version,
                "items": len(self._store),
                "last_status": self._last_refresh_status,
                "feeds": len(settings.feeds),
                "database": bool(settings.database_url),
            }

    async def latest(self) -> list[dict[str, object]]:
        async with self._lock:
            return [item.to_dict() for item in self._store]

    async def seed_demo(self) -> dict[str, object]:
        demo = [
            IntelItem(
                title="Sample cyber threat detected",
                summary="Suspicious activity indicates possible credential abuse. Investigate logs and alerts.",
                category="Cyber",
                risk_score=78,
                risk_level="High",
                source="https://example.com/cyber-alert",
                tags=["phishing", "credentials", "ioc"],
                created_at=now_iso(),
            ),
            IntelItem(
                title="Geopolitical tension rising in region",
                summary="Diplomatic friction and increased rhetoric suggest elevated escalation risk.",
                category="Geopolitics",
                risk_score=65,
                risk_level="High",
                source="https://example.com/geopolitics-brief",
                tags=["diplomacy", "trade", "monitor"],
                created_at=now_iso(),
            ),
        ]

        await database.save_items(demo)

        async with self._lock:
            self._store = demo
            self._last_refresh_status = "SEEDED"

        return {"ok": True, "seeded": len(demo)}

    async def refresh_store(self, force: bool = False) -> dict[str, Any]:
        async with self._lock:
            current_time = time.time()
            cache_is_fresh = self._store and current_time - self._last_refresh_ts < settings.auto_refresh_seconds
            if not force and cache_is_fresh:
                return {"ok": True, "status": "cached", "items": len(self._store)}

            self._last_refresh_status = "loading"
            self._last_refresh_ts = current_time

        async with httpx.AsyncClient() as client:
            results = await asyncio.gather(*(self.fetch_feed(client, feed) for feed in settings.feeds))

        merged = [item for feed_items in results for item in feed_items]
        merged = dedupe_items(merged)
        merged.sort(key=lambda item: (item.risk_score, item.created_at), reverse=True)
        merged = merged[: settings.max_items]

        if merged:
            await database.save_items(merged)

        async with self._lock:
            if merged:
                self._store = merged
                self._last_refresh_status = "OK"
            else:
                db_items = await database.load_items(settings.max_items)
                self._store = db_items
                self._last_refresh_status = "OK" if db_items else "EMPTY"

            return {"ok": True, "status": self._last_refresh_status, "items": len(self._store)}

    async def fetch_feed(self, client: httpx.AsyncClient, feed_url: str) -> list[IntelItem]:
        try:
            response = await client.get(
                feed_url,
                timeout=settings.http_timeout,
                headers={"User-Agent": f"POLARIS-Intel/{settings.app_version}"},
                follow_redirects=True,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning("Feed fetch failed for %s: %s", feed_url, exc)
            return []

        raw_entries = parse_rss_or_atom(response.text, feed_url)
        items: list[IntelItem] = []

        for entry in raw_entries:
            title = (entry.get("title") or "").strip()
            if not title:
                continue

            summary = shorten(strip_html(entry.get("summary") or ""))
            source = (entry.get("link") or feed_url).strip()
            category = classify_category(title, summary, source)
            risk_score = score_risk(title, summary, source, category)

            items.append(
                IntelItem(
                    title=title,
                    summary=summary,
                    category=category,
                    risk_score=risk_score,
                    risk_level=risk_level(risk_score),
                    source=source,
                    tags=extract_tags(title, summary, source),
                    created_at=now_iso(),
                )
            )

        return items

    async def background_refresh_loop(self) -> None:
        while True:
            try:
                await self.refresh_store(force=True)
            except Exception:
                logger.exception("Background refresh failed")
            await asyncio.sleep(settings.auto_refresh_seconds)


intel_service = IntelService()
