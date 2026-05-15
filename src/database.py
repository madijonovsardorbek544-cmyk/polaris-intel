from __future__ import annotations

import asyncio
import json
from typing import Any

from .config import settings
from .models import IntelligenceItem, Watchlist

_ITEMS: list[IntelligenceItem] = []
_WATCHLISTS: list[Watchlist] = []
_LOCK = asyncio.Lock()


def _psycopg():
    try:
        import psycopg  # type: ignore
    except ImportError as exc:
        raise RuntimeError("psycopg is required when DATABASE_URL is configured") from exc
    return psycopg


def database_enabled() -> bool:
    return bool(settings.database_url)


async def init_db() -> None:
    if not database_enabled():
        return

    def run() -> None:
        with _psycopg().connect(settings.database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS intel_items (
                        id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        category TEXT NOT NULL,
                        risk_score INTEGER NOT NULL,
                        risk_level TEXT NOT NULL,
                        confidence_score INTEGER NOT NULL,
                        source_url TEXT NOT NULL,
                        source_domain TEXT NOT NULL,
                        tags JSONB NOT NULL DEFAULT '[]'::jsonb,
                        entities JSONB NOT NULL DEFAULT '{}'::jsonb,
                        affected_countries JSONB NOT NULL DEFAULT '[]'::jsonb,
                        affected_sectors JSONB NOT NULL DEFAULT '[]'::jsonb,
                        why_it_matters TEXT NOT NULL,
                        recommended_action TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL,
                        ingested_at TIMESTAMPTZ NOT NULL,
                        UNIQUE (title, source_url)
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS watchlists (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        countries JSONB NOT NULL DEFAULT '[]'::jsonb,
                        sectors JSONB NOT NULL DEFAULT '[]'::jsonb,
                        organizations JSONB NOT NULL DEFAULT '[]'::jsonb,
                        keywords JSONB NOT NULL DEFAULT '[]'::jsonb,
                        cves JSONB NOT NULL DEFAULT '[]'::jsonb,
                        threat_actors JSONB NOT NULL DEFAULT '[]'::jsonb,
                        created_at TIMESTAMPTZ NOT NULL
                    );
                    """
                )
            conn.commit()

    await asyncio.to_thread(run)


def _json(value: Any) -> str:
    return json.dumps(value or [])


def _item_from_row(row: tuple[Any, ...]) -> IntelligenceItem:
    return IntelligenceItem(
        id=row[0],
        title=row[1],
        summary=row[2],
        category=row[3],
        risk_score=row[4],
        risk_level=row[5],
        confidence_score=row[6],
        source_url=row[7],
        source_domain=row[8],
        tags=row[9] if isinstance(row[9], list) else [],
        entities=row[10] if isinstance(row[10], dict) else {},
        affected_countries=row[11] if isinstance(row[11], list) else [],
        affected_sectors=row[12] if isinstance(row[12], list) else [],
        why_it_matters=row[13],
        recommended_action=row[14],
        created_at=row[15].isoformat() if hasattr(row[15], "isoformat") else str(row[15]),
        ingested_at=row[16].isoformat() if hasattr(row[16], "isoformat") else str(row[16]),
    )


async def save_items(items: list[IntelligenceItem]) -> None:
    if not items:
        return
    async with _LOCK:
        merged = deduplicate_items(items + _ITEMS)
        merged.sort(key=lambda item: (item.risk_score, item.ingested_at), reverse=True)
        _ITEMS[:] = merged[: settings.max_items]

    if not database_enabled():
        return

    def run() -> None:
        with _psycopg().connect(settings.database_url) as conn:
            with conn.cursor() as cur:
                for item in items:
                    cur.execute(
                        """
                        INSERT INTO intel_items
                        (id, title, summary, category, risk_score, risk_level, confidence_score,
                         source_url, source_domain, tags, entities, affected_countries, affected_sectors,
                         why_it_matters, recommended_action, created_at, ingested_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb,
                                %s::jsonb, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            title = EXCLUDED.title,
                            summary = EXCLUDED.summary,
                            category = EXCLUDED.category,
                            risk_score = EXCLUDED.risk_score,
                            risk_level = EXCLUDED.risk_level,
                            confidence_score = EXCLUDED.confidence_score,
                            source_url = EXCLUDED.source_url,
                            source_domain = EXCLUDED.source_domain,
                            tags = EXCLUDED.tags,
                            entities = EXCLUDED.entities,
                            affected_countries = EXCLUDED.affected_countries,
                            affected_sectors = EXCLUDED.affected_sectors,
                            why_it_matters = EXCLUDED.why_it_matters,
                            recommended_action = EXCLUDED.recommended_action,
                            ingested_at = EXCLUDED.ingested_at;
                        """,
                        (
                            item.id,
                            item.title,
                            item.summary,
                            item.category,
                            item.risk_score,
                            item.risk_level,
                            item.confidence_score,
                            item.source_url,
                            item.source_domain,
                            _json(item.tags),
                            json.dumps(item.entities or {}),
                            _json(item.affected_countries),
                            _json(item.affected_sectors),
                            item.why_it_matters,
                            item.recommended_action,
                            item.created_at,
                            item.ingested_at,
                        ),
                    )
            conn.commit()

    await asyncio.to_thread(run)


async def list_items(limit: int | None = None) -> list[IntelligenceItem]:
    limit = limit or settings.max_items
    if database_enabled():
        def run() -> list[IntelligenceItem]:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, title, summary, category, risk_score, risk_level, confidence_score,
                               source_url, source_domain, tags, entities, affected_countries, affected_sectors,
                               why_it_matters, recommended_action, created_at, ingested_at
                        FROM intel_items
                        ORDER BY risk_score DESC, ingested_at DESC
                        LIMIT %s;
                        """,
                        (limit,),
                    )
                    return [_item_from_row(row) for row in cur.fetchall()]
        rows = await asyncio.to_thread(run)
        if rows:
            async with _LOCK:
                _ITEMS[:] = rows
        return rows

    async with _LOCK:
        return list(_ITEMS[:limit])


async def get_item(item_id: str) -> IntelligenceItem | None:
    for item in await list_items(settings.max_items):
        if item.id == item_id:
            return item
    return None


def deduplicate_items(items: list[IntelligenceItem]) -> list[IntelligenceItem]:
    seen: set[tuple[str, str]] = set()
    output: list[IntelligenceItem] = []
    for item in items:
        key = ((item.source_url or "").strip().lower(), (item.title or "").strip().lower())
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _watchlist_from_row(row: tuple[Any, ...]) -> Watchlist:
    return Watchlist(
        id=row[0],
        name=row[1],
        countries=row[2] if isinstance(row[2], list) else [],
        sectors=row[3] if isinstance(row[3], list) else [],
        organizations=row[4] if isinstance(row[4], list) else [],
        keywords=row[5] if isinstance(row[5], list) else [],
        cves=row[6] if isinstance(row[6], list) else [],
        threat_actors=row[7] if isinstance(row[7], list) else [],
        created_at=row[8].isoformat() if hasattr(row[8], "isoformat") else str(row[8]),
    )


async def add_watchlist(watchlist: Watchlist) -> Watchlist:
    async with _LOCK:
        _WATCHLISTS.append(watchlist)

    if database_enabled():
        def run() -> None:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO watchlists
                        (id, name, countries, sectors, organizations, keywords, cves, threat_actors, created_at)
                        VALUES (%s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s);
                        """,
                        (
                            watchlist.id,
                            watchlist.name,
                            _json(watchlist.countries),
                            _json(watchlist.sectors),
                            _json(watchlist.organizations),
                            _json(watchlist.keywords),
                            _json(watchlist.cves),
                            _json(watchlist.threat_actors),
                            watchlist.created_at,
                        ),
                    )
                conn.commit()
        await asyncio.to_thread(run)
    return watchlist


async def list_watchlists() -> list[Watchlist]:
    if database_enabled():
        def run() -> list[Watchlist]:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, name, countries, sectors, organizations, keywords, cves, threat_actors, created_at
                        FROM watchlists
                        ORDER BY created_at DESC;
                        """
                    )
                    return [_watchlist_from_row(row) for row in cur.fetchall()]
        rows = await asyncio.to_thread(run)
        async with _LOCK:
            _WATCHLISTS[:] = rows
        return rows
    async with _LOCK:
        return list(_WATCHLISTS)


async def delete_watchlist(watchlist_id: str) -> bool:
    deleted = False
    async with _LOCK:
        before = len(_WATCHLISTS)
        _WATCHLISTS[:] = [watchlist for watchlist in _WATCHLISTS if watchlist.id != watchlist_id]
        deleted = len(_WATCHLISTS) != before

    if database_enabled():
        def run() -> bool:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM watchlists WHERE id = %s;", (watchlist_id,))
                    count = cur.rowcount > 0
                conn.commit()
                return count
        deleted = await asyncio.to_thread(run) or deleted
    return deleted


async def replace_memory_items(items: list[IntelligenceItem]) -> None:
    async with _LOCK:
        _ITEMS[:] = items[: settings.max_items]
