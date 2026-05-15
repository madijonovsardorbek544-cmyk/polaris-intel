from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from typing import Any

from .config import settings
from .models import IntelligenceItem, SourceHealth, Watchlist

_ITEMS: list[IntelligenceItem] = []
_WATCHLISTS: list[Watchlist] = []
_SOURCE_HEALTH: dict[str, SourceHealth] = {}
_LOCK = asyncio.Lock()


def _psycopg():
    try:
        import psycopg  # type: ignore
    except ImportError as exc:
        raise RuntimeError("psycopg is required when DATABASE_URL is configured") from exc
    return psycopg


def database_enabled() -> bool:
    return bool(settings.database_url)


def _list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return []


def _dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


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
                        risk_factors JSONB NOT NULL DEFAULT '[]'::jsonb,
                        confidence_factors JSONB NOT NULL DEFAULT '[]'::jsonb,
                        watchlist_matches JSONB NOT NULL DEFAULT '[]'::jsonb,
                        UNIQUE (title, source_url)
                    );
                    """
                )
                for statement in [
                    "ALTER TABLE intel_items ADD COLUMN IF NOT EXISTS risk_factors JSONB NOT NULL DEFAULT '[]'::jsonb;",
                    "ALTER TABLE intel_items ADD COLUMN IF NOT EXISTS confidence_factors JSONB NOT NULL DEFAULT '[]'::jsonb;",
                    "ALTER TABLE intel_items ADD COLUMN IF NOT EXISTS watchlist_matches JSONB NOT NULL DEFAULT '[]'::jsonb;",
                ]:
                    cur.execute(statement)
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
                        created_at TIMESTAMPTZ NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    """
                )
                cur.execute("ALTER TABLE watchlists ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();")
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
        tags=_list(row[9]),
        entities=_dict(row[10]),
        affected_countries=_list(row[11]),
        affected_sectors=_list(row[12]),
        why_it_matters=row[13],
        recommended_action=row[14],
        created_at=row[15].isoformat() if hasattr(row[15], "isoformat") else str(row[15]),
        ingested_at=row[16].isoformat() if hasattr(row[16], "isoformat") else str(row[16]),
        risk_factors=_list(row[17]) if len(row) > 17 else [],
        confidence_factors=_list(row[18]) if len(row) > 18 else [],
        watchlist_matches=_list(row[19]) if len(row) > 19 else [],
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
                         why_it_matters, recommended_action, created_at, ingested_at, risk_factors,
                         confidence_factors, watchlist_matches)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb,
                                %s::jsonb, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb)
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
                            ingested_at = EXCLUDED.ingested_at,
                            risk_factors = EXCLUDED.risk_factors,
                            confidence_factors = EXCLUDED.confidence_factors,
                            watchlist_matches = EXCLUDED.watchlist_matches;
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
                            _json(item.risk_factors),
                            _json(item.confidence_factors),
                            _json(item.watchlist_matches),
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
                               why_it_matters, recommended_action, created_at, ingested_at, risk_factors,
                               confidence_factors, watchlist_matches
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
        countries=_list(row[2]),
        sectors=_list(row[3]),
        organizations=_list(row[4]),
        keywords=_list(row[5]),
        cves=_list(row[6]),
        threat_actors=_list(row[7]),
        created_at=row[8].isoformat() if hasattr(row[8], "isoformat") else str(row[8]),
        updated_at=row[9].isoformat() if len(row) > 9 and hasattr(row[9], "isoformat") else (str(row[9]) if len(row) > 9 else ""),
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
                        (id, name, countries, sectors, organizations, keywords, cves, threat_actors, created_at, updated_at)
                        VALUES (%s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s);
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
                            watchlist.updated_at or watchlist.created_at,
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
                        SELECT id, name, countries, sectors, organizations, keywords, cves, threat_actors, created_at, updated_at
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


async def get_watchlist(watchlist_id: str) -> Watchlist | None:
    for watchlist in await list_watchlists():
        if watchlist.id == watchlist_id:
            return watchlist
    return None


async def update_watchlist(watchlist_id: str, updated: Watchlist) -> Watchlist | None:
    async with _LOCK:
        for index, watchlist in enumerate(_WATCHLISTS):
            if watchlist.id == watchlist_id:
                _WATCHLISTS[index] = updated
                break
        else:
            return None if not database_enabled() else updated

    if database_enabled():
        def run() -> bool:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE watchlists SET
                            name = %s,
                            countries = %s::jsonb,
                            sectors = %s::jsonb,
                            organizations = %s::jsonb,
                            keywords = %s::jsonb,
                            cves = %s::jsonb,
                            threat_actors = %s::jsonb,
                            updated_at = %s
                        WHERE id = %s;
                        """,
                        (
                            updated.name,
                            _json(updated.countries),
                            _json(updated.sectors),
                            _json(updated.organizations),
                            _json(updated.keywords),
                            _json(updated.cves),
                            _json(updated.threat_actors),
                            updated.updated_at,
                            watchlist_id,
                        ),
                    )
                    changed = cur.rowcount > 0
                conn.commit()
                return changed
        if not await asyncio.to_thread(run):
            return None
    return updated


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


async def record_source_success(source_url: str, at: str) -> SourceHealth:
    async with _LOCK:
        health = _SOURCE_HEALTH.get(source_url) or SourceHealth(source_url=source_url)
        health.last_success_at = at
        health.last_error = ""
        _SOURCE_HEALTH[source_url] = health
        return health


async def record_source_failure(source_url: str, error: str, at: str) -> SourceHealth:
    async with _LOCK:
        health = _SOURCE_HEALTH.get(source_url) or SourceHealth(source_url=source_url)
        health.last_failure_at = at
        health.failure_count += 1
        health.last_error = error[:300]
        _SOURCE_HEALTH[source_url] = health
        return health


async def list_source_health() -> list[SourceHealth]:
    async with _LOCK:
        return sorted(_SOURCE_HEALTH.values(), key=lambda item: item.source_url)


async def reset_memory_state() -> None:
    async with _LOCK:
        _ITEMS.clear()
        _WATCHLISTS.clear()
        _SOURCE_HEALTH.clear()


def dataclass_to_dict(value: Any) -> dict[str, Any]:
    return asdict(value)
