from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .config import settings
from .models import Alert, IntelligenceItem, SourceHealth, Watchlist, WatchlistMatch

_ITEMS: list[IntelligenceItem] = []
_WATCHLISTS: list[Watchlist] = []
_SOURCE_HEALTH: dict[str, SourceHealth] = {}
_ALERTS: list[Alert] = []
_LOCK = asyncio.Lock()


@dataclass
class AlertSaveResult:
    created_count: int
    existing_count: int
    all_alerts: list[Alert]
    created_alerts: list[Alert]



def _psycopg():
    try:
        import psycopg  # type: ignore
    except ImportError as exc:
        raise RuntimeError("psycopg is required when DATABASE_URL is configured") from exc
    return psycopg


def database_enabled() -> bool:
    return bool(settings.database_url)


def _json(value: Any) -> str:
    return json.dumps(value or [])


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return []


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _dt(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def source_status(health: SourceHealth) -> str:
    if health.last_error:
        return "failing"
    last_empty = parse_iso_datetime(health.last_empty_at)
    last_success = parse_iso_datetime(health.last_success_at)
    if last_empty and (not last_success or last_empty > last_success):
        return "empty"
    if last_success or health.last_success_at:
        return "healthy"
    return "pending"


def _normalize_source_health(health: SourceHealth) -> SourceHealth:
    health.status = source_status(health)
    return health


def _matches_from_json(value: Any) -> list[WatchlistMatch]:
    output: list[WatchlistMatch] = []
    for raw in _as_list(value):
        if not isinstance(raw, dict):
            continue
        output.append(
            WatchlistMatch(
                watchlist_id=str(raw.get("watchlist_id", "")),
                watchlist_name=str(raw.get("watchlist_name", "")),
                matched_on=str(raw.get("matched_on", "")),
                matched_value=str(raw.get("matched_value", "")),
                reason=str(raw.get("reason", "")),
                org_id=str(raw.get("org_id", "demo") or "demo"),
            )
        )
    return output


def _matches_to_json(matches: list[WatchlistMatch]) -> str:
    return json.dumps([match.__dict__ for match in matches])


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
                cur.execute("ALTER TABLE intel_items ADD COLUMN IF NOT EXISTS risk_factors JSONB NOT NULL DEFAULT '[]'::jsonb;")
                cur.execute("ALTER TABLE intel_items ADD COLUMN IF NOT EXISTS confidence_factors JSONB NOT NULL DEFAULT '[]'::jsonb;")
                cur.execute("ALTER TABLE intel_items ADD COLUMN IF NOT EXISTS watchlist_matches JSONB NOT NULL DEFAULT '[]'::jsonb;")
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS watchlists (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        org_id TEXT NOT NULL DEFAULT 'demo',
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
                cur.execute("ALTER TABLE watchlists ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'demo';")
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS source_health (
                        source_url TEXT PRIMARY KEY,
                        last_success_at TIMESTAMPTZ,
                        last_failure_at TIMESTAMPTZ,
                        last_empty_at TIMESTAMPTZ,
                        total_failure_count INTEGER NOT NULL DEFAULT 0,
                        consecutive_failure_count INTEGER NOT NULL DEFAULT 0,
                        empty_count INTEGER NOT NULL DEFAULT 0,
                        last_error TEXT
                    );
                    """
                )
                cur.execute("ALTER TABLE source_health ADD COLUMN IF NOT EXISTS last_empty_at TIMESTAMPTZ;")
                cur.execute("ALTER TABLE source_health ADD COLUMN IF NOT EXISTS total_failure_count INTEGER NOT NULL DEFAULT 0;")
                cur.execute("ALTER TABLE source_health ADD COLUMN IF NOT EXISTS consecutive_failure_count INTEGER NOT NULL DEFAULT 0;")
                cur.execute("ALTER TABLE source_health ADD COLUMN IF NOT EXISTS empty_count INTEGER NOT NULL DEFAULT 0;")
                cur.execute(
                    """
                    DO $$
                    BEGIN
                        IF EXISTS (
                            SELECT 1 FROM information_schema.columns
                            WHERE table_name = 'source_health' AND column_name = 'failure_count'
                        ) THEN
                            UPDATE source_health
                            SET total_failure_count = failure_count
                            WHERE total_failure_count = 0 AND failure_count IS NOT NULL;
                        END IF;
                    END $$;
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS alerts (
                        id TEXT PRIMARY KEY,
                        item_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        risk_level TEXT NOT NULL,
                        matched_watchlist_id TEXT NOT NULL,
                        matched_watchlist_name TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        recommended_action TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'open',
                        created_at TIMESTAMPTZ NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL,
                        notes TEXT,
                        org_id TEXT NOT NULL DEFAULT 'demo',
                        UNIQUE (item_id, matched_watchlist_id, reason)
                    );
                    """
                )
            conn.commit()

    await asyncio.to_thread(run)


def _item_from_row(row: tuple[Any, ...]) -> IntelligenceItem:
    return IntelligenceItem(
        id=row[0], title=row[1], summary=row[2], category=row[3], risk_score=row[4], risk_level=row[5], confidence_score=row[6],
        source_url=row[7], source_domain=row[8], tags=_as_list(row[9]), entities=_as_dict(row[10]), affected_countries=_as_list(row[11]),
        affected_sectors=_as_list(row[12]), why_it_matters=row[13], recommended_action=row[14], created_at=_dt(row[15]) or "",
        ingested_at=_dt(row[16]) or "", risk_factors=_as_list(row[17]), confidence_factors=_as_list(row[18]), watchlist_matches=_matches_from_json(row[19])
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
                        (id, title, summary, category, risk_score, risk_level, confidence_score, source_url, source_domain,
                         tags, entities, affected_countries, affected_sectors, why_it_matters, recommended_action, created_at,
                         ingested_at, risk_factors, confidence_factors, watchlist_matches)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb,
                                %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb)
                        ON CONFLICT (id) DO UPDATE SET
                            title = EXCLUDED.title, summary = EXCLUDED.summary, category = EXCLUDED.category,
                            risk_score = EXCLUDED.risk_score, risk_level = EXCLUDED.risk_level,
                            confidence_score = EXCLUDED.confidence_score, source_url = EXCLUDED.source_url,
                            source_domain = EXCLUDED.source_domain, tags = EXCLUDED.tags, entities = EXCLUDED.entities,
                            affected_countries = EXCLUDED.affected_countries, affected_sectors = EXCLUDED.affected_sectors,
                            why_it_matters = EXCLUDED.why_it_matters, recommended_action = EXCLUDED.recommended_action,
                            ingested_at = EXCLUDED.ingested_at, risk_factors = EXCLUDED.risk_factors,
                            confidence_factors = EXCLUDED.confidence_factors, watchlist_matches = EXCLUDED.watchlist_matches;
                        """,
                        (item.id, item.title, item.summary, item.category, item.risk_score, item.risk_level, item.confidence_score,
                         item.source_url, item.source_domain, _json(item.tags), json.dumps(item.entities or {}), _json(item.affected_countries),
                         _json(item.affected_sectors), item.why_it_matters, item.recommended_action, item.created_at, item.ingested_at,
                         _json(item.risk_factors), _json(item.confidence_factors), _matches_to_json(item.watchlist_matches)),
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
                        SELECT id, title, summary, category, risk_score, risk_level, confidence_score, source_url, source_domain,
                               tags, entities, affected_countries, affected_sectors, why_it_matters, recommended_action,
                               created_at, ingested_at, risk_factors, confidence_factors, watchlist_matches
                        FROM intel_items ORDER BY risk_score DESC, ingested_at DESC LIMIT %s;
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
    return Watchlist(id=row[0], name=row[1], org_id=row[2] or "demo", countries=_as_list(row[3]), sectors=_as_list(row[4]), organizations=_as_list(row[5]), keywords=_as_list(row[6]), cves=_as_list(row[7]), threat_actors=_as_list(row[8]), created_at=_dt(row[9]) or "")


async def add_watchlist(watchlist: Watchlist) -> Watchlist:
    async with _LOCK:
        _WATCHLISTS.append(watchlist)
    if database_enabled():
        def run() -> None:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO watchlists (id, name, org_id, countries, sectors, organizations, keywords, cves, threat_actors, created_at)
                        VALUES (%s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s);
                        """,
                        (watchlist.id, watchlist.name, watchlist.org_id, _json(watchlist.countries), _json(watchlist.sectors), _json(watchlist.organizations), _json(watchlist.keywords), _json(watchlist.cves), _json(watchlist.threat_actors), watchlist.created_at),
                    )
                conn.commit()
        await asyncio.to_thread(run)
    return watchlist


async def list_watchlists() -> list[Watchlist]:
    if database_enabled():
        def run() -> list[Watchlist]:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, name, org_id, countries, sectors, organizations, keywords, cves, threat_actors, created_at FROM watchlists ORDER BY created_at DESC;")
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
    found = False
    async with _LOCK:
        for index, existing in enumerate(_WATCHLISTS):
            if existing.id == watchlist_id:
                _WATCHLISTS[index] = updated
                found = True
                break
    if database_enabled():
        def run() -> bool:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE watchlists SET name = %s, org_id = %s, countries = %s::jsonb, sectors = %s::jsonb,
                            organizations = %s::jsonb, keywords = %s::jsonb, cves = %s::jsonb, threat_actors = %s::jsonb
                        WHERE id = %s;
                        """,
                        (updated.name, updated.org_id, _json(updated.countries), _json(updated.sectors), _json(updated.organizations), _json(updated.keywords), _json(updated.cves), _json(updated.threat_actors), watchlist_id),
                    )
                    count = cur.rowcount > 0
                conn.commit()
                return count
        found = await asyncio.to_thread(run) or found
    return updated if found else None


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


async def record_source_success(source_url: str, occurred_at: str) -> SourceHealth:
    async with _LOCK:
        health = _SOURCE_HEALTH.get(source_url, SourceHealth(source_url=source_url))
        health.last_success_at = occurred_at
        health.last_error = None
        health.consecutive_failure_count = 0
        _SOURCE_HEALTH[source_url] = _normalize_source_health(health)
    if database_enabled():
        def run() -> None:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO source_health (source_url, last_success_at, last_error, consecutive_failure_count)
                        VALUES (%s, %s, NULL, 0)
                        ON CONFLICT (source_url) DO UPDATE SET last_success_at = EXCLUDED.last_success_at,
                            last_error = NULL, consecutive_failure_count = 0;
                        """,
                        (source_url, occurred_at),
                    )
                conn.commit()
        await asyncio.to_thread(run)
    return health


async def record_source_empty(source_url: str, occurred_at: str) -> SourceHealth:
    async with _LOCK:
        health = _SOURCE_HEALTH.get(source_url, SourceHealth(source_url=source_url))
        health.last_empty_at = occurred_at
        health.empty_count += 1
        health.last_error = None
        health.consecutive_failure_count = 0
        _SOURCE_HEALTH[source_url] = _normalize_source_health(health)
    if database_enabled():
        def run() -> None:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO source_health (source_url, last_empty_at, empty_count, last_error, consecutive_failure_count)
                        VALUES (%s, %s, 1, NULL, 0)
                        ON CONFLICT (source_url) DO UPDATE SET last_empty_at = EXCLUDED.last_empty_at,
                            empty_count = source_health.empty_count + 1, last_error = NULL, consecutive_failure_count = 0;
                        """,
                        (source_url, occurred_at),
                    )
                conn.commit()
        await asyncio.to_thread(run)
    return health


async def record_source_failure(source_url: str, occurred_at: str, error: str) -> SourceHealth:
    safe_error = error[:500]
    async with _LOCK:
        health = _SOURCE_HEALTH.get(source_url, SourceHealth(source_url=source_url))
        health.last_failure_at = occurred_at
        health.total_failure_count += 1
        health.consecutive_failure_count += 1
        health.last_error = safe_error
        _SOURCE_HEALTH[source_url] = _normalize_source_health(health)
    if database_enabled():
        def run() -> None:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO source_health (source_url, last_failure_at, total_failure_count, consecutive_failure_count, last_error)
                        VALUES (%s, %s, 1, 1, %s)
                        ON CONFLICT (source_url) DO UPDATE SET last_failure_at = EXCLUDED.last_failure_at,
                            total_failure_count = source_health.total_failure_count + 1,
                            consecutive_failure_count = source_health.consecutive_failure_count + 1,
                            last_error = EXCLUDED.last_error;
                        """,
                        (source_url, occurred_at, safe_error),
                    )
                conn.commit()
        await asyncio.to_thread(run)
    return health


def _source_from_row(row: tuple[Any, ...]) -> SourceHealth:
    return _normalize_source_health(SourceHealth(source_url=row[0], last_success_at=_dt(row[1]), last_failure_at=_dt(row[2]), last_empty_at=_dt(row[3]), total_failure_count=row[4], consecutive_failure_count=row[5], empty_count=row[6], last_error=row[7]))


async def list_source_health() -> list[SourceHealth]:
    if database_enabled():
        def run() -> list[SourceHealth]:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT source_url, last_success_at, last_failure_at, last_empty_at, total_failure_count,
                               consecutive_failure_count, empty_count, last_error
                        FROM source_health
                        ORDER BY COALESCE(last_failure_at, last_empty_at, last_success_at) DESC NULLS LAST, source_url ASC;
                        """
                    )
                    return [_source_from_row(row) for row in cur.fetchall()]
        rows = await asyncio.to_thread(run)
        by_url = {row.source_url: row for row in rows}
    else:
        async with _LOCK:
            by_url = {url: _normalize_source_health(health) for url, health in _SOURCE_HEALTH.items()}
    for feed_url in settings.feeds:
        by_url.setdefault(feed_url, _normalize_source_health(SourceHealth(source_url=feed_url)))
    return list(by_url.values())


def _alert_from_row(row: tuple[Any, ...]) -> Alert:
    return Alert(id=row[0], item_id=row[1], title=row[2], risk_level=row[3], matched_watchlist_id=row[4], matched_watchlist_name=row[5], reason=row[6], recommended_action=row[7], status=row[8], created_at=_dt(row[9]) or "", updated_at=_dt(row[10]) or "", notes=row[11], org_id=row[12] or "demo")


async def list_alerts() -> list[Alert]:
    if database_enabled():
        def run() -> list[Alert]:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, item_id, title, risk_level, matched_watchlist_id, matched_watchlist_name, reason, recommended_action, status, created_at, updated_at, notes, org_id FROM alerts ORDER BY created_at DESC;")
                    return [_alert_from_row(row) for row in cur.fetchall()]
        rows = await asyncio.to_thread(run)
        async with _LOCK:
            _ALERTS[:] = rows
        return rows
    async with _LOCK:
        return list(_ALERTS)


async def get_alert(alert_id: str) -> Alert | None:
    for alert in await list_alerts():
        if alert.id == alert_id:
            return alert
    return None


async def save_alerts_with_counts(alerts: list[Alert]) -> AlertSaveResult:
    if not alerts:
        all_alerts = await list_alerts()
        return AlertSaveResult(created_count=0, existing_count=0, all_alerts=all_alerts, created_alerts=[])

    created_alerts: list[Alert] = []
    existing_count = 0

    if database_enabled():
        def run() -> list[Alert]:
            inserted: list[Alert] = []
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    for alert in alerts:
                        cur.execute(
                            """
                            INSERT INTO alerts (id, item_id, title, risk_level, matched_watchlist_id, matched_watchlist_name,
                                reason, recommended_action, status, created_at, updated_at, notes, org_id)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (item_id, matched_watchlist_id, reason) DO NOTHING
                            RETURNING id, item_id, title, risk_level, matched_watchlist_id, matched_watchlist_name, reason,
                                      recommended_action, status, created_at, updated_at, notes, org_id;
                            """,
                            (alert.id, alert.item_id, alert.title, alert.risk_level, alert.matched_watchlist_id, alert.matched_watchlist_name, alert.reason, alert.recommended_action, alert.status, alert.created_at, alert.updated_at, alert.notes, alert.org_id),
                        )
                        row = cur.fetchone()
                        if row:
                            inserted.append(_alert_from_row(row))
                conn.commit()
            return inserted

        created_alerts = await asyncio.to_thread(run)
        existing_count = len(alerts) - len(created_alerts)
        all_alerts = await list_alerts()
        return AlertSaveResult(created_count=len(created_alerts), existing_count=existing_count, all_alerts=all_alerts, created_alerts=created_alerts)

    async with _LOCK:
        existing_keys = {(a.item_id, a.matched_watchlist_id, a.reason) for a in _ALERTS}
        for alert in alerts:
            key = (alert.item_id, alert.matched_watchlist_id, alert.reason)
            if key in existing_keys:
                existing_count += 1
                continue
            _ALERTS.append(alert)
            created_alerts.append(alert)
            existing_keys.add(key)
        all_alerts = list(_ALERTS)
    return AlertSaveResult(created_count=len(created_alerts), existing_count=existing_count, all_alerts=all_alerts, created_alerts=created_alerts)


async def save_alerts(alerts: list[Alert]) -> list[Alert]:
    if not alerts:
        return []
    result = await save_alerts_with_counts(alerts)
    return result.all_alerts


async def update_alert(alert_id: str, *, status: str | None = None, notes: str | None = None, updated_at: str) -> Alert | None:
    updated: Alert | None = None
    async with _LOCK:
        for alert in _ALERTS:
            if alert.id == alert_id:
                if status is not None:
                    alert.status = status
                if notes is not None:
                    alert.notes = notes
                alert.updated_at = updated_at
                updated = alert
                break
    if database_enabled():
        def run() -> Alert | None:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE alerts SET status = COALESCE(%s, status), notes = COALESCE(%s, notes), updated_at = %s
                        WHERE id = %s
                        RETURNING id, item_id, title, risk_level, matched_watchlist_id, matched_watchlist_name, reason,
                                  recommended_action, status, created_at, updated_at, notes, org_id;
                        """,
                        (status, notes, updated_at, alert_id),
                    )
                    row = cur.fetchone()
                conn.commit()
                return _alert_from_row(row) if row else None
        updated = await asyncio.to_thread(run) or updated
    return updated


async def reset_memory_state() -> None:
    async with _LOCK:
        _ITEMS.clear()
        _WATCHLISTS.clear()
        _SOURCE_HEALTH.clear()
        _ALERTS.clear()
