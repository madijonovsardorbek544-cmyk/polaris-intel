from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .config import settings
from .models import Alert, AlertEvent, IntelligenceItem, ItemFeedback, OrgScoringProfile, PilotLead, PublicMetrics, SourceConfig, SourceHealth, Watchlist, WatchlistMatch

_ITEMS: list[IntelligenceItem] = []
_WATCHLISTS: list[Watchlist] = []
_SOURCE_HEALTH: dict[str, SourceHealth] = {}
_ALERTS: list[Alert] = []
_ALERT_EVENTS: list[AlertEvent] = []
_SOURCE_CONFIGS: list[SourceConfig] = []
_ORG_PROFILES: dict[str, OrgScoringProfile] = {}
_PILOT_LEADS: list[PilotLead] = []
_PUBLIC_METRICS = PublicMetrics()
_FEEDBACK: list[ItemFeedback] = []
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
                cur.execute("ALTER TABLE intel_items ADD COLUMN IF NOT EXISTS source_reliability TEXT NOT NULL DEFAULT 'Medium';")
                cur.execute("ALTER TABLE intel_items ADD COLUMN IF NOT EXISTS source_type TEXT NOT NULL DEFAULT 'custom';")
                cur.execute("ALTER TABLE intel_items ADD COLUMN IF NOT EXISTS evidence_links JSONB NOT NULL DEFAULT '[]'::jsonb;")
                cur.execute("ALTER TABLE intel_items ADD COLUMN IF NOT EXISTS evidence_summary TEXT NOT NULL DEFAULT '';")
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
                        owner TEXT,
                        due_at TEXT,
                        severity_override TEXT,
                        resolution_summary TEXT,
                        UNIQUE (item_id, matched_watchlist_id, reason)
                    );
                    """
                )
                cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS owner TEXT;")
                cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS due_at TEXT;")
                cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS severity_override TEXT;")
                cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolution_summary TEXT;")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS alert_events (
                        id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, event_type TEXT NOT NULL, message TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL
                    );
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS source_configs (
                        id TEXT PRIMARY KEY, url TEXT NOT NULL, label TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'custom', enabled BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL
                    );
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS org_scoring_profiles (
                        org_id TEXT PRIMARY KEY, high_priority_countries JSONB NOT NULL DEFAULT '[]'::jsonb, high_priority_sectors JSONB NOT NULL DEFAULT '[]'::jsonb, risk_boost_keywords JSONB NOT NULL DEFAULT '[]'::jsonb, risk_reduce_keywords JSONB NOT NULL DEFAULT '[]'::jsonb
                    );
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS pilot_leads (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        organization TEXT NOT NULL DEFAULT '',
                        role TEXT NOT NULL DEFAULT '',
                        email TEXT NOT NULL,
                        country TEXT NOT NULL DEFAULT '',
                        organization_type TEXT NOT NULL,
                        problem_description TEXT NOT NULL,
                        preferred_contact_method TEXT NOT NULL DEFAULT '',
                        created_at TIMESTAMPTZ NOT NULL,
                        status TEXT NOT NULL DEFAULT 'new'
                    );
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS public_metrics (
                        metric_key TEXT PRIMARY KEY,
                        metric_value INTEGER NOT NULL DEFAULT 0
                    );
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS item_feedback (
                        id TEXT PRIMARY KEY,
                        item_id TEXT NOT NULL,
                        relevance TEXT NOT NULL,
                        severity_feedback TEXT NOT NULL,
                        org_id TEXT NOT NULL,
                        comment TEXT NOT NULL DEFAULT '',
                        created_at TIMESTAMPTZ NOT NULL
                    );
                """)
            conn.commit()

    await asyncio.to_thread(run)


def _item_from_row(row: tuple[Any, ...]) -> IntelligenceItem:
    return IntelligenceItem(
        id=row[0], title=row[1], summary=row[2], category=row[3], risk_score=row[4], risk_level=row[5], confidence_score=row[6],
        source_url=row[7], source_domain=row[8], tags=_as_list(row[9]), entities=_as_dict(row[10]), affected_countries=_as_list(row[11]),
        affected_sectors=_as_list(row[12]), why_it_matters=row[13], recommended_action=row[14], created_at=_dt(row[15]) or "",
        ingested_at=_dt(row[16]) or "", risk_factors=_as_list(row[17]), confidence_factors=_as_list(row[18]), watchlist_matches=_matches_from_json(row[19]),
        source_reliability=row[20] if len(row) > 20 else "Medium", source_type=row[21] if len(row) > 21 else "custom",
        evidence_links=_as_list(row[22]) if len(row) > 22 else ([row[7]] if row[7] else []), evidence_summary=row[23] if len(row) > 23 else "",
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
                         ingested_at, risk_factors, confidence_factors, watchlist_matches, source_reliability, source_type, evidence_links, evidence_summary)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb,
                                %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s, %s::jsonb, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            title = EXCLUDED.title, summary = EXCLUDED.summary, category = EXCLUDED.category,
                            risk_score = EXCLUDED.risk_score, risk_level = EXCLUDED.risk_level,
                            confidence_score = EXCLUDED.confidence_score, source_url = EXCLUDED.source_url,
                            source_domain = EXCLUDED.source_domain, tags = EXCLUDED.tags, entities = EXCLUDED.entities,
                            affected_countries = EXCLUDED.affected_countries, affected_sectors = EXCLUDED.affected_sectors,
                            why_it_matters = EXCLUDED.why_it_matters, recommended_action = EXCLUDED.recommended_action,
                            ingested_at = EXCLUDED.ingested_at, risk_factors = EXCLUDED.risk_factors,
                            confidence_factors = EXCLUDED.confidence_factors, watchlist_matches = EXCLUDED.watchlist_matches,
                            source_reliability = EXCLUDED.source_reliability, source_type = EXCLUDED.source_type,
                            evidence_links = EXCLUDED.evidence_links, evidence_summary = EXCLUDED.evidence_summary;
                        """,
                        (item.id, item.title, item.summary, item.category, item.risk_score, item.risk_level, item.confidence_score,
                         item.source_url, item.source_domain, _json(item.tags), json.dumps(item.entities or {}), _json(item.affected_countries),
                         _json(item.affected_sectors), item.why_it_matters, item.recommended_action, item.created_at, item.ingested_at,
                         _json(item.risk_factors), _json(item.confidence_factors), _matches_to_json(item.watchlist_matches),
                         item.source_reliability, item.source_type, _json(item.evidence_links), item.evidence_summary),
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
                               created_at, ingested_at, risk_factors, confidence_factors, watchlist_matches,
                               source_reliability, source_type, evidence_links, evidence_summary
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
    configs = await list_source_configs()
    config_urls = [source.url for source in configs]
    for feed_url in (config_urls or settings.feeds):
        by_url.setdefault(feed_url, _normalize_source_health(SourceHealth(source_url=feed_url)))
    return list(by_url.values())


def _alert_from_row(row: tuple[Any, ...]) -> Alert:
    return Alert(id=row[0], item_id=row[1], title=row[2], risk_level=row[3], matched_watchlist_id=row[4], matched_watchlist_name=row[5], reason=row[6], recommended_action=row[7], status=row[8], created_at=_dt(row[9]) or "", updated_at=_dt(row[10]) or "", notes=row[11], org_id=row[12] or "demo", owner=(row[13] if len(row) > 13 else None), due_at=(row[14] if len(row) > 14 else None), severity_override=(row[15] if len(row) > 15 else None), resolution_summary=(row[16] if len(row) > 16 else None))


async def list_alerts() -> list[Alert]:
    if database_enabled():
        def run() -> list[Alert]:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, item_id, title, risk_level, matched_watchlist_id, matched_watchlist_name, reason, recommended_action, status, created_at, updated_at, notes, org_id, owner, due_at, severity_override, resolution_summary FROM alerts ORDER BY created_at DESC;")
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
                                reason, recommended_action, status, created_at, updated_at, notes, org_id, owner, due_at, severity_override, resolution_summary)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (item_id, matched_watchlist_id, reason) DO NOTHING
                            RETURNING id, item_id, title, risk_level, matched_watchlist_id, matched_watchlist_name, reason,
                                      recommended_action, status, created_at, updated_at, notes, org_id, owner, due_at, severity_override, resolution_summary;
                            """,
                            (alert.id, alert.item_id, alert.title, alert.risk_level, alert.matched_watchlist_id, alert.matched_watchlist_name, alert.reason, alert.recommended_action, alert.status, alert.created_at, alert.updated_at, alert.notes, alert.org_id, alert.owner, alert.due_at, alert.severity_override, alert.resolution_summary),
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


async def update_alert(
    alert_id: str,
    *,
    status: str | None = None,
    notes: str | None = None,
    owner: str | None = None,
    due_at: str | None = None,
    severity_override: str | None = None,
    resolution_summary: str | None = None,
    updated_at: str,
) -> Alert | None:
    updated: Alert | None = None
    async with _LOCK:
        for alert in _ALERTS:
            if alert.id == alert_id:
                if status is not None:
                    alert.status = status
                if notes is not None:
                    alert.notes = notes
                if owner is not None:
                    alert.owner = owner
                if due_at is not None:
                    alert.due_at = due_at
                if severity_override is not None:
                    alert.severity_override = severity_override
                if resolution_summary is not None:
                    alert.resolution_summary = resolution_summary
                alert.updated_at = updated_at
                updated = alert
                break
    if database_enabled():
        def run() -> Alert | None:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE alerts SET status = COALESCE(%s, status), notes = COALESCE(%s, notes), owner = COALESCE(%s, owner),
                            due_at = COALESCE(%s, due_at), severity_override = COALESCE(%s, severity_override),
                            resolution_summary = COALESCE(%s, resolution_summary), updated_at = %s
                        WHERE id = %s
                        RETURNING id, item_id, title, risk_level, matched_watchlist_id, matched_watchlist_name, reason,
                                  recommended_action, status, created_at, updated_at, notes, org_id, owner, due_at, severity_override, resolution_summary;
                        """,
                        (status, notes, owner, due_at, severity_override, resolution_summary, updated_at, alert_id),
                    )
                    row = cur.fetchone()
                conn.commit()
                return _alert_from_row(row) if row else None
        updated = await asyncio.to_thread(run) or updated
    return updated


async def add_alert_event(event: AlertEvent) -> AlertEvent:
    async with _LOCK:
        _ALERT_EVENTS.append(event)
    if database_enabled():
        def run() -> None:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute("INSERT INTO alert_events (id, alert_id, event_type, message, created_at) VALUES (%s, %s, %s, %s, %s);", (event.id, event.alert_id, event.event_type, event.message, event.created_at))
                conn.commit()
        await asyncio.to_thread(run)
    return event


async def list_alert_events(alert_id: str) -> list[AlertEvent]:
    if database_enabled():
        def run() -> list[AlertEvent]:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, alert_id, event_type, message, created_at FROM alert_events WHERE alert_id = %s ORDER BY created_at DESC;", (alert_id,))
                    return [AlertEvent(id=row[0], alert_id=row[1], event_type=row[2], message=row[3], created_at=_dt(row[4]) or "") for row in cur.fetchall()]
        return await asyncio.to_thread(run)
    async with _LOCK:
        return [event for event in _ALERT_EVENTS if event.alert_id == alert_id]


async def add_source_config(source: SourceConfig) -> SourceConfig:
    async with _LOCK:
        _SOURCE_CONFIGS.append(source)
    if database_enabled():
        def run() -> None:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute("INSERT INTO source_configs (id, url, label, category, enabled, created_at) VALUES (%s, %s, %s, %s, %s, %s);", (source.id, source.url, source.label, source.category, source.enabled, source.created_at))
                conn.commit()
        await asyncio.to_thread(run)
    return source


async def list_source_configs() -> list[SourceConfig]:
    if database_enabled():
        def run() -> list[SourceConfig]:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, url, label, category, enabled, created_at FROM source_configs ORDER BY created_at DESC;")
                    return [SourceConfig(id=row[0], url=row[1], label=row[2], category=row[3], enabled=bool(row[4]), created_at=_dt(row[5]) or "") for row in cur.fetchall()]
        rows = await asyncio.to_thread(run)
        async with _LOCK:
            _SOURCE_CONFIGS[:] = rows
        return rows
    async with _LOCK:
        return list(_SOURCE_CONFIGS)


async def update_source_config(source_id: str, **updates: object) -> SourceConfig | None:
    updated = None
    async with _LOCK:
        for source in _SOURCE_CONFIGS:
            if source.id == source_id:
                for key, value in updates.items():
                    if value is not None:
                        setattr(source, key, value)
                updated = source
                break
    if database_enabled():
        def run() -> SourceConfig | None:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute("""UPDATE source_configs SET url = COALESCE(%s, url), label = COALESCE(%s, label), category = COALESCE(%s, category), enabled = COALESCE(%s, enabled) WHERE id = %s RETURNING id, url, label, category, enabled, created_at;""", (updates.get('url'), updates.get('label'), updates.get('category'), updates.get('enabled'), source_id))
                    row = cur.fetchone()
                conn.commit()
                return SourceConfig(id=row[0], url=row[1], label=row[2], category=row[3], enabled=bool(row[4]), created_at=_dt(row[5]) or "") if row else None
        updated = await asyncio.to_thread(run) or updated
    return updated


async def delete_source_config(source_id: str) -> bool:
    deleted = False
    async with _LOCK:
        before = len(_SOURCE_CONFIGS)
        _SOURCE_CONFIGS[:] = [source for source in _SOURCE_CONFIGS if source.id != source_id]
        deleted = len(_SOURCE_CONFIGS) != before
    if database_enabled():
        def run() -> bool:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM source_configs WHERE id = %s;", (source_id,))
                    ok = cur.rowcount > 0
                conn.commit()
                return ok
        deleted = await asyncio.to_thread(run) or deleted
    return deleted


async def get_org_profile(org_id: str) -> OrgScoringProfile:
    if database_enabled():
        def run() -> OrgScoringProfile | None:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT org_id, high_priority_countries, high_priority_sectors, risk_boost_keywords, risk_reduce_keywords FROM org_scoring_profiles WHERE org_id = %s;", (org_id,))
                    row = cur.fetchone()
                    return OrgScoringProfile(row[0], _as_list(row[1]), _as_list(row[2]), _as_list(row[3]), _as_list(row[4])) if row else None
        profile = await asyncio.to_thread(run)
        if profile:
            return profile
    async with _LOCK:
        return _ORG_PROFILES.get(org_id, OrgScoringProfile(org_id=org_id))


async def put_org_profile(profile: OrgScoringProfile) -> OrgScoringProfile:
    async with _LOCK:
        _ORG_PROFILES[profile.org_id] = profile
    if database_enabled():
        def run() -> None:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute("""INSERT INTO org_scoring_profiles (org_id, high_priority_countries, high_priority_sectors, risk_boost_keywords, risk_reduce_keywords) VALUES (%s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb) ON CONFLICT (org_id) DO UPDATE SET high_priority_countries = EXCLUDED.high_priority_countries, high_priority_sectors = EXCLUDED.high_priority_sectors, risk_boost_keywords = EXCLUDED.risk_boost_keywords, risk_reduce_keywords = EXCLUDED.risk_reduce_keywords;""", (profile.org_id, _json(profile.high_priority_countries), _json(profile.high_priority_sectors), _json(profile.risk_boost_keywords), _json(profile.risk_reduce_keywords)))
                conn.commit()
        await asyncio.to_thread(run)
    return profile


async def reset_memory_state() -> None:
    async with _LOCK:
        _ITEMS.clear()
        _WATCHLISTS.clear()
        _SOURCE_HEALTH.clear()
        _ALERTS.clear()
        _ALERT_EVENTS.clear()
        _SOURCE_CONFIGS.clear()
        _ORG_PROFILES.clear()
        _PILOT_LEADS.clear()
        _FEEDBACK.clear()
        _PUBLIC_METRICS.landing_page_views = 0
        _PUBLIC_METRICS.demo_page_views = 0
        _PUBLIC_METRICS.pilot_form_submissions = 0



def _lead_from_row(row: tuple[Any, ...]) -> PilotLead:
    return PilotLead(
        id=row[0],
        name=row[1],
        organization=row[2] or "",
        role=row[3] or "",
        email=row[4],
        country=row[5] or "",
        organization_type=row[6],
        problem_description=row[7],
        preferred_contact_method=row[8] or "",
        created_at=_dt(row[9]) or "",
        status=row[10] or "new",
    )


async def add_pilot_lead(lead: PilotLead) -> PilotLead:
    async with _LOCK:
        _PILOT_LEADS.insert(0, lead)
    if database_enabled():
        def run() -> None:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO pilot_leads (id, name, organization, role, email, country, organization_type,
                            problem_description, preferred_contact_method, created_at, status)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                        """,
                        (lead.id, lead.name, lead.organization, lead.role, lead.email, lead.country, lead.organization_type,
                         lead.problem_description, lead.preferred_contact_method, lead.created_at, lead.status),
                    )
                conn.commit()
        await asyncio.to_thread(run)
    return lead


async def list_pilot_leads(limit: int = 50, status: str | None = None) -> list[PilotLead]:
    if database_enabled():
        def run() -> list[PilotLead]:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, name, organization, role, email, country, organization_type, problem_description,
                               preferred_contact_method, created_at, status
                        FROM pilot_leads
                        WHERE (%s IS NULL OR status = %s)
                        ORDER BY created_at DESC
                        LIMIT %s;
                        """,
                        (status, status, limit),
                    )
                    return [_lead_from_row(row) for row in cur.fetchall()]
        return await asyncio.to_thread(run)
    async with _LOCK:
        leads = [lead for lead in _PILOT_LEADS if status is None or lead.status == status]
        return list(leads[:limit])


async def update_pilot_lead_status(lead_id: str, status: str) -> PilotLead | None:
    updated: PilotLead | None = None
    async with _LOCK:
        for lead in _PILOT_LEADS:
            if lead.id == lead_id:
                lead.status = status
                updated = lead
                break
    if database_enabled():
        def run() -> PilotLead | None:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE pilot_leads SET status = %s WHERE id = %s
                        RETURNING id, name, organization, role, email, country, organization_type, problem_description,
                                  preferred_contact_method, created_at, status;
                        """,
                        (status, lead_id),
                    )
                    row = cur.fetchone()
                conn.commit()
                return _lead_from_row(row) if row else None
        updated = await asyncio.to_thread(run) or updated
    return updated


async def increment_public_metric(metric_key: str) -> PublicMetrics:
    allowed = {"landing_page_views", "demo_page_views", "pilot_form_submissions"}
    if metric_key not in allowed:
        raise ValueError("Unknown public metric")
    async with _LOCK:
        setattr(_PUBLIC_METRICS, metric_key, getattr(_PUBLIC_METRICS, metric_key) + 1)
    if database_enabled():
        def run() -> None:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO public_metrics (metric_key, metric_value) VALUES (%s, 1)
                        ON CONFLICT (metric_key) DO UPDATE SET metric_value = public_metrics.metric_value + 1;
                        """,
                        (metric_key,),
                    )
                conn.commit()
        await asyncio.to_thread(run)
    return await get_public_metrics()


async def get_public_metrics() -> PublicMetrics:
    if database_enabled():
        def run() -> dict[str, int]:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT metric_key, metric_value FROM public_metrics;")
                    return {row[0]: int(row[1]) for row in cur.fetchall()}
        rows = await asyncio.to_thread(run)
        return PublicMetrics(
            landing_page_views=rows.get("landing_page_views", 0),
            demo_page_views=rows.get("demo_page_views", 0),
            pilot_form_submissions=rows.get("pilot_form_submissions", 0),
        )
    async with _LOCK:
        return PublicMetrics(
            landing_page_views=_PUBLIC_METRICS.landing_page_views,
            demo_page_views=_PUBLIC_METRICS.demo_page_views,
            pilot_form_submissions=_PUBLIC_METRICS.pilot_form_submissions,
        )


def _feedback_from_row(row: tuple[Any, ...]) -> ItemFeedback:
    return ItemFeedback(
        id=row[0],
        item_id=row[1],
        relevance=row[2],
        severity_feedback=row[3],
        org_id=row[4],
        comment=row[5] or "",
        created_at=_dt(row[6]) or "",
    )


async def add_item_feedback(feedback: ItemFeedback) -> ItemFeedback:
    async with _LOCK:
        _FEEDBACK.insert(0, feedback)
    if database_enabled():
        def run() -> None:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO item_feedback (id, item_id, relevance, severity_feedback, org_id, comment, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s);
                        """,
                        (feedback.id, feedback.item_id, feedback.relevance, feedback.severity_feedback, feedback.org_id, feedback.comment, feedback.created_at),
                    )
                conn.commit()
        await asyncio.to_thread(run)
    return feedback


async def list_item_feedback(limit: int = 200) -> list[ItemFeedback]:
    if database_enabled():
        def run() -> list[ItemFeedback]:
            with _psycopg().connect(settings.database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, item_id, relevance, severity_feedback, org_id, comment, created_at
                        FROM item_feedback ORDER BY created_at DESC LIMIT %s;
                        """,
                        (limit,),
                    )
                    return [_feedback_from_row(row) for row in cur.fetchall()]
        return await asyncio.to_thread(run)
    async with _LOCK:
        return list(_FEEDBACK[:limit])
