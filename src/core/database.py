from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence

import psycopg

from src.core.config import settings
from src.models.intel import IntelItem

CREATE_INTEL_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS intel_items (
    id BIGSERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    category TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    source TEXT NOT NULL,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (title, source)
);
"""

UPSERT_INTEL_ITEM_SQL = """
INSERT INTO intel_items
(title, summary, category, risk_score, risk_level, source, tags, created_at)
VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
ON CONFLICT (title, source) DO UPDATE SET
    summary = EXCLUDED.summary,
    category = EXCLUDED.category,
    risk_score = EXCLUDED.risk_score,
    risk_level = EXCLUDED.risk_level,
    tags = EXCLUDED.tags,
    created_at = EXCLUDED.created_at;
"""

SELECT_INTEL_ITEMS_SQL = """
SELECT title, summary, category, risk_score, risk_level, source, tags, created_at
FROM intel_items
ORDER BY risk_score DESC, created_at DESC
LIMIT %s;
"""


async def init_db() -> None:
    if not settings.database_url:
        return

    def run() -> None:
        with psycopg.connect(settings.database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(CREATE_INTEL_TABLE_SQL)
            conn.commit()

    await asyncio.to_thread(run)


async def save_items(items: Sequence[IntelItem]) -> None:
    if not settings.database_url or not items:
        return

    def run() -> None:
        with psycopg.connect(settings.database_url) as conn:
            with conn.cursor() as cur:
                for item in items:
                    cur.execute(
                        UPSERT_INTEL_ITEM_SQL,
                        (
                            item.title,
                            item.summary,
                            item.category,
                            item.risk_score,
                            item.risk_level,
                            item.source,
                            json.dumps(item.tags),
                            item.created_at,
                        ),
                    )
            conn.commit()

    await asyncio.to_thread(run)


def _normalize_tags(raw_tags: object) -> list[str]:
    if isinstance(raw_tags, list):
        return [str(tag) for tag in raw_tags if tag]
    return []


async def load_items(limit: int) -> list[IntelItem]:
    if not settings.database_url:
        return []

    def run() -> list[IntelItem]:
        rows: list[IntelItem] = []
        with psycopg.connect(settings.database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(SELECT_INTEL_ITEMS_SQL, (limit,))
                for row in cur.fetchall():
                    created_at = row[7].isoformat() if hasattr(row[7], "isoformat") else str(row[7])
                    rows.append(
                        IntelItem(
                            title=row[0],
                            summary=row[1],
                            category=row[2],
                            risk_score=row[3],
                            risk_level=row[4],
                            source=row[5],
                            tags=_normalize_tags(row[6]),
                            created_at=created_at,
                        )
                    )
        return rows

    return await asyncio.to_thread(run)
