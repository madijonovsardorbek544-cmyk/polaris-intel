from __future__ import annotations

from collections import Counter
from dataclasses import asdict

from fastapi import APIRouter, HTTPException, Query

from ..config import settings
from ..database import get_item, list_items, list_source_health
from ..services.briefing import daily_brief, list_alerts
from ..services.ingestion import item_to_dict, refresh_store, seed_demo_items

router = APIRouter(prefix="/api")


@router.get("/latest")
async def latest() -> list[dict[str, object]]:
    return [item_to_dict(item) for item in await list_items(settings.max_items)]


@router.get("/items")
async def items(
    q: str | None = None,
    category: str | None = None,
    risk_level: str | None = None,
    country: str | None = None,
    sector: str | None = None,
    limit: int = Query(default=60, ge=1, le=200),
) -> list[dict[str, object]]:
    results = await list_items(limit)
    if q:
        needle = q.lower()
        results = [item for item in results if needle in f"{item.title} {item.summary} {' '.join(item.tags)}".lower()]
    if category:
        results = [item for item in results if item.category.lower() == category.lower()]
    if risk_level:
        results = [item for item in results if item.risk_level.lower() == risk_level.lower()]
    if country:
        results = [item for item in results if country.lower() in {c.lower() for c in item.affected_countries}]
    if sector:
        results = [item for item in results if sector.lower() in {s.lower() for s in item.affected_sectors}]
    return [item_to_dict(item) for item in results]


@router.get("/items/{item_id}")
async def item_detail(item_id: str) -> dict[str, object]:
    item = await get_item(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Intelligence item not found")
    return item_to_dict(item)


@router.post("/refresh")
async def refresh() -> dict[str, object]:
    return await refresh_store(force=True)


@router.post("/seed")
async def seed() -> dict[str, object]:
    seeded = await seed_demo_items()
    return {"ok": True, "seeded": len(seeded)}


@router.get("/stats")
async def stats() -> dict[str, object]:
    all_items = await list_items(settings.max_items)
    categories = Counter(item.category for item in all_items)
    risks = Counter(item.risk_level for item in all_items)
    countries = Counter(country for item in all_items for country in item.affected_countries)
    sectors = Counter(sector for item in all_items for sector in item.affected_sectors)
    average_risk = round(sum(item.risk_score for item in all_items) / len(all_items), 1) if all_items else 0
    return {
        "total_items": len(all_items),
        "average_risk_score": average_risk,
        "by_category": dict(categories),
        "by_risk_level": dict(risks),
        "top_countries": countries.most_common(8),
        "top_sectors": sectors.most_common(8),
    }


@router.get("/summary")
async def summary() -> dict[str, object]:
    all_items = await list_items(settings.max_items)
    high_priority = [item for item in all_items if item.risk_level in {"Critical", "High"}]
    return {
        "headline": f"{len(high_priority)} high-priority items across {len(all_items)} total intelligence items.",
        "critical_or_high": len(high_priority),
        "top_items": [item_to_dict(item) for item in high_priority[:5]],
        "recommended_focus": [item.recommended_action for item in high_priority[:3]],
    }


@router.get("/sources")
async def sources() -> list[dict[str, object]]:
    return [asdict(source) for source in await list_source_health()]


@router.get("/alerts")
async def alerts() -> list[dict[str, object]]:
    return await list_alerts()


@router.get("/brief/daily")
async def brief_daily() -> dict[str, object]:
    return await daily_brief()
