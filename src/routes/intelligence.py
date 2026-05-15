from __future__ import annotations

from collections import Counter
from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Query

from ..auth import require_api_key
from ..config import settings
from ..database import get_alert, get_item, list_alerts, list_items, list_source_health, save_alerts, update_alert
from ..models import Alert, IntelligenceItem
from ..schemas import AlertUpdate
from ..services.analysis import now_iso
from ..services.briefing import alert_to_dict, alerts_from_items, format_alert_for_telegram, generate_alerts, generate_daily_brief
from ..services.ingestion import item_to_dict, refresh_store, seed_demo_items

router = APIRouter(prefix="/api")


def _item_matches_org(item: IntelligenceItem, org_id: str | None) -> bool:
    if not org_id:
        return True
    return any(match.org_id == org_id for match in item.watchlist_matches)


def _alert_matches_org(alert: Alert | dict[str, object], org_id: str | None) -> bool:
    if not org_id:
        return True
    if isinstance(alert, Alert):
        return alert.org_id == org_id
    return alert.get("org_id") == org_id


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
    org_id: str | None = None,
    limit: int = Query(default=60, ge=1, le=200),
) -> list[dict[str, object]]:
    results = await list_items(limit)
    if org_id:
        results = [item for item in results if _item_matches_org(item, org_id)]
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


@router.post("/refresh", dependencies=[Depends(require_api_key)])
async def refresh() -> dict[str, object]:
    return await refresh_store(force=True)


@router.post("/seed", dependencies=[Depends(require_api_key)])
async def seed() -> dict[str, object]:
    seeded = await seed_demo_items()
    return {"ok": True, "seeded": len(seeded)}


@router.get("/sources")
async def sources() -> list[dict[str, object]]:
    return [asdict(source) for source in await list_source_health()]


@router.get("/alerts")
async def alerts(org_id: str | None = None) -> dict[str, object]:
    persisted = [alert for alert in await list_alerts() if _alert_matches_org(alert, org_id)]
    generated_preview = [alert for alert in generate_alerts(await list_items(settings.max_items)) if _alert_matches_org(alert, org_id)]
    return {
        "persisted": [alert_to_dict(alert) for alert in persisted],
        "generated_preview": generated_preview,
        "total_persisted": len(persisted),
        "total_generated_preview": len(generated_preview),
    }


@router.get("/alerts/flat")
async def alerts_flat(org_id: str | None = None) -> list[dict[str, object]]:
    persisted = [alert for alert in await list_alerts() if _alert_matches_org(alert, org_id)]
    if persisted:
        return [alert_to_dict(alert) for alert in persisted]
    return [alert for alert in generate_alerts(await list_items(settings.max_items)) if _alert_matches_org(alert, org_id)]


@router.get("/alerts/{alert_id}")
async def alert_detail(alert_id: str) -> dict[str, object]:
    alert = await get_alert(alert_id)
    if not alert:
        generated = generate_alerts(await list_items(settings.max_items))
        for candidate in generated:
            if candidate["id"] == alert_id:
                return candidate
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert_to_dict(alert)


@router.post("/alerts/generate", dependencies=[Depends(require_api_key)])
async def generate_persistent_alerts() -> dict[str, object]:
    before = await list_alerts()
    before_keys = {(alert.item_id, alert.matched_watchlist_id, alert.reason) for alert in before}
    candidates = alerts_from_items(await list_items(settings.max_items))
    created = sum(1 for alert in candidates if (alert.item_id, alert.matched_watchlist_id, alert.reason) not in before_keys)
    existing = len(candidates) - created
    saved = await save_alerts(candidates) if candidates else await list_alerts()
    return {"ok": True, "created": created, "existing": existing, "alerts": [alert_to_dict(alert) for alert in saved]}


@router.patch("/alerts/{alert_id}", dependencies=[Depends(require_api_key)])
async def patch_alert(alert_id: str, payload: AlertUpdate) -> dict[str, object]:
    alert = await update_alert(alert_id, status=payload.status, notes=payload.notes, updated_at=now_iso())
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert_to_dict(alert)


@router.post("/alerts/{alert_id}/telegram-preview", dependencies=[Depends(require_api_key)])
async def telegram_preview(alert_id: str) -> dict[str, object]:
    alert = await get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"message": format_alert_for_telegram(alert)}


@router.get("/brief/daily")
async def daily_brief(org_id: str | None = None) -> dict[str, object]:
    all_items = await list_items(settings.max_items)
    if org_id:
        all_items = [item for item in all_items if _item_matches_org(item, org_id)]
    return generate_daily_brief(all_items, await list_source_health())


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
