from __future__ import annotations

from dataclasses import asdict
from typing import Any

from ..config import settings
from ..database import list_items, list_source_health
from ..models import Alert, IntelligenceItem


def generate_alerts_from_items(items: list[IntelligenceItem]) -> list[Alert]:
    alerts: list[Alert] = []
    for item in items:
        if item.risk_level not in {"Critical", "High"} or not item.watchlist_matches:
            continue
        for match in item.watchlist_matches:
            alerts.append(
                Alert(
                    item_id=item.id,
                    title=item.title,
                    risk_level=item.risk_level,
                    matched_watchlist=match.get("watchlist_name", "Unknown watchlist"),
                    reason=match.get("reason", "Watchlist match"),
                    recommended_action=item.recommended_action,
                    created_at=item.ingested_at,
                )
            )
    return alerts


async def list_alerts() -> list[dict[str, Any]]:
    items = await list_items(settings.max_items)
    return [asdict(alert) for alert in generate_alerts_from_items(items)]


async def daily_brief() -> dict[str, Any]:
    items = await list_items(settings.max_items)
    high_priority = [item for item in items if item.risk_level in {"Critical", "High"}]
    top_risks = sorted(high_priority or items, key=lambda item: (item.risk_score, item.ingested_at), reverse=True)[:5]
    countries = sorted({country for item in items for country in item.affected_countries})
    sectors = sorted({sector for item in items for sector in item.affected_sectors})
    actions = list(dict.fromkeys(item.recommended_action for item in top_risks if item.recommended_action))
    source_failures = [asdict(source) for source in await list_source_health() if source.failure_count > 0]

    return {
        "headline_summary": f"{len(high_priority)} Critical/High risks across {len(items)} total intelligence items.",
        "top_5_risks": [asdict(item) for item in top_risks],
        "countries_affected": countries,
        "sectors_affected": sectors,
        "recommended_actions": actions[:5],
        "source_failures": source_failures,
    }
