from __future__ import annotations

from collections import Counter
from dataclasses import asdict

from ..models import IntelligenceItem, SourceHealth
from .analysis import now_iso
from .ingestion import item_to_dict


def generate_alerts(items: list[IntelligenceItem]) -> list[dict[str, object]]:
    alerts: list[dict[str, object]] = []
    for item in items:
        if item.risk_level not in {"Critical", "High"} or not item.watchlist_matches:
            continue
        for match in item.watchlist_matches:
            alerts.append(
                {
                    "item_id": item.id,
                    "title": item.title,
                    "risk_level": item.risk_level,
                    "matched_watchlist": match.watchlist_name,
                    "reason": match.reason,
                    "recommended_action": item.recommended_action,
                    "created_at": item.ingested_at or now_iso(),
                }
            )
    return alerts


def generate_daily_brief(items: list[IntelligenceItem], sources: list[SourceHealth]) -> dict[str, object]:
    top_risks = sorted(items, key=lambda item: (item.risk_score, item.ingested_at), reverse=True)[:5]
    countries = Counter(country for item in items for country in item.affected_countries)
    sectors = Counter(sector for item in items for sector in item.affected_sectors)
    failures = [asdict(source) for source in sources if source.last_error]
    critical_or_high = [item for item in items if item.risk_level in {"Critical", "High"}]
    actions = list(dict.fromkeys(item.recommended_action for item in critical_or_high[:5]))
    headline = (
        f"{len(critical_or_high)} Critical/High risks across {len(items)} tracked items; "
        f"top exposure: {countries.most_common(1)[0][0] if countries else 'no country concentration'} / "
        f"{sectors.most_common(1)[0][0] if sectors else 'no sector concentration'}."
    )
    return {
        "headline_summary": headline,
        "top_5_risks": [item_to_dict(item) for item in top_risks],
        "countries_affected": countries.most_common(10),
        "sectors_affected": sectors.most_common(10),
        "recommended_actions": actions or ["Seed or ingest intelligence, then review items matching your watchlists."],
        "source_failures": failures,
    }
